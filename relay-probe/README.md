# 中转站渠道质量探针 V2.1.1 · Python 网页版

本地或单端口部署的 AI API 渠道测评工作台。浏览器向同源 FastAPI 提交任务，后端使用独立 HTTP 连接池执行 7 组 40 项探针。每份报告可从结论跳到请求编号，展开原始问答、脱敏头、原始 `usage` 和流式时间序列。前端使用原生 ES Modules，无构建步骤。

## Windows 本机启动

在本目录建立虚拟环境并启动。

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
$env:HOST = '127.0.0.1'
.\.venv\Scripts\python -m app.main
```

打开 `http://127.0.0.1:8787`。填写 Base URL、Key 和模型即可开始，也可先拉取模型。控制台首次打开时价格表为空。实扣对账需要先在「价格与规则」保存对应模型的三项价格。

### 本机代理与 Fake-IP

使用 Clash / Mihomo 时，系统 DNS 可能把 HTTPS 渠道域名解析到 `198.18.0.0/15`。出现 Fake-IP 提示时，点击「启用本机网络兼容」后重试。也可在「代理、客户端与对账信息」里预先勾选。TUN 模式下可留空出站代理 URL。使用显式本机代理时填写实际回环地址和端口。

本机兼容要求以回环地址启动服务，并从本机控制台发起请求。连接使用当次校验的地址，TLS 按原域名验证。目标解析到 RFC 1918、回环或链路本地地址时继续拦截。生产部署使用公网目标和适用的解析配置。

## Linux 独立端口

使用 Python 3.11 或更新版本。在项目目录执行以下命令。`start.sh` 会优先使用项目内的虚拟环境。

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
HOST=127.0.0.1 PORT=8787 sh start.sh
```

| 环境变量 | 默认值 | 作用 |
| --- | --- | --- |
| `HOST` | `0.0.0.0` | 监听地址。可设为 `127.0.0.1` 供本地浏览器或反代访问 |
| `PORT` | `8787` | 独立 HTTP 端口 |
| `ACCESS_PASSWORD` | 空 | 非空时保护全部 `/api/*`，浏览器通过内存 Bearer 口令访问 |
| `ALLOW_PRIVATE_TARGETS` | `false` | 设为 `true` 才允许内网目标和内网代理。用于连接本地模拟站 |
| `PROBE_DATA_DIR` | `.runtime/` | 仅保存脱敏的自定义 Profile。运行与报告保存在内存 |

服务使用单进程，SSE、任务取消和抓包窗口共享同一进程内存。运行完成后，后端保留脱敏报告约 30 分钟供断线重连。浏览器本地历史可自行删除或清空。长请求在历史中压缩为摘要，完整原始证据可从当轮报告导出为 JSON。关页会断开事件监听，手动中止按钮会取消任务和在途请求。

### Nginx 反向代理

在已配置 HTTPS 的站点内使用下列 `location`。后端监听回环端口，线上服务通过进程环境注入 `ACCESS_PASSWORD`。SSE 路由保留 `Last-Event-ID` 续读能力。下例在反代入口关闭仅供本机使用的捕获端点，本机 CLI 连接后端回环端口。

```nginx
location ^~ /api/capture/ {
    return 403;
}

location / {
    proxy_pass http://127.0.0.1:8787;
    proxy_http_version 1.1;
    proxy_set_header Host $http_host;
    proxy_set_header Connection "";
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_cache off;
    proxy_read_timeout 3600s;
    gzip off;
}
```

自定义日志格式应省略请求头、请求体和查询参数。应用启动器关闭访问日志。API 密钥只随请求体抵达后端，鉴权头与回显中的同一值在报告生成前脱敏。密钥及连接池引用在结束、异常和中止路径释放。Python 和浏览器使用运行时管理的字符串，物理内存清零不可验证。

## 模拟站与自动验收

以下命令从项目根目录运行。主要验收会自动在两个随机回环端口启动模拟站与控制台，通过真实 HTTP 与 SSE 执行测试。`#19` 实际等待 15 秒和 60 秒，`#40` 实际运行 60 秒。

```sh
python -m pytest -q tests/test_acceptance.py
python -m pytest -q tests/test_transport.py
```

传输专项在本机生成临时 TLS 证书，并实际握手验证 HTTPS 直连、HTTP CONNECT、HTTPS 代理和 SOCKS5。该专项需要 OpenSSL。可另装浏览器验收依赖，在项目虚拟环境中执行以下命令。

```sh
python -m pip install playwright
python -m playwright install chromium
python -m pytest -q tests/test_browser.py
```

手工查看模拟站时，在一个终端运行 `python -m uvicorn tests.mock_relay:app --host 127.0.0.1 --port 8788 --no-access-log`，在另一个终端将 `ALLOW_PRIVATE_TARGETS=true`、`HOST=127.0.0.1` 注入控制台启动进程。Base URL 可填 `http://127.0.0.1:8788/normal_responses/v1`，使用任意临时测试串并选择 `mock-model`。模拟账本使用专门的测试系数，在验收文件中定义。

| 场景路径 | 可观察结果 |
| --- | --- |
| `normal_responses` | 原生 SSE、推理档位差异、合法缓存粒度、加密推理回传 |
| `responses_404_chat_ok` | 响应路径 404，Auto 切换 Chat |
| `responses_401`、`responses_429` | 保留首次失败与片段，停止预检 |
| `fake_cache_non128`、`fake_cache_sticky` | 非 128 粒度、低于 1024、冷命中、受控内容失效异常 |
| `fake_reasoning_zero`、`encrypted_strip` | high 推理计数为零、二轮加密项回传 400 |
| `fake_input_billing`、`model_swap` | 阶梯输入不变、响应自报异构模型名 |
| `stress_429_at_10` | 连接并发达到 10 后返回 429，保留临界档的部分样本 |
| `no_balance`、`no_usage`、`paper_cache` | 余额端点不可用、用量未返回、高缓存与 TTFT 背离 |

场景也可通过 `X-Mock-Scenario` 请求头选择。带固定答案的模拟站只用于验证采集和裁决逻辑。用户界面和正常后端运行路径都使用实际请求。

## 客户端 Profile 与真实 CLI 抓包

内置 Profile 的说明词与三项工具由本项目自建。基准使用随项目提供的官方 `o200k_base` 词表在本地实算。词表 SHA-256 为 `446a9538cb6c348e3516120d7c08b09f57c36495e2acfffe59a5bf8b0cfb1a2d`。控制台展示模板的实际基准 token 数，外部工具的 9845 口径独立。

1. 在控制台打开「客户端 Profile → 开启一次抓包」，取得五分钟有效的一次性抓包口令。在本机空目录发起一次无需工具的测试任务。
2. 将下面示例中的 `base_url` 端口替换为控制台端口。把页面给出的一次性口令读入当前终端环境变量 `RELAY_CAPTURE_TOKEN`。无需向 CLI 提供中转站 Key。
3. 输入下列一次性 CLI 配置。示例使用 POSIX shell 换行。Windows PowerShell 可将命令合并为一行。CLI 收到来自本地端点的确认消息后，控制台模板库会自动显示新 Profile。

```sh
read -rs -p "Capture token: " RELAY_CAPTURE_TOKEN
echo
export RELAY_CAPTURE_TOKEN
codex exec --ephemeral --skip-git-repo-check -s read-only \
  -c 'model_provider="probe_capture"' \
  -c 'model_providers.probe_capture.name="Local Capture"' \
  -c 'model_providers.probe_capture.base_url="http://127.0.0.1:8787/api/capture/v1"' \
  -c 'model_providers.probe_capture.wire_api="responses"' \
  -c 'model_providers.probe_capture.env_key="RELAY_CAPTURE_TOKEN"' \
  -m fixture-model 'Reply OK.'
unset RELAY_CAPTURE_TOKEN
```

导入保存客户端头、system/developer 上下文、工具声明和请求骨架。鉴权头剥离，会话标识按本轮重新生成，用户输入由探针题面替换。`Authorization`、`api-key`、Cookie、代理鉴权以及浏览器专用头从复刻头集合剔除。模板编辑器提供 JSON 导入导出，也接受含内联 JSON 的 POSIX cURL。捕获端点仅在一次性窗口内接受回环请求，同时兼容 Responses 与 Chat 路径。

## 检测范围与操作

| 探针 | 样本与输出 |
| --- | --- |
| #1–5 能力 | 12 段分词增量、四道动态推理题、严格 JSON Schema、强制/并行工具及闭环、冲突指令、约 100K token 头中尾检索 |
| #6–10 请求质量 | Profile 与裸请求输入差分、冷启动和全轮缓存合规、不可见字符位置、流式速度与中断、Responses 事件和前序 ID 续接 |
| #11–15 验账 | 五档输入阶梯、五次固定输入、可见输出与推理归属、小额粒度、整轮及热缓存段实扣对账 |
| #16–20 缓存 | 固定前缀默认 8 次，A/A′/A″ 失效、45K 冷热 TTFT、双会话与真实间隔、四档缓存率费用推演 |
| #21–27 签名 | 用量矛盾、可编辑注入指纹库、零额外请求的模型漂移、首中末三组采样、流式集中到达、答案缓存、BPS 待对照记录 |
| #28–36 模型与 Codex | 无状态加密推理回传、流式补丁转义、回声、参数透传、截断、三项多轮记忆、编程术语误杀、随机纯色 PNG、32K 至 200K 上下文 |
| #37–40 压测 | 1、5、10、20 逐档并发，可显式增加 50 档。记录状态分布、分位延迟、吞吐和费用。持续速率独立开启 |

快速模式选择 20 项，推理使用 low/high；完整模式默认选 #1–34。压测模式默认选 #37–39。矩阵方格和选择面板都可以按项开关。#35、#36、#40 始终需显式开启。对只分析已有样本的探针，单独勾选时使用本轮协议预检等实际样本。三个压测视图共用一次加压过程。

每轮使用随机盐和动态题面。报告中的「仅复测异常项」带回失败、需关注和证据不足的编号。前一次密钥已释放，重新运行需再次输入。历史对比可横向查看时段、能力、账目、缓存、注入和裁决。隐私开关同时作用于报告、四种导出和历史导出。

## 读数、计费与裁决口径

- **分词。** 本地计数按 `o200k_base` 实算文本原文，并计入规范化请求内容骨架及工具 Schema。逐段增量抵消固定封装开销。供应商内部序列化、隐藏指令和图像编码可能改变服务器计数，A/B 报告保留两侧数值。聚合用量只能给出注入部分命中缓存的上下界，2,000 token 短对话的费用按该区间计算。
- **协议。** Auto 优先 Responses。404、405、501 或明确的不支持端点错误允许降级。401、403、429、其余 5xx 和网络错误直接保留。本实现把规格明确列出的 501 作为 5xx 的特例。Chat 的 `prompt_tokens` / `completion_tokens` 与 Responses 的 `input_tokens` / `output_tokens` 分别解码。缺字段保留空值。
- **流式。** TTFT 取首次可见文本或函数参数增量的到达时间。长输出按前后四分位观察速度，至少需要每个四分位四个到达间隔。Max ITL 采用可观测的语义块间隔，块内多 token 的真实分隔时间待确认。集中输出和 TTFT 背离只提供疑似证据。
- **价格。** 费用等于 `((输入 − 缓存) × 输入单价 + 缓存 × 缓存单价 + 输出 × 输出单价) / 1000000`。缺少价格或必要计数字段时保留未知值。只有完整可比的理论费用才参与倍率计算。手工测前、测后额度可在报告页实时重算。
- **账本。** 原始面板余额按用户填写的每美元单位换算。常见兼容 `total_usage` 字段按美分解释，报告保留字段名与换算因子，可用人工对账覆盖。不同字段、路径或计量方向的快照不混算。实扣缓存折扣依赖 #15 与 #16 同选、热段独占账户以及非缓存部分按所填单价计费。
- **预算。** 快速默认 $1，完整及压测默认 $2。有单价时在发包前为预计输入与最大输出预留费用，在用量返回后结算。无单价时默认上限为 180 次请求、600,000 总 token，控制台可调。上游额外注入和已在途请求可能造成已发生用量超出预估；熔断会阻止后续发送并保留样本。
- **证据强度。** 已观测到的缓存计数矛盾、受控序列中可复核的内容无关高缓存、系统性阶梯偏离、分词不符或自报异构模型名触发指定硬红线。健康灯独立于能力分。时间抖动、日期快照、上游轮换、答案缓存和注入指纹匹配均保留推断边界。模型自报标识可审计，底层权重和真实 KV Cache 状态无法直接观测。
- **评分与样本不足。** 仅 #1–5 参与加权。报告同时展示分数及覆盖项数。未采集计分项时可基于实测硬红线判 D，其余情况显示「证据不足，待裁决」。不足三项可引用证据的自选报告仅列出现有理由。运行时段取部署主机的本地时区。
- **草案。** 所有可调判定阈值、预算上限与权重集中在「价格与规则」。BPS 保持「待对照确切指纹」。初始注入量 4233 与 4157 由需求规格提供，未独立核实。未填价格时 #20 单独标注推演假设折扣。

## 接口

| 方法与路径 | 用途 |
| --- | --- |
| `GET /api/config` | 探针目录、预设与可编辑阈值 |
| `POST /api/models` | 后端代理拉取模型，接受 `base_url`、`api_key` 和可选 `proxy` |
| `GET /api/profiles`、`POST /api/profiles`、`DELETE /api/profiles/{id}` | 读取、保存、导入和删除本地模板 |
| `POST /api/capture/arm` | 开启五分钟单次抓包，返回临时口令 |
| `POST /api/capture/v1/responses`、`POST /api/capture/v1/chat/completions` | 接收 CLI 请求，保存脱敏 Profile，返回本地确认 |
| `POST /api/runs` | 创建内存任务，返回 `run_id`、选择清单与预估量级 |
| `GET /api/runs/{run_id}/stream` | `log`、`sample`、`progress`、`report` 事件。支持 `Last-Event-ID` |
| `POST /api/runs/{run_id}/abort` | 取消在途请求、释放密钥并生成部分报告 |

请求结构以 `app/schemas.py` 为准。浏览器通过 `static/js/api.js` 访问同源 API。SSRF 校验检查全部 DNS 结果，连接使用已验证 IP，保留原始 Host、TLS 域名校验和 SNI。自动跳转关闭，HTTP CONNECT 与 SOCKS5 同样使用已验证的目标地址。

## 验收记录

V2.1.1 的两版回归、Fake-IP 验证和交付文件信息见验收记录。独立网页版包包含 `VALIDATION.md`，完整仓库中位于 [`relay-probe-rust/VALIDATION.md`](../relay-probe-rust/VALIDATION.md)。

V2.1.0 在 Windows 的 Python 3.11.9 环境完成 47 项自动检查，包括 42 项模拟站验收、4 项本地 TLS 与代理传输检查、1 项 Chromium 端到端操作。完整模式覆盖全部 40 个探针，高开销开关在该测试中显式启用。浏览器测试实际下载并检查了 JSON、CSV、Markdown 和 2080 像素宽的 PNG。

另在 Ubuntu 24.04 / Python 3.12.3 上通过 `sh start.sh` 启动并读取首页及 40 项探针目录。本机 Codex CLI 0.157.1 使用一次性口令完成了独立抓包导入，捕获模板包含 9 项工具声明。商业中转站的真实扣费、真实上游缓存命中及公网 Nginx 环境仍需在对应账户或部署环境验证。
