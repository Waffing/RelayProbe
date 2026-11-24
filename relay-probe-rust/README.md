# 中转站渠道质量探针 V2.1.1 · Rust

本地 AI API 渠道测评软件。探针引擎、HTTP 服务、代理传输、精确分词、调度、预算和裁决全部使用 Rust 实现。原生 HTML/CSS/JavaScript 中文控制台和 `o200k_base` 词表编入可执行文件。

## Windows 使用

解压便携包，双击 `RelayProbe.exe`。程序启动后自动用默认浏览器打开本机控制台。填写 Base URL、API Key 和模型，选择检测项目后开始运行。

运行软件无需安装 Python、Node.js 或 Rust。保持启动窗口打开，关闭窗口或按 Ctrl+C 退出。需要取消当前测评时，先点击页面上的「中止」按钮。

默认仅监听 `127.0.0.1:8787`。默认端口已被占用时，依次尝试 8788–8799，并打开实际使用的端口。指定 `PORT` 后严格使用所指定的端口，冲突时显示错误。浏览器历史按端口保存，查看同一份历史需使用相同端口。

```powershell
$env:HOST = '127.0.0.1'
$env:PORT = '8787'
.\RelayProbe.exe
```

命令行支持 `--no-open`、`--version`、`--help`。本机默认回环监听是此次 Windows 迁移的部署选择。

## 检测与报告

| 组别 | 项目 |
| --- | --- |
| #1–5 能力 | 12 段分词增量、动态推理题、严格结构、强制与并行工具闭环、系统指令、约 100K 长文检索 |
| #6–10 请求质量 | Profile / 裸请求差分、缓存合规与冷启动、不可见字符、流式完整性与尾部速度、Responses 续接 |
| #11–15 验账 | 五档输入阶梯、重复稳定性、输出交叉计数、取整行为、整轮与缓存窗口余额对账 |
| #16–20 缓存 | 命中率、首末字失效、45K 冷热 TTFT、实际时间间隔和并发双会话、价格敏感度 |
| #21–27 签名 | 用量矛盾、注入指纹库、返回模型漂移、首中末上游特征、假流式、答案缓存、BPS 待对照记录 |
| #28–36 模型与 Codex | 加密推理回传、流式工具转义、回声、参数透传、截断、多轮记忆、技术词误杀、可选视觉和上下文阶梯 |
| #37–40 压测 | 1→5→10→20 阶梯、停压、分位耗时与吞吐、可选 60 秒持续速率 |

快速模式默认选择 20 项，完整模式选择 #1–34，压测模式选择 #37–39。#35、#36、#40 需要显式开启，可按单项自由选择。50 并发需要开启对应开关。

报告支持逐条请求证据、JSON / CSV / Markdown / 高清 PNG 导出、隐私隐藏域名、历史对比、补填余额和异常项目复测。价格表初始为空，按实际供应商价格填写。只有 #1–5 参与能力分，健康灯独立计算。

预检优先使用 Responses，404、405、501 或明确的不支持端点响应允许降级。401、403、429、其余 5xx 和网络错误保留实际失败。501 按原规格作为允许降级的特例处理。

## 密钥和网络

API Key 由浏览器提交给本机 Rust 服务，所有目标请求均由后端发出。Key 和代理凭据不写入报告、Profile、历史、URL 或服务访问日志。受控密钥字符串使用 `Zeroizing` 管理，完成、异常、中止后释放连接池与密钥。网络库、浏览器和操作系统内部缓冲区的物理清零无法通过本软件保证。

目标和代理均校验全部 DNS 结果，连接固定到已校验 IP。HTTP CONNECT、HTTPS CONNECT 和 SOCKS5 隧道使用目标 IP，HTTPS 继续按原始域名验证证书及 SNI。跳转不自动跟随，出站不继承系统代理或 Cookie。需要代理时在页面明确填写。

Clash / Mihomo 返回 Fake-IP 时，连接表单会显示「启用本机网络兼容」。启用后重试即可。该选项仅在本机回环控制台开放，当前页面内生效，用于 HTTPS 域名的 `198.18.0.0/15` DNS 结果和显式填写的回环代理。仍会检查每条 DNS 结果并校验 TLS 证书。TUN 模式下可留空代理 URL。

自定义 Profile 默认保存到 `%LOCALAPPDATA%\RelayProbe\profiles.json`。历史、价格和界面设置保存在当前浏览器。运行报告在内存中保留约 30 分钟供 SSE 重连。

| 环境变量 | 默认值 | 用途 |
| --- | --- | --- |
| `HOST` | `127.0.0.1` | 监听地址 |
| `PORT` | `8787` | 端口，未显式设置时可自动避让 |
| `ACCESS_PASSWORD` | 空 | 保护全部 `/api/*` 的控制台口令 |
| `ALLOW_PRIVATE_TARGETS` | `false` | 允许本地模拟站或受信内网目标 |
| `PROBE_DATA_DIR` | Windows 本地应用数据目录中的 `RelayProbe` | 脱敏 Profile 目录 |
| `SSL_CERT_FILE` | 系统证书库 | 额外信任的 PEM CA，用于企业证书或测试 |

## Profile 导入与 CLI 抓包

内置模板是本项目自建的 Codex 风格基准。页面显示其本地实算 token 数。可在 Profile 编辑器粘贴 JSON 或带内联 JSON 请求体的 POSIX cURL，也可编辑或导出模板。

抓包时，在控制台开启一次抓包，取得五分钟有效的一次性口令。让本机 CLI 向以下端点发一次请求。

```text
http://127.0.0.1:8787/api/capture/v1
```

在当前终端设置临时 `RELAY_CAPTURE_TOKEN` 后，可使用下列 Codex CLI 配置。端口须与软件当前端口一致。

```powershell
codex exec --ephemeral --skip-git-repo-check -s read-only -c 'model_provider="probe_capture"' -c 'model_providers.probe_capture.name="Local Capture"' -c 'model_providers.probe_capture.base_url="http://127.0.0.1:8787/api/capture/v1"' -c 'model_providers.probe_capture.wire_api="responses"' -c 'model_providers.probe_capture.env_key="RELAY_CAPTURE_TOKEN"' -m fixture-model 'Reply OK.'
```

模板保留客户端头、system/developer 内容、工具声明和请求骨架。鉴权头被剥离，用户对话与工作区内容从输入历史中移除，会话标识由运行时生成。捕获端点仅接受本机回环连接及有效口令。

## 源码构建

使用 Rust 1.90 或更新版本。Windows 可使用 MSVC 工具链及其链接工具，或 GNU 工具链和 MinGW-w64。本次 Windows 构建使用 GNU 目标与静态 CRT。

```powershell
.\scripts\build.ps1
```

Linux 或 macOS 可使用本机 Rust 工具链构建。`native-tls` 在 Linux 上需要 OpenSSL 开发依赖。

```sh
cargo build --release --locked
HOST=127.0.0.1 PORT=8787 ./target/release/relay-probe --no-open
```

源码按 `src/core/`、`src/probes/` 和 `src/server.rs` 拆分。`Cargo.lock` 固定依赖版本。测试目录中的 Python 仅用于模拟站、独立分词对照与浏览器自动化。

## 自动验收

先构建 Release 可执行文件，再运行以下命令。测试从任意临时目录启动 Rust 程序，实际连接本地模拟站，检查 HTTP、SSE、计费、并发、捕获、SSRF、TLS 和四种导出。

```powershell
py -3.11 -m venv .test-venv
.\.test-venv\Scripts\python -m pip install -r tests\requirements.txt
.\.test-venv\Scripts\python -m playwright install chromium
.\.test-venv\Scripts\python -m pytest -q tests
```

使用 `RELAY_PROBE_EXE` 指向其他构建产物。TLS 测试需要 OpenSSL 命令行生成本机临时证书。全量检测中的 15 秒、60 秒缓存等待和 60 秒持续采样均使用真实时长。

## 服务器反代

可设置 `HOST` 和独立端口部署，使用 `ACCESS_PASSWORD` 控制访问。Nginx 配置需保留 SSE 连接并关闭缓冲。

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

反代监听场景请将 `HOST` 设置为服务器指定地址或 `0.0.0.0`，以允许所配置域名的 Host 头。日志格式应省略鉴权头、请求体和查询参数。

## 判定口径

费用按非缓存输入、缓存读取和输出单价计算。缺少必要用量字段时费用保持未知。无单价默认上限为 180 次请求、600,000 总 token，预算有单价时按发包前预留与返回后结算执行。

分词采用原文文本与规范化内容骨架进行本地计数。供应商内部封装、隐藏指令和图像编码可能影响服务器计数。注入量与缓存归属使用可观察差额和上下界，保留完整证据。

TTFT 取首次文本或工具参数增量，ITL 采用语义块到达时间。原始 chunk 时间序列、完整 `usage`、脱敏请求和响应均保留。连接建立阶段数据描述该 HTTP 连接的初次建立，`request_to_headers` 与 `total_transfer` 对应当前请求。

阈值与权重集中在「价格与规则」，均保留草案标注。4233 / 4157 指纹来自用户规格，尚未独立核实。BPS 保持「待对照确切指纹」。模型标识、纸面缓存与混池判断只能覆盖当前响应中的可观察行为。

本地模拟验收结果见 `VALIDATION.md`。商业中转站真实扣费、真实上游缓存和公网反代部署须在对应账户及环境验证。
