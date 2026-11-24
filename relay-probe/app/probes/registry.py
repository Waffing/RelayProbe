from app.signatures import engine
from . import billing_probes as bill, cache_probes as cache, model_probes as model, quality_probes as quality
from . import scoring_probes as scoring, stress_probes as stress

GROUPS = [
    ("能力计分", ["分词指纹", "推理能力", "结构与工具闭环", "指令层级", "大海捞针"]),
    ("请求质量", ["注入 A/B 差分", "缓存合规与冷启动", "不可见字符", "流式完整性", "协议与原生 Responses"]),
    ("验账与计费", ["阶梯输入验账", "重复稳定性", "输出计数交叉验证", "计费取整", "余额与有效折扣"]),
    ("缓存深度", ["实测缓存率", "缓存失效", "TTFT 交叉验真", "时间与多会话粘性", "缓存敏感度推演"]),
    ("科技签名", ["用量改写层", "注入指纹", "模型与指纹漂移", "混池与轮换上游", "假流式", "答案缓存", "BPS 类指纹"]),
    ("模型与 Codex", ["加密推理链", "工具参数转义", "随机回声", "参数透传", "输出截断", "多轮记忆", "编程安全词误杀", "多模态真伪", "上下文阶梯"]),
    ("并发压测", ["阶梯加压", "停压条件", "每档统计", "持续速率"])]
NAMES = dict(enumerate((name for _, names in GROUPS for name in names), 1))
HIGH = {35,36,40}
ACTIVE = {**scoring.HANDLERS, **quality.HANDLERS, **bill.HANDLERS, **cache.HANDLERS, **model.HANDLERS,
          **engine.ACTIVE, 40: stress.sustained}
PASSIVE = {7: quality.audit_cache, 8: quality.invisible, 9: quality.stream_audit, 13: bill.output_audit,
           15: bill.reconcile, 20: cache.sensitivity, **engine.PASSIVE, **dict.fromkeys((37,38,39), stress.stress_result)}


def catalog():
    return [{"id": i, "name": name, "group": group, "expensive": i in HIGH} for i,name in NAMES.items()
            for group, names in GROUPS if name in names]


def selected(mode, ids, expensive):
    defaults = {"quick": [1,2,3,4,6,7,8,9,10,11,12,13,16,20,21,22,23,25,27,30],
                "full": list(range(1,35)), "stress": [37,38,39]}
    return sorted((set(ids or defaults[mode]) - (HIGH-set(expensive))) | (set(expensive) if ids is None else set()))


def estimate(spec, ids):
    numbers = {1:13, 2:8 if spec.mode=="quick" else 12, 3:4, 4:2, 5:1, 6:2, 7:2, 9:1, 10:3,
               11:5, 12:5, 14:5, 15:4, 16:spec.controls.cache_repeats, 17:3, 18:2,
               19:7 if spec.mode=="quick" else 8, 22:int(6 not in ids), 24:6, 26:2, 28:2, 29:1, 30:1, 31:5,
               32:2, 33:4, 34:4, 35:1, 36:4, 40:spec.controls.sustained_rpm}
    calls = 1+sum(numbers.get(i, 0) for i in ids) + (36+50*spec.allow_50 if set(ids)&{37,38,39} else 0)
    if 15 in ids and 16 in ids:
        calls += 4
    pads = {5:100_000, 7:8192, 11:15_000, 16:4096*spec.controls.cache_repeats, 17:24576,
            18:90_000, 19:24576, 36:424_000}
    return {"requests_approx": calls, "tokens_approx": calls*512+sum(pads.get(i,0) for i in ids),
            "basis": "按已勾选项目、已知长前缀以及每次约 512 tok 的规划假设估量。预检降级、失败和提前停压会改变实际量。"}
