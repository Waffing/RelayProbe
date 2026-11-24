from datetime import datetime

from app.probes.base import mean, ok, ratio
from app.schemas import Report

GRADES = {"A": "A 值得入手", "B": "B 小额试用", "C": "C 只适合不敏感小活", "D": "D 不值得入手（避坑）"}
GUIDANCE = {
    "A": ["按一次实际任务的小额预算首充", "本轮已通过的编程与工具场景", "未实测的高开销场景", "高峰时段或版本变更后复测"],
    "B": ["只充值一次试用任务所需额度", "可复核、可重试的低成本任务", "无人值守的重要任务", "首次试用后换时段复测"],
    "C": ["先使用已有余额", "非敏感且可人工校验的小任务", "重要工程、长链路或高额调用", "异常修复后复测"],
    "D": ["暂停首充", "验证站方修复的隔离样本", "付费生产工作负载", "拿到修复说明后复测"],
}


def report(run):
    rows = sorted(run.rows, key=lambda r: r.seq)
    findings = sorted(run.results.values(), key=lambda x: x.id)
    spec, rules = run.spec, run.spec.controls.rules
    def metric(i, name):
        f = run.results.get(i)
        return f.metrics.get(name) if f else None
    graded = [f for f in findings if 1<=f.id<=5 and f.score is not None]
    weights = spec.controls.weights
    weighted = sum(weights[f.id-1] for f in graded)
    score = round(100*sum(f.score*weights[f.id-1] for f in graded)/weighted,1) if weighted else None
    alerts = [f for f in findings if f.status in ("需关注","异常")]
    hard = [f for f in alerts if f.hard and f.strength == "实测检出" and f.id in (1,7,11,17,18,23)]
    complete = [r for r in rows if r.method=="POST" and ok(r)]
    partial = bool(run.stop) or any(f.status == "证据不足" for f in findings)
    severe = [f for f in alerts if f.status=="异常" and f.id in (2,7,11,17,23,28,37,38)]
    high_injection = (metric(6,"profile_delta") or 0) >= rules.high_injection
    health = "红" if hard or severe or high_injection else "黄" if alerts or partial or not complete else "绿"
    if hard:
        grade = "D"
    elif score is None or not complete:
        grade = None
    elif health=="红":
        grade = "C" if score>=rules.score_c else "D"
    elif score>=rules.score_a and health=="绿" and len(graded)==5 and not partial:
        grade = "A"
    elif score>=rules.score_b:
        grade = "B"
    elif score>=rules.score_c:
        grade = "C"
    else:
        grade = "D"
    ordered = sorted((f for f in findings if f.samples), key=lambda f:(not f.hard, f.status!="异常", f.status!="需关注", f.id))
    reasons = [{"id": f.id, "text": f.summary, "samples": f.samples, "evidence": f.evidence} for f in ordered[:5]]
    counts = {}
    model_rows = [r for r in rows if r.method=="POST"]
    for k in ("input","output","cached","reasoning"):
        known = [r.counts[k] for r in model_rows if r.counts.get(k) is not None]
        counts[k] = sum(known) if known else None
        counts[k+"_reported"] = len(known)
    failed = sum(not ok(r) for r in rows)
    stream_time = sum(r.chunks[-1]["t"]-r.chunks[0]["t"] for r in model_rows if len(r.chunks)>1)
    stream_tokens = sum(sum(c["tokens"] for c in r.chunks[1:]) for r in model_rows if len(r.chunks)>1)
    totals = {**run.budget.snapshot(), **counts, "requests":len(rows), "failed":failed,
              "ttft":mean(r.ttft for r in complete), "output_tps":ratio(stream_tokens,stream_time)}
    start = datetime.fromisoformat(run.started)
    period = "晚高峰 19:00–23:59" if start.hour>=19 else "凌晨低峰" if start.hour<7 else "白天平峰"
    scope = "裸请求" if spec.bare else f"完整伪装 {run.profile.name}"
    origin = "自建基准" if run.profile.source=="自建基准模板" else run.profile.source
    route = f"走 {run.protocol} · {scope}（{origin} {run.profile.baseline_tokens} tok，与外部工具 9845 口径独立）"
    summary = f"{len(rows)} 次请求，{failed} 次失败，{len(alerts)} 项异常或需关注，{len(hard)} 项触发硬红线。"
    pending = ["草案·待用户确认：判分分界、证据提示阈值与能力权重。", "本地基准采用 o200k_base 规范化请求内容；供应商内部序列化开销待确认。",
               "BPS 确切指纹待确认。", "4233 / 4157 源自规格所述 2026-11 三家实测，来源未独立复核。"]
    if not spec.prices:
        pending.append("未配置官方单价，已跳过计算。")
    if len(graded)<5:
        pending.append(f"能力评分覆盖 {len(graded)}/5 项，已测项按权重归一。")
    if partial:
        pending.append("样本不完整，见各项证据与运行停止原因。")
    ledger_metric = run.results.get(15)
    reconciliation = dict(ledger_metric.metrics) if ledger_metric else {}
    ledger = spec.ledger
    if ledger.before is not None and ledger.after is not None:
        amount = (ledger.after-ledger.before)*(1 if ledger.kind=="used" else -1)/ledger.units_per_usd
        reconciliation["deduction_usd"] = amount if amount>=0 else None
        reconciliation["effective_multiplier"] = ratio(reconciliation["deduction_usd"],totals["cost"]) if not totals["unknown_cost"] else None
    meta = {"name":spec.name, "base_url":spec.base_url, "model":spec.model, "mode":spec.mode, "protocol":run.protocol,
            "requested_protocol":spec.protocol, "route":route, "profile":run.profile.name, "profile_id":run.profile.id,
            "profile_source":run.profile.source, "baseline_tokens":run.profile.baseline_tokens, "mode_bare":spec.bare,
            "start":run.started, "end":datetime.now().astimezone().isoformat(), "period":period, "salt":run.salt, "selection":run.ids,
            "stop":run.stop, "partial":partial, "ledger":spec.ledger.model_dump(), "prices":spec.prices.model_dump() if spec.prices else None,
            "controls":spec.controls.model_dump(), "advertised_cache":spec.advertised_cache}
    return Report(run_id=run.id, meta=meta, requests=rows, findings=findings, totals=totals,
                  head={"score":score, "score_coverage":len(graded), "health":health, "triggers":[f.id for f in alerts],
                        "effective_multiplier":reconciliation.get("effective_multiplier"), "deduction_usd":reconciliation.get("deduction_usd"),
                        "cache_rate":metric(16,"mean"), "injection":metric(6,"profile_delta"),
                        "input_verdict":run.results[11].summary if 11 in run.results else "未测阶梯",
                        "summary":summary},
                  verdict={"grade":grade, "label":GRADES.get(grade,"证据不足，待裁决"), "hard":[f.id for f in hard],
                           "reasons":reasons, "guidance":GUIDANCE.get(grade, ["暂缓首充","尚待实测","未覆盖场景","补足计分项后复测"]),
                           "summary":summary}, pending=pending)
