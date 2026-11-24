import asyncio
import re
from collections import Counter

from app.probes.base import mean, ok, percentile, question, ratio


def usage_rewrite(c):
    rows = [r for r in c.traffic if r.status == 200]
    issues, missing = [], []
    for r in rows:
        counts = r.counts
        i, o, cached, reasoning, total = (counts.get(k) for k in ("input", "output", "cached", "reasoning", "total"))
        bad = []
        if None not in (i, o, total) and total != i+o:
            bad.append("总量不守恒")
        if None not in (i, cached) and cached > i:
            bad.append("缓存大于输入")
        if cached and (cached % 128 or cached < 1024):
            bad.append("缓存粒度或门槛不符")
        if None not in (o, reasoning) and not r.calls and abs(o-reasoning-r.local_output)>c.rules.output_tolerance:
            bad.append("可见输出交叉差幅")
        if bad:
            issues.append({"seq": r.seq, "observations": bad})
        absent = [k for k,v in (("system_fingerprint", r.fingerprint), ("x-request-id", r.response_headers.get("x-request-id")),
                                ("cached_tokens", cached), ("reasoning_tokens", reasoning), ("usage", r.usage)) if v is None]
        if absent:
            missing.append({"seq": r.seq, "missing": absent})
    if not rows:
        return c.lack("无成功的协议响应", rows=[])
    return c.finding(f"{len(rows)} 条响应中 {len(issues)} 条计数异常，{len(missing)} 条缺少参考字段",
                     {"issues": issues, "missing": missing, "scope": "字段缺失单列，无法据此归因改写层"}, rows=rows,
                     status="需关注" if issues or missing else "通过")


async def injection_fingerprint(c):
    src = c.run.results.get(6)
    if src:
        value = src.metrics.get("profile_delta")
        rows = [r for r in c.traffic if r.seq in src.evidence]
    else:
        r = await c.ask("注入指纹基线", f"样本 {c.salt}，只回复 OK。", bare=False)
        value, rows = r.input_delta, [r]
    metrics = {"observed": value, "library": c.spec.fingerprints, "provenance": "初始 4233 / 4157 来自规格所述 2026-11 三家实测，未经独立核实"}
    if value is None:
        return c.lack("无有效输入差额", metrics, rows)
    hit = value in c.spec.fingerprints
    return c.finding(f"输入差额 {value} tok，{'匹配' if hit else '未匹配'}库中数值", metrics, rows=rows,
                     status="需关注" if hit else "通过", strength="疑似" if hit else "未检出")


def drift(c):
    rows = [r for r in c.traffic if r.model or r.fingerprint]
    models = Counter(r.model for r in rows if r.model)
    fps = Counter(r.fingerprint for r in rows if r.fingerprint)
    requested = c.spec.model
    mismatches = [m for m in models if m != requested]
    def family(m):
        leaf = m.casefold().rsplit("/",1)[-1]
        return re.sub(r"(?:-(?:\d{4}-\d{2}-\d{2}|\d{8}|\d{4}|latest|preview|snapshot))+$","",leaf)
    alias = family(requested) in ("auto","default","router","latest")
    foreign = [m for m in mismatches if not alias and family(m) != family(requested)]
    if not models:
        return c.lack("响应未返回模型", rows=rows)
    return c.finding(f"{len(models)} 个返回模型名，{len(fps)} 种指纹，{len(foreign)} 个异构返回名",
                     {"models": dict(models), "fingerprints": dict(fps), "unexpected_names": mismatches,
                      "heterogeneous": foreign, "scope": "审计响应自报标识；同族日期快照和指纹跳变仅提示复核"},
                     rows=rows, status="异常" if foreign else "需关注" if mismatches or len(fps)>1 else "通过", hard=bool(foreign))


async def checkpoint(c, phase):
    prompt, _ = question(c.salt, 0)
    a = await c.ask(phase+" · 短分词", "回执 "+c.salt+" | 短句 72，café 🧭，请回复 OK。")
    b = await c.ask(phase+" · 短推理", prompt, effort="low")
    c.memo.setdefault("checkpoints", []).append({"phase": phase, "seqs": [a.seq,b.seq], "latency": mean((a.elapsed,b.elapsed)),
        "fingerprint_delta": a.input_delta, "reasoning": b.counts.get("reasoning"), "headers": {
            k: v for k,v in b.response_headers.items() if k in ("server","via","x-upstream","x-served-by","openai-processing-ms")},
        "id_prefix": re.split("[_-]", b.response_id or "")[0], "fingerprint": b.fingerprint})


def mixed(c):
    samples = c.memo.get("checkpoints", [])
    if len(samples) < 3:
        return c.lack(f"开头、中段、末尾取得 {len(samples)}/3 组", {"phases": samples})
    identities = {(s["headers"].get("x-upstream"), s["headers"].get("server"), s["id_prefix"], s["fingerprint"],
                   s["fingerprint_delta"], s["reasoning"]) for s in samples}
    times = [s["latency"] for s in samples if s["latency"] is not None]
    clusters = sorted(samples, key=lambda s:s["latency"])
    timing_groups = []
    for sample in clusters:
        if not timing_groups or sample["latency"] > timing_groups[-1]["min_s"]*c.rules.duration_ratio:
            timing_groups.append({"min_s":sample["latency"],"phases":[]})
        timing_groups[-1]["phases"].append(sample["phase"])
    metrics = {"phases":samples,"latency_groups":timing_groups,"feature_groups":len(identities),
               "latency_range":[min(times),max(times)] if times else []}
    return c.finding(f"3 个时点出现 {len(identities)} 组可观察特征", metrics,
                     status="需关注" if len(identities)>1 else "通过")


def bursts(c):
    rows = [r for r in c.traffic if r.chunks]
    stats, flagged = [], []
    for r in rows:
        times = [x["t"] for x in r.chunks]
        gaps = [times[0]] + [b-a for a,b in zip(times,times[1:])]
        stats.append({"seq": r.seq, "max_silence": max(gaps), "chunks": len(times), "gap_p50": percentile(gaps,.5),
                      "gap_p95": percentile(gaps,.95), "arrival_span": times[-1]-times[0]})
        if times[0] >= c.rules.burst_gap_s and times[-1]-times[0] < c.rules.burst_gap_s/10 and len(times)>=2:
            flagged.append(r.seq)
    if not rows:
        return c.lack("没有输出 chunk 时间序列", rows=[])
    return c.finding(f"{len(rows)} 条流式样本中 {len(flagged)} 条出现静默后集中输出",
                     {"distributions": stats, "flagged": flagged}, rows=rows, status="需关注" if flagged else "通过")


async def answer_cache(c):
    prompt, _ = question(c.salt, 2)
    text = f"回执 {c.salt}。{prompt}"
    a = await c.ask("同题首轮", text, key="answer")
    await asyncio.sleep(1)
    b = await c.ask("间隔重发", text, key="answer")
    rel = ratio(b.ttft,a.ttft)
    identical = a.text == b.text
    if not ok(a) or not ok(b) or rel is None:
        return c.lack("同题样本不完整")
    suspect = identical and rel < c.rules.answer_ttft_ratio
    return c.finding(f"两次回答{'相同' if identical else '不同'}，第二次 TTFT 为首次的 {rel:.2f} 倍" +
                     ("，疑似命中站内答案缓存" if suspect else ""), {"ttft_ratio": rel, "identical": identical}, status="需关注" if suspect else "通过")


def bps(c):
    rows = c.traffic
    return c.finding("待对照确切指纹", {"observable": [{"seq": r.seq, "model": r.model, "fingerprint": r.fingerprint,
                     "status": r.status, "ttft": r.ttft} for r in rows]}, rows=rows, status="待对照确切指纹")


PASSIVE = {21: usage_rewrite, 23: drift, 24: mixed, 25: bursts, 27: bps}
ACTIVE = {22: injection_fingerprint, 26: answer_cache}
