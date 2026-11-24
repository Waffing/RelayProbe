import unicodedata

from app.core.tokenizer import padding
from .base import cache_rate, ok, ratio


async def injection(c):
    prompt = f"样本 {c.salt}。只回答 OK。"
    full = await c.ask("Profile 基线", prompt, bare=False)
    bare = await c.ask("极简裸请求对照", prompt, bare=True)
    a, b = full.input_delta, bare.input_delta
    metrics = {"profile_delta": a, "bare_delta": b, "profile_share": ratio(a, full.counts.get("input"))}
    if None in (a, b) or not all(map(ok, (full, bare))):
        return c.lack("A/B 请求缺少可比较的输入计数", metrics)
    excess = max(a, 0)
    cached = full.counts.get("cached")
    # Aggregate usage does not locate cached tokens. Only these bounds are identifiable.
    usable = cached is not None and 0 <= cached <= full.counts["input"]
    lower = max(0, cached-full.local_input) if usable else None
    upper = min(cached, excess) if usable else None
    metrics.update(injection_cache_bounds=[lower, upper], input_inflation_2000=(2000+excess)/2000,
                   estimated_cost_ratio_2000=None)
    p = c.spec.prices
    if p and p.input and lower is not None:
        vals = [(2000*p.input + (excess-h)*p.input + h*p.cached)/(2000*p.input) for h in (lower, upper)]
        metrics["estimated_cost_ratio_2000"] = sorted(vals)
    tol = c.rules.input_tolerance
    text = ("Profile 侧额外输入较多，疑似按客户端分流" if a-b > tol else
            "两种请求均有额外输入，疑似固定注入" if min(a, b) > tol else "两种请求的本地输入差额接近基线")
    return c.finding(f"Profile 差额 {a:+d} tok，裸请求 {b:+d} tok。{text}", metrics,
                     status="需关注" if max(a,b) > tol else "通过")


async def cache_cold(c):
    prefix = padding(4096, c.salt+"-fresh")
    row = await c.ask("全新盐冷启动", prefix, key="cold-unique")
    await c.ask("相同前缀热样本", prefix, key="cold-unique")
    c.memo["cold_seq"] = row.seq
    return audit_cache(c)


def audit_cache(c):
    rows = [r for r in c.traffic if r.counts.get("cached") is not None]
    invalid = [r for r in rows if (x := r.counts["cached"]) > 0 and (x % 128 or x < 1024)]
    cold = next((r for r in rows if r.seq == c.memo.get("cold_seq")), None)
    high = cold is not None and (cache_rate(cold) or 0) >= c.rules.high_cache
    metrics = {"non128": [r.seq for r in rows if r.counts["cached"] % 128],
               "below1024": [r.seq for r in rows if 0 < r.counts["cached"] < 1024],
               "cold_rate": cache_rate(cold) if cold else None, "cold_seq": c.memo.get("cold_seq")}
    if not rows or not cold:
        return c.lack("缺少冷启动缓存明细", metrics, rows)
    broken_granularity = bool(metrics["non128"])
    return c.finding(f"{len(rows)} 个缓存计数中 {len(invalid)} 个违反粒度或起跳门槛" +
                     ("，低于 1024 的非零计数疑似自算" if metrics["below1024"] else "") +
                     ("，冷启动异常命中，疑似伪造缓存" if high else ""), metrics, rows=rows,
                     status="异常" if broken_granularity or high else "需关注" if invalid else "通过",
                     strength="实测检出" if broken_granularity else "疑似" if invalid or high else "未检出", hard=broken_granularity)


def invisible(c):
    rows = [r for r in c.traffic if r.text]
    hits = [{"seq": r.seq, "position": i, "codepoint": f"U+{ord(ch):04X}"} for r in rows for i, ch in enumerate(r.text)
            if unicodedata.category(ch) in ("Cf", "Cc") and ch not in "\n\r\t"]
    if not rows:
        return c.lack("没有可扫描的返回文本", rows=rows)
    return c.finding(f"扫描 {len(rows)} 条回答，发现 {len(hits)} 个不可见字符", {"hits": hits}, rows=rows,
                     status="需关注" if hits else "通过", strength="实测检出" if hits else "未检出")


async def long_stream(c):
    await c.ask("长输出速度样本", f"样本 {c.salt}。连续输出 640 次字符 X，不加空格。", limit=1024)
    return stream_audit(c)


def stream_audit(c):
    rows = [r for r in c.traffic if r.stream]
    if not rows:
        return c.lack("无流式请求", rows=[])
    finished = sum(ok(r) for r in rows)
    usage = sum(all(r.counts.get(k) is not None for k in ("input", "output", "total")) for r in rows)
    timings, timeouts = [], []
    for r in rows:
        if not ok(r) and any(abs(r.elapsed-t) <= c.rules.timeout_window_s for t in (30, 60)):
            timeouts.append({"seq": r.seq, "seconds": r.elapsed})
        chunks = r.chunks
        # At least four inter-chunk intervals per quartile for a speed comparison.
        if len(chunks) < 20:
            continue
        q = len(chunks)//4
        def speed(items):
            return ratio(sum(p["tokens"] for p in items[1:]), items[-1]["t"]-items[0]["t"])
        front, tail = speed(chunks[:q]), speed(chunks[-q:])
        timings.append({"seq": r.seq, "first_quarter_tps": front, "last_quarter_tps": tail, "tail_ratio": ratio(tail, front),
                        "max_itl_s": max(b["t"]-a["t"] for a,b in zip(chunks, chunks[1:]))})
    bad = finished != len(rows) or usage != len(rows) or any(t["tail_ratio"] is not None and t["tail_ratio"] < c.rules.tail_ratio for t in timings)
    decays = [t for t in timings if t["tail_ratio"] is not None and t["tail_ratio"] < c.rules.tail_ratio]
    return c.finding(f"{finished}/{len(rows)} 正常结束，{usage}/{len(rows)} 返回完整用量" +
                     (f"，{len(decays)} 个长输出样本出现尾段减速" if decays else ""),
                     {"completed": finished, "usage_complete": usage, "timings": timings, "near_timeout": timeouts,
                      "timing_scope": "按可见语义块到达时间测量。单块包含多 token 时，块内 ITL 不可观测。"},
                     rows=rows, status="需关注" if bad else "通过")


async def native(c):
    stateless = await c.ask("store=false", "只回复 OK", extra={"store": False})
    checks = {"id": bool(stateless.response_id), "usage": stateless.usage is not None, "正常完结": ok(stateless)}
    if c.run.protocol == "responses":
        checks["原生事件"] = all(e in stateless.events for e in ("response.output_text.delta", "response.completed"))
        stored = await c.ask("建立可续接响应", "本轮口令为 " + c.salt + "，先回答 OK。", extra={"store": True})
        if stored.response_id:
            follow = await c.ask("previous_response_id 续接", "请复述前一轮给出的口令。", extra={"previous_response_id": stored.response_id, "store": False})
            checks["续接请求受理"] = ok(follow)
            checks["续接记忆"] = ok(follow) and c.salt in follow.text
        else:
            checks["续接请求受理"] = False
    return c.checked(checks, metrics={"protocol": c.run.protocol})


HANDLERS = {6: injection, 7: cache_cold, 9: long_stream, 10: native}
