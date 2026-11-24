import asyncio
import statistics
import time

from app.core.tokenizer import padding
from .base import cache_rate, mean, ok, ratio, together
from .billing_probes import balance_snapshot


async def measured(c):
    prefix = padding(4096, c.salt+"-rate")
    rows = []
    for i in range(c.spec.controls.cache_repeats):
        if i == 1 and 15 in c.run.ids:
            c.memo["cache_ledger"] = {"before": await balance_snapshot(c, "热缓存窗口起始"), "seqs": []}
        r = await c.ask(f"固定前缀 {i+1}", prefix, key="rate")
        rows.append(r)
        if i > 0 and "cache_ledger" in c.memo:
            c.memo["cache_ledger"]["seqs"].append(r.seq)
    if "cache_ledger" in c.memo:
        c.memo["cache_ledger"]["after"] = await balance_snapshot(c, "热缓存窗口结束")
    rates = [cache_rate(r) for r in rows if ok(r) and cache_rate(r) is not None]
    if not rates:
        return c.lack("未返回可用缓存计数", rows=rows)
    avg = mean(rates)
    ad = c.spec.advertised_cache
    return c.finding(f"含冷启动的 {len(rates)} 条样本平均命中 {avg:.1%}", {"mean": avg, "median": statistics.median(rates),
                     "range": [min(rates), max(rates)], "rates": rates, "advertised_percent": ad}, rows=rows,
                     status="需关注" if ad is not None and avg*100 < ad else "通过")


async def invalidate(c):
    prefix = padding(8192, c.salt+"-content")
    a = await c.ask("A 建缓存", "A"+prefix+"X", key="content")
    b = await c.ask("A′ 改末字", "A"+prefix+"Y", key="content")
    d = await c.ask("A″ 改首字", "B"+prefix+"Y", key="content")
    rates = list(map(cache_rate, (a,b,d)))
    if None in rates or not all(map(ok, (a,b,d))):
        return c.lack("A/A′/A″ 用量不完整", {"rates": rates})
    # A shared profile prefix may legitimately hit. Test the entire controlled suffix beyond that bound.
    common_bound = max(0, d.local_input-8192) + max(0,d.input_delta or 0) + 128
    high = rates[2] >= c.rules.high_cache and d.counts["cached"] > common_bound
    fixed = high and rates[0] >= c.rules.high_cache and rates[1] >= c.rules.high_cache and b.counts["cached"] == d.counts["cached"]
    return c.finding(f"建缓存 {rates[0]:.1%}，改末字 {rates[1]:.1%}，改首字 {rates[2]:.1%}" +
                     ("，缓存与内容无关，疑似伪造缓存" if high else ""),
                     {"rates": rates, "shared_prefix_bound": common_bound}, status="异常" if high else "通过",
                     strength="实测检出" if fixed else "疑似" if high else "未检出", hard=fixed)


async def ttft(c):
    text = padding(45000, c.salt+"-kv")
    a = await c.ask("45K 冷请求", text, key="kv", heavy=True)
    b = await c.ask("45K 热请求", text, key="kv", heavy=True)
    speed = ratio(b.ttft, a.ttft)
    hot = cache_rate(b)
    metrics = {"cold_s": a.ttft, "warm_s": b.ttft, "warm_cold_ratio": speed, "warm_cache": hot}
    if None in (speed, hot) or not ok(a) or not ok(b):
        return c.lack("冷/热 TTFT 或缓存样本不完整", metrics)
    paper = hot >= c.rules.high_cache and speed >= c.rules.warm_ttft_ratio
    return c.finding(f"冷 {a.ttft:.3f}s，热 {b.ttft:.3f}s，热请求账面命中 {hot:.1%}" +
                     ("，疑似纸面缓存" if paper else ""), metrics, status="需关注" if paper else "通过")


async def stickiness(c):
    text = padding(3072, c.salt+"-sticky")
    await c.ask("建立粘性前缀", text, key="sticky")
    spans = [0, 15] if c.spec.mode == "quick" else [0, 15, 60]
    rates = []
    for gap in spans:
        if gap:
            c.run.log(f"缓存粘性等待 {gap} 秒", c.id)
        at = time.monotonic()
        await asyncio.sleep(gap)
        waited = time.monotonic()-at
        r = await c.ask(f"间隔 {gap}s", text, key="sticky")
        rates.append({"interval_s": gap, "waited_s": waited, "rate": cache_rate(r), "seq": r.seq})
    await together(*(c.ask(f"会话 {s} 建缓存", text, key="session-"+s, session=s) for s in ("a","b")))
    pairs = await together(*(c.ask(f"会话 {s} 重发", text, key="session-"+s, session=s) for s in ("a","b")))
    multi = [cache_rate(r) for r in pairs]
    if any(r["rate"] is None for r in rates) or None in multi:
        return c.lack("粘性样本缺少缓存字段", {"intervals": rates, "sessions": multi})
    drop = rates[0]["rate"] >= c.rules.high_cache and rates[1]["rate"] < c.rules.high_cache
    return c.finding(f"{len(spans)} 个时间档与 2 个并发会话已采样" + ("，短间隔缓存回落，疑似无粘性轮询" if drop else ""),
                     {"intervals": rates, "sessions": multi}, status="需关注" if drop else "通过")


def sensitivity(c):
    p = c.spec.prices
    if p and not p.input:
        return c.lack("输入单价为零，折扣比例无定义", rows=[])
    discount = p.cached/p.input if p else c.rules.assumed_cache_ratio
    measured_rate = c.run.results.get(16)
    base = measured_rate.metrics.get("mean") if measured_rate else None
    reference = base if base is not None else 1.
    baseline = 1-reference+reference*discount
    table = [{"rate": r, "relative_input_cost": 1-r+r*discount, "increase": ratio(1-r+r*discount, baseline)}
             for r in (.95, .90, .88, .60)]
    for x in table:
        if x["increase"] is not None:
            x["increase"] -= 1
    rows = [r for r in c.traffic if r.probe == 16]
    return c.finding(f"按{'所填单价' if p else '草案假设'}折扣比 {discount:.3f} 推演 4 档缓存率",
                     {"basis": "所填单价" if p else "假设比，待确认", "reference": reference,
                      "reference_source": "实测" if base is not None else "假设 100% 命中", "discount": discount, "scenarios": table}, rows=rows)


HANDLERS = {16: measured, 17: invalidate, 18: ttft, 19: stickiness}
