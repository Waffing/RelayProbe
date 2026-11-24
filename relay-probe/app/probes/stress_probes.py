import asyncio
import time
from collections import Counter

from .base import mean, ok, percentile


def stop_reason(done):
    if len(done) >= 2 and all(r.status in (429,403) for r in done[-2:]):
        return "连续两次 429/403"
    if done and sum(not ok(r) for r in done)/len(done) > .30:
        return "当前完成窗口错误率 >30%"
    return ""


def stats(rows, duration):
    latency = [r.elapsed for r in rows]
    good = sum(ok(r) for r in rows)
    codes = Counter(str(r.status) if r.status is not None else r.error or "无状态" for r in rows)
    outputs = [r.counts.get("output") for r in rows if ok(r)]
    return {"success": good, "failed": len(rows)-good, "statuses": dict(codes),
            "latency_p50": percentile(latency,.50), "latency_p95": percentile(latency,.95),
            "latency_p99": percentile(latency,.99), "ttft_mean": mean(r.ttft for r in rows),
            "elapsed_s": duration, "req_s": len(rows)/duration if duration else None,
            "tok_s": sum(outputs)/duration if outputs and None not in outputs and duration else None,
            "cost": sum(r.cost for r in rows) if rows and all(r.cost is not None for r in rows) else None,
            "seqs": [r.seq for r in rows]}


async def ramp(c):
    stages, critical, reason = [], None, ""
    c.memo["stress"] = {"stages": stages, "critical": None, "stop": ""}
    for n in [1,5,10,20]+([50] if c.spec.allow_50 else []):
        start = time.monotonic()
        tasks = [asyncio.create_task(c.ask(f"{n} 并发 · {i+1}", f"样本 {c.salt}-{n}-{i}，只回复 OK。",
                                          track_failure=False, limit=64)) for i in range(n)]
        done = []
        try:
            for result in asyncio.as_completed(tasks):
                done.append(await result)
                reason = stop_reason(done)
                if reason:
                    critical = n
                    c.run.log(f"{n} 并发停压，{reason}", c.id)
                    break
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        stage_rows = [r for r in c.rows if r.label.startswith(f"{n} 并发 · ")]
        stages.append({"level": n, **stats(stage_rows, time.monotonic()-start)})
        if critical:
            break
    c.memo["stress"].update(critical=critical, stop=reason)


def stress_result(c):
    record = c.memo.get("stress", {})
    stages = record.get("stages", [])
    rows = [r for r in c.traffic if r.seq in {i for s in stages for i in s["seqs"]}]
    if not stages:
        return c.lack("未完成并发阶梯", rows=rows)
    crit = record.get("critical")
    return c.finding(f"已测并发档 {' → '.join(str(s['level']) for s in stages)}" +
                     (f"，临界 {crit} 并发，{record['stop']}" if crit else "，窗口未触发停压"),
                     record, rows=rows, status="异常" if crit else "通过")


async def sustained(c):
    if c.memo.get("stress",{}).get("critical"):
        return c.lack("阶梯已触发停压，持续速率未启动")
    rpm = c.spec.controls.sustained_rpm
    start = time.monotonic()
    deadline = start+60
    done, tasks, reason, sent = [], set(), "", 0
    completed_at = {}
    async def sample(n):
        row = await c.ask(f"匀速 {n}", f"只回复 OK。{c.salt}-{n}", track_failure=False, limit=64)
        completed_at[row.seq] = time.monotonic()-start
        return row
    try:
        while not reason:
            now = time.monotonic()
            if now >= deadline and not tasks:
                break
            if sent < rpm and now < deadline and now >= start+sent*60/rpm:
                sent += 1
                if len(tasks) < (50 if c.spec.allow_50 else 20):
                    tasks.add(asyncio.create_task(sample(sent)))
            wake = min(deadline, start+sent*60/rpm)
            delay = max(0,wake-time.monotonic()) if now < deadline else None
            if not tasks:
                await asyncio.sleep(delay or 0)
                continue
            completed, tasks = await asyncio.wait(tasks,timeout=delay,return_when=asyncio.FIRST_COMPLETED)
            fresh = sorted((t.result() for t in completed),key=lambda r:completed_at[r.seq])
            for row in fresh:
                done.append(row)
                reason = stop_reason(done)
                if reason:
                    break
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    elapsed = time.monotonic()-start
    rows = c.rows
    first = next((r.seq for r in rows if not ok(r)), None)
    windows = []
    for t in range(0,60,10):
        batch = [r for r in done if t <= completed_at[r.seq] < t+10]
        windows.append({"from_s":t,"to_s":t+10,"completed":len(batch),"error_rate":sum(not ok(r) for r in batch)/len(batch) if batch else None})
    return c.finding(f"{elapsed:.1f}s 内成功 {sum(ok(r) for r in rows)}/{len(rows)} 次",
                     {"target_rpm": rpm, "observed_success_rpm": sum(ok(r) for r in rows)*60/elapsed,
                      "first_error_seq": first, "first_error_at_s":completed_at.get(first), "windows":windows,
                      "scope":"已达成功速率；未触发限流时，真实上限待测。", "stop": reason, **stats(rows, elapsed)}, status="需关注" if first else "通过")
