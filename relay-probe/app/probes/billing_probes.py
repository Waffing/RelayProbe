import math

from app.core.tokenizer import padding
from .base import ok, ratio


async def ladder(c):
    table = []
    for n in (0, 1000, 2000, 4000, 8000):
        row = await c.ask(f"输入 +{n}", f"只回复 OK，样本 {c.salt}。\n" + padding(n, c.salt+"billing"))
        table.append({"padding": n, "expected": row.local_input, "reported": row.counts.get("input") if ok(row) else None, "seq": row.seq})
    base = table[0]
    for r in table:
        r["expected_delta"] = r["expected"]-base["expected"]
        r["reported_delta"] = r["reported"]-base["reported"] if None not in (r["reported"], base["reported"]) else None
        r["difference"] = r["reported_delta"]-r["expected_delta"] if r["reported_delta"] is not None else None
    if any(r["difference"] is None for r in table):
        return c.lack("阶梯样本缺少完整输入用量", {"steps": table})
    differences = [r["difference"] for r in table[1:]]
    tol = c.rules.input_tolerance
    systematic = all(x > tol for x in differences) or all(x < -tol for x in differences)
    bad = any(abs(x) > tol for x in differences)
    return c.finding(f"4 个非零阶梯，{sum(abs(x)>tol for x in differences)} 档超出输入差额容差" +
                     ("，系统性偏离，疑似伪造输入" if systematic else ""), {"steps": table, "tolerance": tol},
                     status="异常" if systematic else "需关注" if bad else "通过", hard=systematic)


async def stability(c):
    rows = [await c.ask(f"相同请求 {i+1}", "继续") for i in range(5)]
    vals = [r.counts.get("input") for r in rows if ok(r)]
    if len(vals) != 5 or None in vals:
        return c.lack("未取得五个输入计数", {"input": vals})
    ladder_result = c.run.results.get(11)
    brief = ladder_result.summary if ladder_result else "本轮未取得阶梯结果"
    return c.finding(f"5 次相同输入出现 {len(set(vals))} 种计数。固定输入的稳定性须结合变长阶梯解读。",
                     {"inputs": vals, "ladder": brief},
                     rows=rows+[r for r in c.traffic if r.probe == 11], status="需关注" if len(set(vals))>1 else "通过")


def output_audit(c):
    rows = [r for r in c.traffic if ok(r) and (r.text or r.calls)]
    table = []
    for r in rows:
        o, reason = r.counts.get("output"), r.counts.get("reasoning")
        # Text-only comparison: tool payloads are separately attributable output, not inflation.
        comparable = not r.calls and None not in (o, reason)
        table.append({"seq": r.seq, "visible": r.local_output, "reasoning": reason, "reported": o,
                      "difference": o-reason-r.local_output if comparable else None,
                      "scope": "工具参数另计" if r.calls else "可见文本与推理"})
    valid = [r for r in table if r["difference"] is not None]
    bad = [r["seq"] for r in valid if abs(r["difference"]) > c.rules.output_tolerance]
    if not valid:
        return c.lack("缺少可见文本、输出或推理字段", {"rows": table}, rows)
    return c.finding(f"{len(valid)} 条可比较输出中 {len(bad)} 条超容差", {"rows": table, "flagged": bad},
                     rows=rows, status="需关注" if bad else "通过")


async def rounding(c):
    samples = []
    for i, n in enumerate((1, 3, 9, 17, 33)):
        value = padding(n, c.salt+f"-tiny{i}")
        r = await c.ask(f"小额样本 {n}", f"原样回显【{value}】", effort="low")
        samples.append({"seq": r.seq, "visible": r.local_output, "output": r.counts.get("output"), "reasoning": r.counts.get("reasoning")})
    usable = [r for r in samples if r["output"] is not None and r["reasoning"] is not None]
    if len(usable) < 3:
        return c.lack("小额样本不足", {"rows": samples})
    values = [r["output"] for r in usable]
    unit = math.gcd(*values)
    minimum = len(set(values)) == 1 and len({r["visible"] for r in usable}) > 1
    rounded = unit > 1 and any(r["output"] != r["visible"]+r["reasoning"] for r in usable)
    return c.finding(f"{len(usable)} 个小额样本，输出计数公约数 {unit} tok" + ("，疑似取整或最低门槛" if minimum or rounded else ""),
                     {"rows": samples, "gcd": unit, "possible_floor": min(values) if minimum else None,
                      "scope": "usage 粒度，逐笔实扣仍需账单"}, status="需关注" if minimum or rounded else "通过")


async def balance_snapshot(c, label):
    for path in ("/v1/dashboard/billing/usage", "/api/user/self"):
        row, data = await c.run.aux(c.id, label, path)
        if row.error or not isinstance(data, dict):
            continue
        d = data.get("data", data)
        if not isinstance(d, dict):
            continue
        for field, kind, factor in (("balance_usd", "balance", 1), ("used_usd", "used", 1),
                                    ("total_usage", "used", 100), ("quota", "balance", c.spec.panel_units_per_usd),
                                    ("used_quota", "used", c.spec.panel_units_per_usd)):
            value = d.get(field)
            if type(value) in (int, float) and factor and value >= 0:
                snapshot = {"usd": value/factor, "kind": kind, "field": field, "factor": factor, "seq": row.seq, "path": path}
                row.snippet = str({field: value})
                return snapshot
    return None


def deduction(before, after):
    if not before or not after or any(before[k] != after[k] for k in ("kind", "field", "path", "factor")):
        return None
    value = (after["usd"]-before["usd"]) * (1 if before["kind"] == "used" else -1)
    return value if value >= 0 else None


def reconcile(c):
    start, end = c.memo.get("balance_before"), c.memo.get("balance_after")
    debit = deduction(start, end)
    ledger = c.spec.ledger
    if ledger.before is not None and ledger.after is not None:
        debit = (ledger.after-ledger.before)*(1 if ledger.kind == "used" else -1)/ledger.units_per_usd
        if debit < 0:
            debit = None
    rows = c.run.rows
    official = c.run.budget.spent if c.spec.prices and not c.run.budget.unknown_cost else None
    mult = ratio(debit, official)
    segment = c.memo.get("cache_ledger", {})
    segment_debit = deduction(segment.get("before"), segment.get("after"))
    cached_ratio = None
    cached_rows = [r for r in rows if r.seq in segment.get("seqs", [])]
    p = c.spec.prices
    if (p and p.input and segment_debit is not None and cached_rows and
            all(None not in (r.counts.get("input"), r.counts.get("cached"), r.counts.get("output")) for r in cached_rows)):
        cached = sum(r.counts["cached"] for r in cached_rows)
        other = sum((r.counts["input"]-r.counts["cached"])*p.input+r.counts["output"]*p.output for r in cached_rows)
        cached_ratio = ratio(segment_debit*1e6-other, cached*p.input)
    metrics = {"before": start, "after": end, "deduction_usd": debit, "official_usd": official, "effective_multiplier": mult,
               "cache_segment": segment, "segment_deduction": segment_debit, "cache_effective_price_ratio": cached_ratio,
               "cache_effective_discount": 1-cached_ratio if cached_ratio is not None else None,
               "scope": "窗口独占账户，假定非缓存输入与输出按已填单价扣除。外部并发消费会影响对账。"}
    note = "未配置官方单价，已跳过计算" if not p else "余额不可用或计量不完整，可补填同轮测前与测后额度"
    if mult is None:
        return c.lack(note, metrics, rows)
    return c.finding(f"该轮实扣 ${debit:.8f}，有效倍率 {mult:.4f}×", metrics, rows=rows)


HANDLERS = {11: ladder, 12: stability, 14: rounding}
