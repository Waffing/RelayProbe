import asyncio
import math
import random
import statistics

from app.schemas import Finding


class SkipProbe(Exception):
    pass


def mean(values):
    items = [v for v in values if v is not None]
    return statistics.mean(items) if items else None


def percentile(values, p):
    seq = sorted(x for x in values if x is not None)
    if not seq:
        return None
    at = (len(seq)-1)*p
    return seq[math.floor(at)] + (seq[math.ceil(at)]-seq[math.floor(at)])*(at % 1)


def ratio(a, b):
    return a / b if a is not None and b else None


def cache_rate(row):
    return ratio(row.counts.get("cached"), row.counts.get("input"))


def ok(row):
    return row.status == 200 and not row.error and row.complete


def question(salt, i):
    rng = random.Random(f"{salt}/math/{i}")
    a, b, k = rng.randint(50, 499), rng.randint(5, 41), rng.randint(3, 19)
    expr, result = [(f"({a} + {b}) * {k}", (a+b)*k), (f"({a} - {b}) * {k}", (a-b)*k),
                    (f"({a} * {b}) % {k}", (a*b)%k), (f"({a} * {b}) // {k}", (a*b)//k)][i % 4]
    return f"计算表达式 {expr} 的整数结果。只返回整数。", str(result)


async def together(*coroutines):
    tasks = [asyncio.create_task(c) for c in coroutines]
    try:
        return await asyncio.gather(*tasks)
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


class Probe:
    def __init__(self, run, pid):
        self.run, self.id = run, pid
        self.spec, self.rules, self.salt, self.memo = run.spec, run.spec.controls.rules, run.salt, run.memo

    @property
    def rows(self):
        return [r for r in self.run.rows if r.probe == self.id]

    @property
    def traffic(self):
        return [r for r in self.run.rows if r.method == "POST"]

    async def ask(self, label, prompt, **opts):
        return await self.run.ask(self.id, label, prompt, **opts)

    def finding(self, summary, metrics=None, *, rows=None, status="通过", strength=None, score=None, hard=False):
        from .registry import NAMES
        ids = sorted({r.seq for r in (self.rows if rows is None else rows)})
        return Finding(id=self.id, name=NAMES[self.id], summary=summary, metrics=metrics or {}, status=status,
                       strength=strength or ("实测检出" if status == "异常" else "疑似" if status == "需关注" else "未检出"),
                       score=score, samples=len(ids), evidence=ids, hard=hard)

    def lack(self, summary, metrics=None, rows=None):
        return self.finding(summary, metrics, rows=rows, status="证据不足")

    def checked(self, checks, *, metrics=None, quantified=False):
        hits = sum(checks.values())
        total = len(checks)
        return self.finding(f"{hits}/{total} 项校验通过", {"checks": checks, **(metrics or {})},
                            status="通过" if hits == total else "异常", score=hits/total if quantified else None)
