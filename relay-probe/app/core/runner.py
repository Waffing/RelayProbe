import asyncio
import secrets
import time
import uuid
from collections import Counter
from datetime import datetime

from app.core import protocols, scoring
from app.core.budget import Budget, BudgetStop
from app.core.security import clean_headers, scrub
from app.core.tokenizer import input_count
from app.probes import registry, stress_probes
from app.probes.base import Probe, SkipProbe, ok
from app.probes.billing_probes import balance_snapshot
from app.schemas import Exchange
from app.signatures.engine import checkpoint


class Run:
    def __init__(self, spec, profile, relay):
        self.id, self.salt = uuid.uuid4().hex, secrets.token_hex(10)
        self.spec, self.profile, self.relay = spec, profile, relay
        self.ids = registry.selected(spec.mode, spec.probe_ids, spec.expensive)
        if not self.ids:
            raise ValueError("高开销探针需显式开启对应开关")
        self.estimate = registry.estimate(spec, self.ids)
        self.protocol = "chat" if spec.protocol=="chat" else "responses"
        self.started = datetime.now().astimezone().isoformat()
        self.events, self.rows, self.results, self.memo = [], [], {}, {}
        self.changed, self.budget, self.failures = asyncio.Event(), Budget(spec), Counter()
        self.finished, self.stop, self.task, self.begun = 0., "", None, False

    def emit(self, name, data):
        self.events.append((name,data))
        self.changed.set()

    def log(self, message, probe=0):
        self.emit("log", {"time": datetime.now().astimezone().isoformat(), "message":message, "probe":probe})

    async def dispatch(self, pid, label, body, headers, disguised, read, *, path=None, auxiliary=False):
        reserve = self.budget.reserve(body, auxiliary)
        seq = self.budget.sent
        start = time.monotonic()
        row = None
        try:
            row, data = await self.relay.exchange(seq, pid, label, self.protocol, body, headers, disguised, read,
                                                  path=path, auxiliary=auxiliary)
            return row, data
        except asyncio.CancelledError:
            row = Exchange(seq=seq, probe=pid, label=label, protocol=self.protocol, disguised=disguised,
                           path=path or protocols.PATHS[self.protocol], method="GET" if auxiliary else "POST",
                           headers=clean_headers(headers), body=scrub(body,self.relay.secrets), stream=bool(body.get("stream")),
                           error="已取消在途请求", elapsed=time.monotonic()-start, local_input=0 if auxiliary else input_count(body))
            raise
        finally:
            self.budget.settle(reserve, row, auxiliary)
            if row:
                self.rows.append(row)
                self.emit("sample", {"seq":seq, "probe":pid, "label":label, "status":row.status, "error":row.error,
                                     "elapsed":row.elapsed, **self.budget.snapshot()})

    async def ask(self, pid, label, prompt, *, bare=None, key=None, session="", heavy=False, track_failure=True, **opts):
        if track_failure and self.failures[pid] >= self.spec.controls.consecutive_failures:
            raise SkipProbe("连续失败达到已配上限，证据不足")
        bare = self.spec.bare if bare is None else bare
        headers = {} if bare else {k:v.replace("{session}",self.id+session) for k,v in self.profile.headers.items()}
        body = protocols.build(self.protocol, self.spec.model, self.profile, prompt, self.salt+"-"+(key or str(pid)), bare=bare, **opts)
        if key is not None:
            body["prompt_cache_key"] = self.salt+"-"+key
        row, _ = await self.dispatch(pid, label, body, headers, not bare,
                                     self.spec.controls.heavy_s if heavy else self.spec.controls.read_s)
        if track_failure:
            self.failures[pid] = 0 if ok(row) else self.failures[pid]+1
            if self.failures[pid] >= self.spec.controls.consecutive_failures and pid:
                raise SkipProbe("连续失败达到已配上限，证据不足")
        return row

    async def aux(self, pid, label, path):
        return await self.dispatch(pid, label, {}, {}, False, self.spec.controls.read_s, path=path, auxiliary=True)

    async def work(self):
        self.log("已创建任务，开始协议预检")
        if 15 in self.ids:
            self.memo["balance_before"] = await balance_snapshot(Probe(self,15), "整轮测前余额")
        pre = await self.ask(0,"协议预检","只回复 OK。",track_failure=False,limit=64)
        if self.spec.protocol=="auto" and protocols.downgrade(pre.status, pre.snippet):
            self.protocol = "chat"
            self.log(f"Responses HTTP {pre.status} 符合降级条件，切换 Chat Completions")
            pre = await self.ask(0,"Chat 降级预检","只回复 OK。",track_failure=False,limit=64)
        if not ok(pre):
            self.stop = f"协议预检停止：{pre.error or pre.finish or '未正常完成'} {pre.snippet[:220]}"
            return
        if 24 in self.ids:
            await checkpoint(Probe(self,24),"开头")
        jobs = [i for i in self.ids if i in registry.ACTIVE or i in (37,38,39)]
        middle = len(jobs)//2
        for index, i in enumerate(jobs):
            if 24 in self.ids and index==middle:
                await checkpoint(Probe(self,24),"中段")
            c = Probe(self,i)
            self.log(registry.NAMES[i], i)
            try:
                if i in (37,38,39):
                    if "stress" not in self.memo:
                        await stress_probes.ramp(c)
                else:
                    self.results[i] = await registry.ACTIVE[i](c)
            except SkipProbe as exc:
                self.results[i] = c.lack(str(exc))
            self.emit("progress", {"probe":i, "done":index+1, "total":len(jobs), **self.budget.snapshot()})
        if 24 in self.ids:
            if not jobs:
                await checkpoint(Probe(self,24),"中段")
            await checkpoint(Probe(self,24),"末尾")
        if 15 in self.ids:
            self.memo["balance_after"] = await balance_snapshot(Probe(self,15), "整轮测后余额")

    def finish(self):
        for i in self.ids:
            c = Probe(self,i)
            if i in registry.PASSIVE and not (i in self.results and self.results[i].status=="证据不足" and self.failures[i]):
                self.results[i] = registry.PASSIVE[i](c)
            if i not in self.results:
                metrics = {"steps":self.memo["context_steps"]} if i==36 and "context_steps" in self.memo else {}
                self.results[i] = c.lack(self.stop or "未取得有效样本",metrics)
        result = scoring.report(self)
        self.emit("report",result.model_dump())
        self.finished = time.monotonic()
        self.changed.set()

    async def execute(self):
        self.begun = True
        try:
            await self.work()
        except asyncio.CancelledError:
            self.stop = "手动中止，样本不完整"
        except (BudgetStop, SkipProbe) as exc:
            self.stop = str(exc)
        except Exception as exc:
            self.stop = f"运行中断（{type(exc).__name__}），样本不完整"
        finally:
            try:
                await self.relay.close()
            finally:
                self.finish()

    async def abort(self):
        if self.finished:
            return
        self.relay.forget()
        self.task.cancel()
        await asyncio.gather(self.task, return_exceptions=True)
        if not self.begun:
            self.stop = "手动中止，样本不完整"
            await self.relay.close()
            self.finish()
