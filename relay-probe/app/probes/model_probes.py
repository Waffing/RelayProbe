import base64
import json
import secrets
import struct
import zlib

from app.core.profiles import tool
from app.core.tokenizer import padding
from .base import SkipProbe, ok
from .scoring_probes import lookup_tool, valid_call


async def encrypted(c):
    if c.run.protocol != "responses":
        return c.lack("当前为 Chat Completions，该项需要 Responses")
    first = {"role": "user", "content": f"校核任务 {c.salt}。计算 37 × 19，再用一句话解释。"}
    opts = {"store": False, "include": ["reasoning.encrypted_content"]}
    a = await c.ask("首轮加密推理项", [first], effort="high", extra=opts, heavy=True)
    items = [i for i in a.output_items if i.get("type") == "reasoning" and i.get("encrypted_content")]
    if not ok(a) or not items:
        return c.finding(f"首轮返回 {len(items)} 个可回传的加密推理项", {"count": len(items)}, status="需关注")
    b = await c.ask("原样回传加密项", [first, *a.output_items, {"role": "user", "content": "根据刚才的计算只回复结果。"}],
                    effort="high", extra=opts, heavy=True)
    return c.finding(f"{len(items)} 个推理项原样回传，二轮 HTTP {b.status or '未返回'}",
                     {"items": len(items), "second_status": b.status}, status="通过" if ok(b) else "异常")


async def escaping(c):
    patch = f'函数 patch_{c.salt[:6]}():\n    # 中文注释 "保留引号"\n    if ready:\n        emit("C:\\\\日志\\\\文件\\n", \'嵌套 "字符"\')\n'
    t = tool("record_patch", "逐字符记录补丁。", {"patch": {"type": "string"}})
    r = await c.ask("流式参数拼接", "调用 record_patch，把以下文本原样传入：\n"+patch, tools=[t], forced="record_patch")
    try:
        value = json.loads(r.calls[0]["arguments"]).get("patch")
    except (IndexError, ValueError, AttributeError):
        value = None
    streamed = ("response.function_call_arguments.delta" in r.events if c.run.protocol == "responses" else bool(r.chunks))
    return c.checked({"流式参数到达": streamed, "解码后逐字一致": ok(r) and value == patch}, metrics={"expected": patch, "actual": value})


async def echo(c):
    value = f"墨/{secrets.token_hex(10)}+Ω=尾"
    r = await c.ask("随机串回声", f"原样回显【{value}】，不加任何文字。")
    return c.checked({"原样回显": ok(r) and r.text == value}, metrics={"expected": value, "actual": r.text})


async def parameters(c):
    value = "A"+c.salt[:8]
    prompt = f"原样回显【{value}】，只输出括号中的内容。"
    a = await c.ask("temperature=0 第一次", prompt, extra={"temperature": 0})
    b = await c.ask("temperature=0 第二次", prompt, extra={"temperature": 0})
    lim = await c.ask("输出上限 8 tok", "连续输出 500 次字符 X。", limit=8, effort="low")
    stop = "§"+c.salt
    s = await c.ask("stop 序列", f"原样回显【{value}{stop}after】", extra={"stop": [stop]})
    name = "lookup_value"
    f = await c.ask("强制工具", "调用 lookup_value 函数，key 取 value。", tools=[lookup_tool(name)], forced=name)
    return c.checked({"temperature=0 一致": ok(a) and ok(b) and a.text == b.text == value,
                      "输出上限": lim.status == 200 and lim.counts.get("output") is not None and lim.counts["output"] <= 8,
                      "stop 生效": ok(s) and s.text == value,
                      "forced tool": ok(f) and len(f.calls) == 1 and valid_call(f.calls[0], name)},
                     metrics={"parameter_status": {r.label: r.status for r in c.rows}})


async def truncation(c):
    rows = [await c.ask("流式" if stream else "非流式", "连续输出 128 次字符 X，只返回这一行。", stream=stream) for stream in (True, False)]
    return c.checked({r.label: ok(r) and r.text == "X"*128 for r in rows},
                     metrics={"rows": [{"seq": r.seq, "length": len(r.text), "finish_reason_or_status": r.finish} for r in rows]})


async def memory(c):
    facts = {k: secrets.token_hex(5) for k in ("river", "key", "tree")}
    history = [{"role": "user", "content": "\n".join(f"事实 {k}={v}" for k,v in facts.items())+"\n记住三项后回复 OK。"}]
    first = await c.ask("建立三项事实", history)
    history.append({"role": "assistant", "content": first.text})
    checks = {}
    for k, v in facts.items():
        history.append({"role": "user", "content": f"查询 {k}，只回复事实值。"})
        r = await c.ask("回忆 "+k, history)
        checks[k] = ok(r) and r.text.strip() == v
        history.append({"role": "assistant", "content": r.text})
    return c.checked(checks, metrics={"facts": facts})


async def benign_terms(c):
    prompts = ["说明代码审查中将 rm -rf 标作危险命令的原因。", "用一句话描述 eval 的安全审计目的。",
               "说明参数化查询如何防御 SQL 拼接风险。", "说明为何文档中用虚构占位符 sk-test-0000。"]
    try:
        for i,p in enumerate(prompts):
            await c.ask("无害审计词 "+str(i+1), p)
    except SkipProbe:
        pass
    rows = c.rows
    return c.checked({name: ok(r) for name,r in zip(("rm -rf", "eval", "SQL", "测试占位符"),rows)},
                     metrics={"statuses": [r.status for r in rows], "untested": len(prompts)-len(rows),
                              "scope": "连续失败后未发出的样本证据不足" if len(rows)<4 else "全部词项已采样"})


def color_png(rgb):
    def chunk(kind, data):
        return struct.pack(">I",len(data))+kind+data+struct.pack(">I",zlib.crc32(kind+data))
    data = b"\x89PNG\r\n\x1a\n"+chunk(b"IHDR",struct.pack(">IIBBBBB",16,16,8,2,0,0,0))
    data += chunk(b"IDAT",zlib.compress((b"\0"+rgb*16)*16))+chunk(b"IEND",b"")
    return "data:image/png;base64,"+base64.b64encode(data).decode()


async def vision(c):
    color, rgb = secrets.choice([("红", b"\xff\0\0"), ("绿", b"\0\xff\0"), ("蓝", b"\0\0\xff")])
    prompt = [{"role": "user", "content": [{"type": "input_text", "text": "这张图是什么颜色？只答红、绿、蓝中的一个字。"},
                                          {"type": "input_image", "image_url": color_png(rgb)}]}]
    r = await c.ask("随机纯色 PNG", prompt)
    return c.checked({"颜色相符": ok(r) and r.text.strip() == color}, metrics={"expected": color, "actual": r.text})


async def context(c):
    table = []
    c.memo["context_steps"] = table
    for n in (32000, 64000, 128000, 200000):
        code = secrets.token_hex(7)
        prompt = f"校验码={code}\n{padding(n, c.salt+str(n))}\n只返回校验码，不要解释。"
        r = await c.ask(f"{n//1000}K 档", prompt, heavy=True)
        table.append({"padding": n, "local_input": r.local_input, "status": r.status,
                      "recalled": ok(r) and r.text.strip() == code, "seq": r.seq})
    passed = [s["local_input"] for s in table if s["recalled"]]
    return c.finding(f"4 档中 {len(passed)} 档通过头部随机码校验", {"steps": table, "highest_verified": max(passed, default=None)},
                     status="通过" if len(passed)==4 else "需关注")


HANDLERS = {28: encrypted, 29: escaping, 30: echo, 31: parameters, 32: truncation, 33: memory, 34: benign_terms, 35: vision, 36: context}
