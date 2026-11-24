from copy import deepcopy

from .tokenizer import count

PATHS = {"responses": "/v1/responses", "chat": "/v1/chat/completions"}


def downgrade(status, snippet):
    if status in (404, 405, 501):
        return True
    if status is None or status in (401, 403, 429) or status >= 500:
        return False
    return any(s in snippet.lower() for s in ("endpoint unsupported", "not implemented", "unknown path"))


def chat_tool(t):
    if t.get("type") == "function" and "name" in t:
        return {"type": "function", "function": {k: v for k, v in t.items() if k != "type"}}
    return t


def chat_message(item):
    if item.get("type") == "function_call":
        return {"role": "assistant", "content": None, "tool_calls": [
            {"id": item["call_id"], "type": "function", "function": {"name": item["name"], "arguments": item["arguments"]}}]}
    if item.get("type") == "function_call_output":
        return {"role": "tool", "tool_call_id": item["call_id"], "content": item["output"]}
    msg = dict(item)
    if isinstance(msg.get("content"), list):
        msg["content"] = [{"type": "image_url", "image_url": {"url": p["image_url"]}} if p.get("type") == "input_image"
                          else {"type": "text", "text": p["text"]} if p.get("type") == "input_text" else p for p in msg["content"]]
    return msg


def build(protocol, model, profile, prompt, cache_key, *, bare=False, system="", stream=True,
          effort=None, limit=256, tools=None, forced=None, schema=None, extra=None):
    b = {} if bare else deepcopy(profile.body)
    seed = b.pop("input", [])
    messages = b.pop("messages", [])
    fixed = (seed if isinstance(seed, list) else []) + messages
    items = [{"role": "user", "content": prompt}] if isinstance(prompt, str) else deepcopy(prompt)
    instructions = b.pop("instructions", "")
    if system:
        instructions = "\n".join(filter(None, (instructions, system)))
    if tools is not None:
        b["tools"] = tools
    if forced:
        b["tool_choice"] = {"type": "function", "name": forced}
    b.update(model=model, stream=stream)
    if not bare:
        b["prompt_cache_key"] = cache_key
    reasoning = b.pop("reasoning", {})
    base_effort = b.pop("reasoning_effort", None)
    if effort or base_effort:
        reasoning["effort"] = effort or base_effort
    if protocol == "responses":
        if instructions:
            b["instructions"] = instructions
        b["input"] = fixed + items if fixed or not isinstance(prompt, str) else prompt
        b.pop("stream_options", None)
        b.pop("max_completion_tokens", None)
        if reasoning:
            b["reasoning"] = reasoning
        if b.get("tools"):
            b["tools"] = [{"type": "function", **t["function"]} if t.get("type") == "function" and "function" in t else t for t in b["tools"]]
        if isinstance(b.get("tool_choice"), dict) and "function" in b["tool_choice"]:
            b["tool_choice"] = {"type": "function", **b["tool_choice"]["function"]}
        if schema:
            b["text"] = {"format": {"type": "json_schema", **schema}}
        b["max_output_tokens"] = limit
    else:
        for k in ("include", "previous_response_id", "text", "max_output_tokens", "truncation"):
            b.pop(k, None)
        prefix = [{"role": "system", "content": instructions}] if instructions else []
        b["messages"] = prefix + [chat_message(i) for i in fixed + items]
        if reasoning.get("effort"):
            b["reasoning_effort"] = reasoning["effort"]
        if "tools" in b:
            b["tools"] = [chat_tool(t) for t in b["tools"] if t.get("type") == "function"]
        if isinstance(b.get("tool_choice"), dict):
            b["tool_choice"] = chat_tool(b["tool_choice"])
        if schema:
            b["response_format"] = {"type": "json_schema", "json_schema": schema}
        if stream:
            b["stream_options"] = {"include_usage": True}
        else:
            b.pop("stream_options", None)
        b["max_completion_tokens"] = limit
    b.update(extra or {})
    return b


def counts(protocol, usage):
    u = usage or {}
    ik, ok = ("input_tokens", "output_tokens") if protocol == "responses" else ("prompt_tokens", "completion_tokens")
    def number(x):
        return x if type(x) is int and x >= 0 else None
    def detail(k, field):
        d = u.get(k + "_details")
        return number(d.get(field)) if isinstance(d, dict) else None
    return {"input": number(u.get(ik)), "output": number(u.get(ok)), "cached": detail(ik, "cached_tokens"),
            "reasoning": detail(ok, "reasoning_tokens"), "total": number(u.get("total_tokens"))}


def absorb(row, obj, event, elapsed):
    """Decode only the negotiated protocol. Terminal usage and semantic deltas are separate."""
    if not isinstance(obj, dict):
        return
    delta = ""
    if row.protocol == "responses":
        typ = obj.get("type") or event
        data = obj.get("response", obj)
        if typ == "response.output_text.delta":
            delta = obj.get("delta", "")
            row.text += delta
        elif typ == "response.function_call_arguments.delta":
            delta = obj.get("delta", "")
            idx = obj.get("output_index", 0)
            call = next((c for c in row.calls if c["index"] == idx), None)
            if call is None:
                call = {"index": idx, "name": "", "call_id": "", "arguments": ""}
                row.calls.append(call)
            call["arguments"] += delta
        elif typ in ("response.output_item.added", "response.output_item.done"):
            item = obj.get("item", {})
            if typ == "response.output_item.done" and item:
                row.output_items.append(item)
            if item.get("type") == "function_call":
                idx = obj.get("output_index", 0)
                call = next((c for c in row.calls if c["index"] == idx), None)
                if call is None:
                    row.calls.append({"index": idx, "name": item.get("name"), "call_id": item.get("call_id"),
                                      "arguments": item.get("arguments", "")})
                else:
                    call.update(name=item.get("name", call["name"]), call_id=item.get("call_id", call["call_id"]))
        if typ in ("response.failed", "error"):
            row.error = "SSE 上游错误"
            row.snippet = str(data.get("error") or obj)[:1500]
        if typ in ("response.completed", "response.incomplete") or not row.stream:
            row.finish = data.get("status") or typ
            row.complete = row.finish in ("completed", "response.completed")
            row.output_items = data.get("output") or row.output_items
            if not row.text and (not row.stream or not row.chunks):
                row.text = "".join(p.get("text", "") for i in row.output_items for p in i.get("content", []) if p.get("type") == "output_text")
            if not row.calls:
                row.calls = [{"index": ix, "name": i.get("name"), "call_id": i.get("call_id"), "arguments": i.get("arguments", "")}
                             for ix, i in enumerate(row.output_items) if i.get("type") == "function_call"]
        obj = data
    else:
        for choice in obj.get("choices") or []:
            msg = choice.get("delta", {}) if row.stream else choice.get("message", {})
            piece = msg.get("content") or ""
            row.text += piece
            delta += piece
            for ix, part in enumerate(msg.get("tool_calls") or []):
                idx = part.get("index", ix)
                call = next((c for c in row.calls if c["index"] == idx), None)
                if call is None:
                    call = {"index": idx, "name": "", "call_id": "", "arguments": ""}
                    row.calls.append(call)
                call["call_id"] += part.get("id") or ""
                f = part.get("function") or {}
                call["name"] += f.get("name") or ""
                call["arguments"] += f.get("arguments") or ""
                delta += f.get("arguments") or ""
            if choice.get("finish_reason"):
                row.finish = choice["finish_reason"]
                if not row.stream:
                    row.complete = True
    if delta and row.stream:
        if row.ttft is None:
            row.ttft = elapsed
        row.chunks.append({"t": round(elapsed, 6), "tokens": count(delta), "chars": len(delta)})
    row.response_id = obj.get("id") or row.response_id
    row.model = obj.get("model") or row.model
    row.fingerprint = obj.get("system_fingerprint") or row.fingerprint
    if isinstance(obj.get("usage"), dict):
        row.usage = obj["usage"]
