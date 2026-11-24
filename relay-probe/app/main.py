import asyncio
import ipaddress
import json
import logging
import secrets
import time
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import SecretStr, ValidationError

from app import config
from app.core import profiles
from app.core.client import Relay
from app.core.security import TargetError, auth_values, authenticated, scrub
from app.schemas import Profile, RunRequest, Target

runs = {}
capture = {"token": "", "until": 0.}
CAPTURE = ("/api/capture/v1/responses", "/api/capture/v1/chat/completions")
for logger_name in ("uvicorn.access", "httpx", "httpcore"):
    logging.getLogger(logger_name).setLevel(logging.WARNING)


@asynccontextmanager
async def lifespan(app):
    async def expire():
        while True:
            await asyncio.sleep(30)
            for rid, run in list(runs.items()):
                if run.finished and time.monotonic() - run.finished > config.HISTORY_TTL:
                    runs.pop(rid, None)
    timer = asyncio.create_task(expire())
    try:
        yield
    finally:
        timer.cancel()
        await asyncio.gather(timer, *(r.abort() for r in list(runs.values()) if not r.finished), return_exceptions=True)
        runs.clear()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


def loopback_host(request: Request) -> bool:
    try:
        return urlsplit(f"//{request.headers.get('host', '')}").hostname in {"localhost", "127.0.0.1", "::1"}
    except ValueError:
        return False


def local_network_available(request: Request) -> bool:
    if config.HOST.lower() not in {"localhost", "127.0.0.1", "::1"} or not loopback_host(request):
        return False
    try:
        return bool(request.client and ipaddress.ip_address(request.client.host).is_loopback)
    except ValueError:
        return False


@app.middleware("http")
async def protect(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/"):
        origin = request.headers.get("origin")
        if origin and urlsplit(origin).netloc != request.headers.get("host"):
            return JSONResponse({"detail": "需要同源控制台请求"}, 403)
        if request.url.query:
            return JSONResponse({"detail": "API 参数仅接受请求体或请求头"}, 400)
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        bearer = token if scheme.lower()=="bearer" else ""
        capture_auth = path in CAPTURE and time.monotonic() < capture["until"] and authenticated(bearer, capture["token"])
        if config.ACCESS_PASSWORD and not (authenticated(bearer, config.ACCESS_PASSWORD) or capture_auth):
            return JSONResponse({"detail": "请输入控制台访问口令"}, 401)
        if request.method == "POST" and path not in CAPTURE and request.headers.get("content-type", "").split(";")[0] != "application/json":
            return JSONResponse({"detail": "需要 application/json"}, 415)
        if path in CAPTURE and not (capture_auth or authenticated(bearer, config.ACCESS_PASSWORD)):
            return JSONResponse({"detail": "请使用控制台生成的一次抓包口令"}, 401)
    response = await call_next(request)
    response.headers["referrer-policy"] = "no-referrer"
    response.headers["x-content-type-options"] = "nosniff"
    response.headers["content-security-policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    if path.startswith("/api/") and not path.endswith("/stream"):
        response.headers["cache-control"] = "no-store"
    return response


@app.exception_handler(RequestValidationError)
async def invalid(request, exc):
    keys = set(RunRequest.model_fields) | set(config.Controls.model_fields) | set(config.Rules.model_fields)
    fields = sorted({str(k) for e in exc.errors() for k in e["loc"] if k in keys})
    return JSONResponse({"detail": "输入字段格式无效", "fields": fields}, 422)


@app.exception_handler(TargetError)
async def unsafe(request, exc):
    return JSONResponse({"detail": str(exc), "code": exc.code}, 400)


@app.get("/api/config")
async def configuration(request: Request):
    from app.probes.registry import catalog, selected
    return {"controls": config.Controls().model_dump(), "probes": catalog(),
            "modes": {m: selected(m, None, []) for m in ("quick", "full", "stress")},
            "allow_private": config.ALLOW_PRIVATE, "local_network_compat": local_network_available(request)}


@app.post("/api/models")
async def models(target: Target, request: Request):
    relay = await Relay.open(target, local=local_network_available(request))
    try:
        row, data = await relay.exchange(1, 0, "模型列表", "models", {}, {}, False, 60, path="/v1/models", auxiliary=True)
        if row.error:
            return JSONResponse({"detail": row.error, "snippet": row.snippet, "status": row.status}, 502)
        if not isinstance(data, dict) or not isinstance(data.get("data"), list):
            raise HTTPException(502, "模型列表缺少 data 数组")
        return {"models": [x["id"] for x in data["data"] if isinstance(x, dict) and isinstance(x.get("id"), str)]}
    finally:
        await relay.close()


@app.get("/api/profiles")
async def list_profiles():
    return profiles.all_profiles()


@app.post("/api/profiles")
async def add_profile(request: Request):
    try:
        data = await request.json()
        p = profiles.parse_import(data["raw"], data.get("name", "导入 Profile")) if "raw" in data else Profile.model_validate(data)
        return profiles.save(p, auth_values(request.headers))
    except (ValueError, TypeError, KeyError, AttributeError, ValidationError):
        raise HTTPException(422, "Profile JSON 或 cURL 格式无效") from None


@app.delete("/api/profiles/{pid}")
async def delete_profile(pid: str):
    custom = profiles.all_profiles()[1:]
    if not any(p.id == pid for p in custom):
        raise HTTPException(404, "找不到可删除的自定义 Profile")
    profiles.write_custom([p for p in custom if p.id != pid])
    return {"ok": True}


@app.post("/api/capture/arm")
async def arm():
    capture.update(token=secrets.token_urlsafe(32), until=time.monotonic()+300)
    return {"token": capture["token"], "expires_in": 300}


@app.post(CAPTURE[0])
@app.post(CAPTURE[1])
async def capture_once(request: Request):
    if not request.client or not ipaddress.ip_address(request.client.host).is_loopback:
        raise HTTPException(403, "抓包端点仅接受回环连接")
    if time.monotonic() >= capture["until"]:
        raise HTTPException(409, "请先在控制台开启一次抓包")
    capture.update(token="", until=0.)
    try:
        protocol = "responses" if request.url.path.endswith("responses") else "chat"
        body = await request.json()
        p = profiles.parse_import({"headers": dict(request.headers), "body": body}, "本机 Codex 抓包", protocol)
        p.source = "实机抓包复刻"
        p = profiles.save(p, auth_values(request.headers))
    except (ValueError, TypeError, KeyError, AttributeError):
        raise HTTPException(422, "未识别捕获请求的 JSON 骨架") from None
    message = "已保存脱敏 Profile，可以返回控制台。"
    info = {"message": message, "profile_id": p.id, "baseline_tokens": p.baseline_tokens}
    if not body.get("stream"):
        return info
    rid = "capture_"+secrets.token_hex(8)
    model = "local-capture"
    async def confirmation():
        if protocol == "responses":
            item = {"type":"message", "id":"msg_"+rid, "role":"assistant", "status":"completed",
                    "content":[{"type":"output_text","text":message,"annotations":[]}]}
            response = {"id":rid,"object":"response","model":model,"status":"completed","output":[item]}
            for typ, fields in (("response.created",{"response":{**response,"output":[],"status":"in_progress"}}),
                                ("response.output_item.added",{"output_index":0,"item":{**item,"status":"in_progress","content":[]}}),
                                ("response.output_text.delta",{"output_index":0,"content_index":0,"item_id":item["id"],"delta":message}),
                                ("response.output_item.done",{"output_index":0,"item":item}),
                                ("response.completed",{"response":response})):
                yield f"event: {typ}\ndata: {json.dumps({'type':typ,**fields},ensure_ascii=False)}\n\n"
        else:
            for delta, finish in (({"role":"assistant","content":message},None),({},"stop")):
                obj = {"id":rid,"object":"chat.completion.chunk","model":model,
                       "choices":[{"index":0,"delta":delta,"finish_reason":finish}]}
                yield f"data: {json.dumps(obj,ensure_ascii=False)}\n\n"
            yield "data: [DONE]\n\n"
    return StreamingResponse(confirmation(),media_type="text/event-stream",headers={"x-captured-profile-id":p.id})


@app.post("/api/runs")
async def create_run(spec: RunRequest, request: Request):
    from app.core.runner import Run
    from app.probes.registry import selected
    if not selected(spec.mode,spec.probe_ids,spec.expensive):
        raise HTTPException(422,"高开销探针需显式开启对应开关")
    try:
        profile = profiles.get_profile(spec.profile_id)
    except ValueError:
        raise HTTPException(422, "所选 Profile 不存在") from None
    relay = await Relay.open(spec, spec.controls.connect_s, local=local_network_available(request))
    try:
        safe_spec = spec.model_copy(update={"api_key":SecretStr(""),"proxy":None,"base_url":scrub(relay.base,relay.secrets),
                                           "name":scrub(spec.name,relay.secrets), "model":scrub(spec.model,relay.secrets)})
        run = Run(safe_spec, profile, relay)
        runs[run.id] = run
        run.task = asyncio.create_task(run.execute())
        return {"run_id": run.id, "estimate": run.estimate, "selected": run.ids}
    except BaseException:
        await relay.close()
        raise


def lookup(rid):
    if rid not in runs:
        raise HTTPException(404, "运行不存在或已过保留时间")
    return runs[rid]


@app.get("/api/runs/{rid}/stream")
async def stream(rid: str, request: Request):
    run = lookup(rid)
    try:
        cursor = max(0, int(request.headers.get("last-event-id", "0")))
    except ValueError:
        raise HTTPException(400, "事件序号无效") from None
    async def events():
        nonlocal cursor
        while True:
            while cursor < len(run.events):
                typ, payload = run.events[cursor]
                cursor += 1
                yield f"id: {cursor}\nevent: {typ}\ndata: {json.dumps(payload, ensure_ascii=False, separators=(',', ':'))}\n\n"
            if run.finished:
                return
            run.changed.clear()
            try:
                await asyncio.wait_for(run.changed.wait(), 12)
            except TimeoutError:
                yield ": keep-alive\n\n"
    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"})


@app.post("/api/runs/{rid}/abort")
async def abort(rid: str):
    await lookup(rid).abort()
    return {"ok": True}


app.mount("/", StaticFiles(directory=str(config.ROOT / "static"), html=True, check_dir=False), name="console")

if __name__ == "__main__":
    uvicorn.run("app.main:app", host=config.HOST, port=config.PORT, access_log=False, proxy_headers=False)
