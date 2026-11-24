import json
import time
from http.cookiejar import DefaultCookiePolicy
from urllib.parse import unquote

import httpcore
import httpx

from app.schemas import Exchange
from . import protocols
from .security import address, clean_headers, scrub
from .tokenizer import count, input_count


class NoRelayCookies(DefaultCookiePolicy):
    def set_ok(self, cookie, request):
        return False


class PinnedStream(httpcore.AsyncNetworkStream):
    def __init__(self, inner, names, proxy_tls_name=None):
        self.inner, self.names, self.proxy_tls_name = inner, names, proxy_tls_name

    async def read(self, max_bytes, timeout=None):
        return await self.inner.read(max_bytes, timeout)

    async def write(self, buffer, timeout=None):
        await self.inner.write(buffer, timeout)

    async def aclose(self):
        await self.inner.aclose()

    async def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        hostname = self.proxy_tls_name or self.names.get(server_hostname, server_hostname)
        stream = await self.inner.start_tls(ssl_context, hostname, timeout)
        return PinnedStream(stream, self.names)

    def get_extra_info(self, info):
        return self.inner.get_extra_info(info)


class PinnedBackend(httpcore.AnyIOBackend):
    def __init__(self, names, ips, proxy_tls_name=None):
        self.names, self.ips, self.proxy_tls_name = names, ips, proxy_tls_name

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        stream = await super().connect_tcp(self.ips.get(host, host), port, timeout, local_address, socket_options)
        return PinnedStream(stream, self.names, self.proxy_tls_name)


class Relay:
    @classmethod
    async def open(cls, target, connect=15, *, local=False):
        options = {"timeout": connect, "local": local, "compatibility": target.local_network_compat}
        dest = await address(target.base_url, **options)
        proxy_text = target.proxy.get_secret_value() if target.proxy else ""
        proxy = await address(proxy_text, proxy=True, **options) if proxy_text else None
        self = cls()
        self.key = target.api_key.get_secret_value()
        self.secrets = [self.key]
        if proxy:
            self.secrets.extend([proxy_text, unquote(proxy.url.password)])
        self.base = str(dest.url).rstrip("/")
        self.wire = dest.url.copy_with(host=dest.ip)
        self.host = dest.url.netloc.decode()
        self.connect = connect
        self.proxied = bool(proxy)
        transport = httpx.AsyncHTTPTransport(proxy=proxy.url if proxy else None, retries=0,
                                             limits=httpx.Limits(max_connections=55, max_keepalive_connections=50))
        # httpcore's HTTP CONNECT and SOCKS paths need the original TLS name after opening an IP tunnel.
        transport._pool._network_backend = PinnedBackend({dest.ip: dest.url.raw_host.decode()},
                                                         {proxy.url.raw_host.decode(): proxy.ip} if proxy else {},
                                                         proxy.url.raw_host.decode() if proxy and proxy.url.scheme=="https" else None)
        self.http = httpx.AsyncClient(transport=transport, follow_redirects=False, trust_env=False)
        self.http.headers.clear()
        self.http.cookies.jar.set_policy(NoRelayCookies())
        return self

    def forget(self):
        self.key = ""
        self.secrets.clear()

    async def close(self):
        self.forget()
        try:
            await self.http.aclose()
        finally:
            self.http = None

    async def exchange(self, seq, probe, label, protocol, body, headers, disguised, read,
                       *, path=None, auxiliary=False):
        path = path or protocols.PATHS[protocol]
        h = {**clean_headers(headers), "host": self.host, "authorization": "Bearer " + self.key}
        if not auxiliary:
            h["content-type"] = "application/json"
        method = "GET" if auxiliary else "POST"
        row = Exchange(seq=seq, probe=probe, label=label, protocol=protocol, disguised=disguised,
                       path=path, method=method, body=body, headers=scrub(h, self.secrets),
                       stream=bool(body.get("stream")), local_input=0 if auxiliary else input_count(body))
        start = time.perf_counter()
        marks = {}
        async def trace(name, info):
            phase, state = name.rsplit(".", 1)
            if state == "started":
                marks[phase] = time.perf_counter()
            elif phase in marks:
                row.phases[phase] = round(time.perf_counter() - marks[phase], 6)

        data = None
        url = self.wire.copy_with(path=self.wire.path.rstrip("/") + path)
        try:
            async with self.http.stream(method, url, headers=h, json=None if auxiliary else body,
                                        timeout=httpx.Timeout(read, connect=self.connect, pool=self.connect),
                                        extensions={"trace": trace}) as res:
                row.headers = scrub(dict(res.request.headers), self.secrets)
                row.status = res.status_code
                row.response_headers = scrub(dict(res.headers), self.secrets)
                if res.status_code >= 300:
                    snippet = bytearray()
                    async for part in res.aiter_bytes():
                        snippet.extend(part[:4096 - len(snippet)])
                        if len(snippet) >= 4096:
                            break
                    row.error = f"HTTP {res.status_code}"
                    row.snippet = snippet.decode("utf-8", "replace")
                elif row.stream and "text/event-stream" in res.headers.get("content-type", "").lower():
                    event, pieces, size = "", [], 0
                    def flush():
                        if not pieces:
                            return
                        raw = "\n".join(pieces)
                        if raw == "[DONE]":
                            row.events.append("[DONE]")
                            if protocol == "chat":
                                row.complete = bool(row.finish)
                            return
                        obj = json.loads(raw)
                        row.events.append(event or obj.get("type") or "message")
                        protocols.absorb(row, obj, event, time.perf_counter() - start)
                    async for line in res.aiter_lines():
                        size += len(line)
                        if size > 12_000_000:
                            raise ValueError("响应超出采样上限")
                        if not line:
                            flush()
                            event, pieces = "", []
                        elif line.startswith("event:"):
                            event = line[6:].strip()
                        elif line.startswith("data:"):
                            pieces.append(line[5:].lstrip(" "))
                    flush()
                    if not row.complete and not row.error:
                        row.error = "流未收到正常终止事件"
                else:
                    buf = bytearray()
                    async for part in res.aiter_bytes():
                        buf.extend(part)
                        if len(buf) > 12_000_000:
                            raise ValueError("响应超出采样上限")
                    data = json.loads(buf)
                    if isinstance(data, dict) and data.get("error"):
                        row.error = "上游返回错误对象"
                        row.snippet = json.dumps(data["error"],ensure_ascii=False)[:1500]
                    elif auxiliary:
                        row.complete = isinstance(data, dict)
                    else:
                        if row.stream:
                            row.error = "请求 SSE，实际返回非流式响应"
                        protocols.absorb(row, data, "", time.perf_counter() - start)
        except (httpx.HTTPError, ValueError, OSError, TypeError, KeyError, AttributeError) as exc:
            category = {httpx.ConnectTimeout: "连接超时", httpx.ReadTimeout: "读超时", httpx.PoolTimeout: "连接池超时",
                        httpx.ProxyError: "代理失败", httpx.RemoteProtocolError: "上游协议中断"}.get(type(exc))
            if isinstance(exc, httpx.ConnectError):
                category = "TLS 证书或握手错误" if any(x in str(exc).lower() for x in ("ssl", "certificate", "tls")) else ("代理连接失败" if self.proxied else "连接失败")
            row.error = f"{category or '响应解析或传输失败'}（{type(exc).__name__}）"
            row.snippet = str(exc)[:1000]
        finally:
            self.http.cookies.clear()
        row.elapsed = round(time.perf_counter() - start, 6)
        row.counts = protocols.counts(protocol, row.usage)
        row.local_output = count(row.text)
        if row.counts["input"] is not None:
            row.input_delta = row.counts["input"] - row.local_input
        # Sanitize before this sample is visible to SSE, scoring or any persistent storage.
        safe = {field:scrub(value,self.secrets) for field,value in row.model_dump().items()}
        safe["counts"] = row.counts  # Fixed metric names and integers only.
        row = Exchange.model_validate(safe)
        return row, scrub(data, self.secrets) if auxiliary else None
