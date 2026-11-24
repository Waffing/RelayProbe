import asyncio
import hmac
import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit, urlunsplit

import httpx

from app import config

AUTH_FIELD = re.compile(r"authorization|api[-_]?key|cookie|password|credential|secret|access[-_]?token|refresh[-_]?token|bearer|auth[-_]?token|signature", re.I)
KEY_PATTERN = re.compile(r"(?i)\b(?:sk|rk|sess)-[a-z0-9_-]{6,}")
BEARER = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")
QUERY_AUTH = re.compile(r"(?i)([?&](?:key|api[_-]?key|token|auth|signature)=)[^&\s\"']+")
MASK = "[已脱敏]"
FAKE_IP_RANGE = ipaddress.ip_network("198.18.0.0/15")
DROP_HEADERS = {"host", "origin", "referer", "connection", "content-length", "transfer-encoding",
                "accept-encoding", "forwarded", "via", "x-real-ip", "proxy-connection", "upgrade", "te", "trailer"}


def scrub(value, secrets=()):
    if isinstance(value, dict):
        return {scrub(str(k), secrets): scrub(v, secrets) for k, v in value.items() if not AUTH_FIELD.search(str(k))}
    if isinstance(value, (list, tuple)):
        return [scrub(v, secrets) for v in value]
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, MASK)
        return QUERY_AUTH.sub(r"\1[已脱敏]", BEARER.sub(MASK, KEY_PATTERN.sub(MASK, value)))
    return value


def auth_values(headers):
    values = []
    for k, v in headers.items():
        if AUTH_FIELD.search(k) and isinstance(v,str):
            values.extend([v, v.split(" ", 1)[-1]])
        elif isinstance(v,dict):
            values.extend(auth_values(v))
        elif isinstance(v,list):
            for child in v:
                if isinstance(child,dict):
                    values.extend(auth_values(child))
    return tuple(v for v in values if v)


def clean_headers(headers, secrets=()):
    return {k.lower(): scrub(v, secrets) for k, v in headers.items()
            if not AUTH_FIELD.search(k) and k.lower() not in DROP_HEADERS
            and not k.lower().startswith(("sec-", "proxy-", "x-forwarded-"))
            and re.fullmatch(r"[A-Za-z0-9_-]+", k) and v.isascii() and "\r" not in v and "\n" not in v}


def authenticated(value: str, password: str) -> bool:
    return bool(password and hmac.compare_digest(value.encode(), password.encode()))


class TargetError(ValueError):
    def __init__(self, message: str, code: str | None = None):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Address:
    url: httpx.URL
    ip: str


def allowed(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if config.ALLOW_PRIVATE:
        return True
    if isinstance(addr, ipaddress.IPv6Address):
        addr = addr.ipv4_mapped or addr
        # Transition and scoped addresses can embed a non-public IPv4 destination.
        if isinstance(addr, ipaddress.IPv6Address) and (addr.sixtofour or addr.teredo or "%" in ip
                or addr in ipaddress.ip_network("64:ff9b::/96") or addr in ipaddress.ip_network("64:ff9b:1::/48")):
            return False
    return addr.is_global and not addr.is_multicast


def check_addresses(url: httpx.URL, ips: list[str], *, proxy=False, local=False, compatibility=False):
    if not ips:
        raise TargetError("DNS 未返回可连接地址")
    if all(allowed(ip) for ip in ips):
        return
    if local:
        if proxy:
            host = url.host
            try:
                loopback_host = ipaddress.ip_address(host).is_loopback
            except ValueError:
                loopback_host = host.lower() == "localhost"
            compatible = loopback_host and all(ipaddress.ip_address(ip).is_loopback for ip in ips)
            guidance = "SSRF 已拦截本机代理。启用本机代理与 Fake-IP 兼容后重试。"
        else:
            host = url.host.rstrip(".")
            try:
                ipaddress.ip_address(host)
                named_host = False
            except ValueError:
                named_host = "." in host
            compatible = (url.scheme == "https" and named_host
                          and all(allowed(ip) or is_fake_ip(ip) for ip in ips))
            guidance = "SSRF 检测到目标域名使用 Fake-IP。启用本机代理与 Fake-IP 兼容后重试。"
        if compatible:
            if compatibility:
                return
            raise TargetError(guidance, "local_network_compat")
    raise TargetError("SSRF 已拦截非公网代理。请使用公网代理或受信本机代理。" if proxy else
                      "SSRF 已拦截非公网目标。请检查 Base URL 和 DNS 解析。")


def is_fake_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address):
        addr = addr.ipv4_mapped
    return isinstance(addr, ipaddress.IPv4Address) and addr in FAKE_IP_RANGE


async def address(raw: str, *, proxy=False, timeout=15, local=False, compatibility=False) -> Address:
    try:
        parts = urlsplit(raw.strip())
        schemes = {"http", "https", "socks5"} if proxy else {"http", "https"}
        if (parts.scheme not in schemes or not parts.hostname or parts.query or parts.fragment
                or (not proxy and parts.username is not None) or (proxy and parts.path not in ("", "/"))
                or "\\" in raw or "%" in parts.hostname or any(ord(c) < 32 for c in raw)):
            raise ValueError()
        path = parts.path.rstrip("/")
        if not proxy:
            path = path.removesuffix("/v1")
            if any(p in (".", "..") for p in unquote(path).split("/")):
                raise ValueError()
        url = httpx.URL(urlunsplit((parts.scheme, parts.netloc, path, "", "")))
        port = url.port or {"https": 443, "http": 80, "socks5": 1080}[parts.scheme]
    except (ValueError, httpx.InvalidURL):
        raise TargetError("URL 无效，请检查协议、域名与端口，移除查询参数。") from None
    try:
        infos = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(
            url.raw_host.decode(), port, type=socket.SOCK_STREAM), timeout)
    except (OSError, TimeoutError) as exc:
        raise TargetError(f"{'代理 ' if proxy else ''}DNS 解析失败或超时（{type(exc).__name__}）") from None
    ips = list(dict.fromkeys(info[4][0] for info in infos))
    check_addresses(url, ips, proxy=proxy, local=local, compatibility=compatibility)
    return Address(url, ips[0])
