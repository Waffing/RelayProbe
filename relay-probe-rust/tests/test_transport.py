"""TLS and proxy regression for the address-pinned transport using only local fixtures."""
import asyncio
import os
import secrets
import shutil
import ssl
import struct
import subprocess
from pathlib import Path

import pytest

import httpx
from tests.conftest import executable


@pytest.fixture(scope="module")
def tls_files(tmp_path_factory):
    exe = shutil.which("openssl")
    if not exe:
        candidate = Path(os.environ.get("ProgramFiles",""))/"Git/usr/bin/openssl.exe"
        if not candidate.is_file():
            pytest.skip("本机缺少临时测试证书生成工具 OpenSSL")
        exe = str(candidate)
    tmp = tmp_path_factory.mktemp("transport-tls")
    cert, key = tmp/"cert.pem", tmp/"fixture.key"
    subprocess.run([exe,"req","-x509","-newkey","rsa:2048","-nodes","-days","1","-subj","/CN=localhost",
                    "-addext","subjectAltName=DNS:localhost,IP:127.0.0.1","-keyout",str(key),"-out",str(cert)],
                   check=True, capture_output=True)
    return cert,key


@pytest.mark.parametrize("kind",["direct","http","https","socks5"])
def test_tls_and_pinned_tunnels(tls_files,kind,tmp_path):
    cert,key = tls_files

    async def exercise():
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert,key)
        sni, requested = [], []
        ctx.set_servername_callback(lambda sock,name,context:sni.append(name))
        async def origin(reader,writer):
            headers = await reader.readuntil(b"\r\n\r\n")
            requested.append(headers.split(b"\r\n",1)[0])
            payload = b'{"data":[{"id":"fixture"}]}'
            writer.write(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "+str(len(payload)).encode()+b"\r\n\r\n"+payload)
            await writer.drain()
            writer.close()
        origin_server=await asyncio.start_server(origin,"127.0.0.1",0,ssl=ctx)
        upstream_port=origin_server.sockets[0].getsockname()[1]
        destinations=[]
        async def fixed_tunnel(reader,writer):
            try:
                if kind=="socks5":
                    ver,n=await reader.readexactly(2)
                    assert ver==5
                    await reader.readexactly(n)
                    writer.write(b"\x05\x00");await writer.drain()
                    header=await reader.readexactly(4)
                    assert header==b"\x05\x01\x00\x01"
                    ip=".".join(str(x) for x in await reader.readexactly(4))
                    port=struct.unpack(">H",await reader.readexactly(2))[0]
                    destinations.append(f"{ip}:{port}")
                    reply=b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00"
                else:
                    preamble=await reader.readuntil(b"\r\n\r\n")
                    destinations.append(preamble.split(b" ",2)[1].decode())
                    reply=b"HTTP/1.1 200 Connection established\r\n\r\n"
                # Always bridge to the single server just created for this test.
                up,out=await asyncio.open_connection("127.0.0.1",upstream_port)
                writer.write(reply);await writer.drain()
                async def copy(rd,wr):
                    while data:=await rd.read(8192):
                        wr.write(data)
                        await wr.drain()
                tasks=[asyncio.create_task(copy(reader,out)),asyncio.create_task(copy(up,writer))]
                await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
                for t in tasks:t.cancel()
                await asyncio.gather(*tasks,return_exceptions=True)
                out.close()
            finally:
                writer.close()
        proxy=None
        if kind!="direct":
            proxy=await asyncio.start_server(fixed_tunnel,"127.0.0.1",0,ssl=ctx if kind=="https" else None)
        try:
            proxy_url=f"{kind}://127.0.0.1:{proxy.sockets[0].getsockname()[1]}" if proxy else None
            with executable(tmp_path / kind, ca=cert) as (local, _, _):
                async with httpx.AsyncClient(base_url=str(local.base_url), trust_env=False) as api:
                    response = await api.post("/api/models", json={"base_url": f"https://localhost:{upstream_port}",
                                              "api_key": secrets.token_urlsafe(24), "proxy": proxy_url})
                    assert response.status_code == 200, response.text
                    assert response.json()["models"] == ["fixture"]
                    assert "localhost" in sni
                    if kind == "https":
                        assert sni == [None, "localhost"]
                    assert requested == [b"GET /v1/models HTTP/1.1"]
                    if proxy:
                        assert destinations == [f"127.0.0.1:{upstream_port}"]
        finally:
            if proxy:
                proxy.close();await proxy.wait_closed()
            origin_server.close();await origin_server.wait_closed()
    asyncio.run(exercise())


def test_local_proxy_compat_is_opt_in(tmp_path):
    async def exercise():
        observed = []

        async def fixture_proxy(reader, writer):
            try:
                connect = await reader.readuntil(b"\r\n\r\n")
                observed.append(connect.split(b"\r\n", 1)[0])
                writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                await writer.drain()
                request = await reader.readuntil(b"\r\n\r\n")
                observed.append(request.split(b"\r\n", 1)[0])
                payload = b'{"data":[{"id":"local-proxy-fixture"}]}'
                headers = f"HTTP/1.1 200 OK\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
                writer.write(headers.encode() + payload)
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        proxy = await asyncio.start_server(fixture_proxy, "127.0.0.1", 0)
        async with proxy:
            port = proxy.sockets[0].getsockname()[1]
            with executable(tmp_path / "local-proxy", private=False) as (local, _, _):
                async with httpx.AsyncClient(base_url=str(local.base_url), trust_env=False) as api:
                    spec = {
                        "base_url": "http://1.1.1.1",
                        "api_key": secrets.token_urlsafe(24),
                        "proxy": f"http://127.0.0.1:{port}",
                    }
                    denied = await api.post("/api/models", json=spec)
                    assert denied.status_code == 400
                    assert denied.json()["code"] == "local_network_compat"
                    assert observed == []
                    allowed = await api.post("/api/models", json={**spec, "local_network_compat": True})
                    assert allowed.status_code == 200, allowed.text
                    assert allowed.json()["models"] == ["local-proxy-fixture"]
                    assert observed == [b"CONNECT 1.1.1.1:80 HTTP/1.1", b"GET /v1/models HTTP/1.1"]

    asyncio.run(exercise())
