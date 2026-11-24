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

from app import config
from app.core.client import Relay
from app.core.security import TargetError, check_addresses
from app.schemas import Target


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
def test_tls_and_pinned_tunnels(tls_files,kind,monkeypatch):
    cert,key = tls_files
    monkeypatch.setattr(config,"ALLOW_PRIVATE",True)
    monkeypatch.setenv("SSL_CERT_FILE",str(cert))

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
        # The localhost address validated by getaddrinfo may be IPv6. Pin this fixture to v4.
        original_resolve=asyncio.get_running_loop().getaddrinfo
        async def resolve_fixture(host,port,*args,**kwargs):
            return await original_resolve("127.0.0.1" if host=="localhost" else host,port,*args,**kwargs)
        monkeypatch.setattr(asyncio.get_running_loop(),"getaddrinfo",resolve_fixture)
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
            dest=Target(base_url=f"https://localhost:{upstream_port}",api_key=secrets.token_urlsafe(24),proxy=proxy_url)
            client=await Relay.open(dest,3)
            try:
                row,data=await client.exchange(1,0,"models","models",{}, {},False,5,path="/v1/models",auxiliary=True)
                assert row.status==200 and data["data"][0]["id"]=="fixture",(row.error,row.snippet)
                assert "localhost" in sni
                if kind=="https":
                    assert sni==[None,"localhost"]
                assert requested==[b"GET /v1/models HTTP/1.1"]
                if proxy:
                    assert destinations==[f"127.0.0.1:{upstream_port}"]
            finally:
                await client.close()
        finally:
            if proxy:
                proxy.close();await proxy.wait_closed()
            origin_server.close();await origin_server.wait_closed()
    asyncio.run(exercise())


def test_local_compatibility_only_admits_scoped_addresses(monkeypatch):
    monkeypatch.setattr(config, "ALLOW_PRIVATE", False)
    https = httpx.URL("https://relay.example.com")
    fake = "198.18.1.42"
    with pytest.raises(TargetError) as blocked:
        check_addresses(https, [fake], local=True)
    assert blocked.value.code == "local_network_compat"
    check_addresses(https, [fake, "8.8.8.8"], local=True, compatibility=True)
    for url, ips in (
        ("http://relay.example.com", [fake]),
        ("https://198.18.1.42", [fake]),
        (str(https), [fake, "127.0.0.1"]),
        (str(https), [fake, "169.254.169.254"]),
        (str(https), ["10.0.0.1"]),
        ("https://127.0.0.1", ["127.0.0.1"]),
    ):
        with pytest.raises(TargetError) as blocked:
            check_addresses(httpx.URL(url), ips, local=True, compatibility=True)
        assert blocked.value.code is None
    with pytest.raises(TargetError):
        check_addresses(https, [fake], compatibility=True)
    local_proxy = httpx.URL("http://localhost")
    with pytest.raises(TargetError) as blocked:
        check_addresses(local_proxy, ["127.0.0.1"], proxy=True, local=True)
    assert blocked.value.code == "local_network_compat"
    check_addresses(local_proxy, ["127.0.0.1", "::1"], proxy=True, local=True, compatibility=True)
    with pytest.raises(TargetError):
        check_addresses(local_proxy, ["127.0.0.1", "10.0.0.1"], proxy=True, local=True, compatibility=True)
    with pytest.raises(TargetError):
        check_addresses(httpx.URL("http://proxy.example.com"), ["127.0.0.1"], proxy=True,
                        local=True, compatibility=True)
