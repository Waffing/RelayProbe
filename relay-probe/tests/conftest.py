import socket
import threading
import time
from contextlib import contextmanager

import httpx
import pytest
import uvicorn

from app import config
from app.main import app as console
from tests.mock_relay import app as mock


@contextmanager
def server(application):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    port = sock.getsockname()[1]
    instance = uvicorn.Server(uvicorn.Config(application, log_level="warning", access_log=False, proxy_headers=False))
    thread = threading.Thread(target=instance.run, kwargs={"sockets":[sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic()+15
        while not instance.started:
            if not thread.is_alive() or time.monotonic()>deadline:
                raise RuntimeError("测试服务未能启动")
            time.sleep(.01)
        yield f"http://127.0.0.1:{port}"
    finally:
        instance.should_exit = True
        thread.join(10)
        sock.close()


@pytest.fixture(scope="session")
def services(tmp_path_factory):
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(config,"DATA",tmp_path_factory.mktemp("profile-store"))
        patch.setattr(config,"ALLOW_PRIVATE",True)
        patch.setattr(config,"ACCESS_PASSWORD","")
        with server(mock) as relay, server(console) as local:
            with httpx.Client(base_url=local, trust_env=False, timeout=240) as client:
                yield client, relay
