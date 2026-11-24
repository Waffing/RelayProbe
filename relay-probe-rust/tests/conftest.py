"""Black-box acceptance starts the compiled Rust executable and a Python protocol fixture."""
import os
import socket
import subprocess
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import httpx
import pytest
import uvicorn

from tests.mock_relay import app as mock

ROOT = Path(__file__).resolve().parents[1]
EXE = Path(os.environ.get("RELAY_PROBE_EXE", ROOT / "target/release/relay-probe.exe"))


@contextmanager
def mock_server():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    port = sock.getsockname()[1]
    instance = uvicorn.Server(uvicorn.Config(mock, log_level="warning", access_log=False))
    thread = threading.Thread(target=instance.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 15
        while not instance.started:
            if not thread.is_alive() or time.monotonic() > deadline:
                raise RuntimeError("Mock server failed to start")
            time.sleep(.01)
        yield f"http://127.0.0.1:{port}"
    finally:
        instance.should_exit = True
        thread.join(10)
        sock.close()


@contextmanager
def executable(data, *, private=True, password="", ca=None):
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    data.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "HOST": "127.0.0.1", "PORT": str(port),
           "ALLOW_PRIVATE_TARGETS": str(private).lower(), "ACCESS_PASSWORD": password,
           "PROBE_DATA_DIR": str(data)}
    if ca:
        env["SSL_CERT_FILE"] = str(ca)
    output = data / "process.log"
    with output.open("wb") as log:
        process = subprocess.Popen([str(EXE), "--no-open"], env=env, cwd=data,
                                   stdout=log, stderr=log,
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        try:
            with httpx.Client(base_url=f"http://127.0.0.1:{port}", trust_env=False, timeout=240) as client:
                deadline = time.monotonic() + 30
                while True:
                    if process.poll() is not None:
                        raise RuntimeError(output.read_text("utf-8", errors="replace"))
                    try:
                        if client.get("/").status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    if time.monotonic() > deadline:
                        raise RuntimeError("Rust executable failed to start")
                    time.sleep(.05)
                yield client, process, output
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(10)


@pytest.fixture(scope="session")
def relay():
    with mock_server() as url:
        yield url


@pytest.fixture(scope="session")
def services(tmp_path_factory, relay):
    with executable(tmp_path_factory.mktemp("rust-console")) as (client, _, _):
        yield client, relay
