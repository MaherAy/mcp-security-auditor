"""Lance une application ASGI sur un vrai port HTTP, dans un thread, le temps d'un test."""

import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

import httpx
import uvicorn


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextmanager
def serve(app, port: int) -> Iterator[str]:
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:  # attend que la carte soit servie
        try:
            if httpx.get(f"{base_url}/.well-known/agent-card.json").status_code == 200:
                break
        except httpx.TransportError:
            pass
        time.sleep(0.2)
    else:
        raise RuntimeError("A2A server did not start")
    try:
        yield base_url
    finally:
        server.should_exit = True
        thread.join(timeout=10)
