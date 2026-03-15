from __future__ import annotations

import socket
from dataclasses import dataclass
from time import time


@dataclass(frozen=True)
class PortResult:
    port: int
    open: bool
    error: str | None
    rtt_ms: float | None


def tcp_check(host: str, port: int, timeout_s: float = 0.5) -> PortResult:
    """
    Safe TCP connect check.
    - open=True means TCP connect succeeded.
    - open=False with error may mean closed, filtered, or unreachable.
    """
    start = time()
    err: str | None = None
    ok = False

    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            ok = True
    except OSError as e:
        err = e.strerror or e.__class__.__name__

    rtt = (time() - start) * 1000.0
    return PortResult(port=port, open=ok, error=None if ok else err, rtt_ms=rtt)
