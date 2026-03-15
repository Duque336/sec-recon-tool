from __future__ import annotations

import socket
import ssl


def grab_ssh_banner(host: str, port: int = 22, timeout_s: float = 0.7) -> str | None:
    """
    Read the SSH identification string (e.g., 'SSH-2.0-OpenSSH_8.9').
    Safe: this is a passive read of the server's greeting line.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout_s) as s:
            s.settimeout(timeout_s)
            data = s.recv(256)
        line = data.decode("utf-8", errors="replace").strip()
        return line if line else None
    except OSError:
        return None


def grab_http_server_header(host: str, port: int, timeout_s: float = 0.9) -> str | None:
    """
    Send a minimal HTTP HEAD request and extract the Server header (if present).
    For HTTPS (443), wraps the socket with TLS but does not verify certs (recon use).
    """
    req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: sec-recon-tool\r\nConnection: close\r\n\r\n"
    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout_s)
        raw_sock.settimeout(timeout_s)

        if port == 443:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock

        with sock:
            sock.sendall(req.encode("ascii", errors="ignore"))
            data = sock.recv(2048)

        text = data.decode("iso-8859-1", errors="replace")
        for line in text.splitlines():
            if line.lower().startswith("server:"):
                return line.split(":", 1)[1].strip() or None
        return None
    except OSError:
        return None
