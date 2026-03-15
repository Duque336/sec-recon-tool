from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json


@dataclass(frozen=True)
class HostDelta:
    host: str
    opened: tuple[int, ...]
    closed: tuple[int, ...]


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _open_ports_by_host(report: dict) -> dict[str, set[int]]:
    m: dict[str, set[int]] = {}
    for hostrec in report.get("results", []):
        host = hostrec.get("host", "")
        opens = {int(p["port"]) for p in hostrec.get("ports", []) if p.get("open")}
        m[host] = opens
    return m


def diff_reports(prev_json: Path, curr_json: Path) -> tuple[list[str], list[str], list[HostDelta]]:
    prev = _load(prev_json)
    curr = _load(curr_json)

    prev_map = _open_ports_by_host(prev)
    curr_map = _open_ports_by_host(curr)

    prev_hosts = set(prev_map.keys())
    curr_hosts = set(curr_map.keys())

    new_hosts = sorted(curr_hosts - prev_hosts)
    missing_hosts = sorted(prev_hosts - curr_hosts)

    deltas: list[HostDelta] = []
    for host in sorted(curr_hosts & prev_hosts):
        opened = sorted(curr_map[host] - prev_map[host])
        closed = sorted(prev_map[host] - curr_map[host])
        if opened or closed:
            deltas.append(HostDelta(host=host, opened=tuple(opened), closed=tuple(closed)))

    return new_hosts, missing_hosts, deltas
