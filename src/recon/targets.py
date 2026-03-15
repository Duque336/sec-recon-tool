from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from pathlib import Path


@dataclass(frozen=True)
class TargetSet:
    sources: tuple[str, ...]
    hosts: tuple[str, ...]  # IP strings


def _split_targets(s: str) -> list[str]:
    # Accept comma-separated and whitespace-separated entries
    raw = [p.strip() for p in s.replace("\n", " ").split(",")]
    parts: list[str] = []
    for r in raw:
        parts.extend([x for x in r.split() if x])
    return parts


def _expand_one(entry: str) -> list[str]:
    entry = entry.strip()
    if not entry:
        return []

    # CIDR
    if "/" in entry:
        net = ip_network(entry, strict=False)
        return [str(h) for h in net.hosts()]

    # Single IP
    return [str(ip_address(entry))]


def parse_targets(targets: str, file: str | None = None) -> TargetSet:
    sources: list[str] = []
    entries: list[str] = []

    if targets:
        sources.append(f"arg:{targets}")
        entries.extend(_split_targets(targets))

    if file:
        p = Path(file).expanduser()
        sources.append(f"file:{str(p)}")
        text = p.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            entries.append(line)

    expanded: list[str] = []
    for e in entries:
        expanded.extend(_expand_one(e))

    # de-duplicate while preserving order
    seen: set[str] = set()
    uniq: list[str] = []
    for host in expanded:
        if host not in seen:
            seen.add(host)
            uniq.append(host)

    return TargetSet(sources=tuple(sources), hosts=tuple(uniq))
