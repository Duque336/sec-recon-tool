from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import json


@dataclass(frozen=True)
class SummaryRow:
    host: str
    open_ports: str
    notes: str


def _load_report(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_markdown(report_json: Path, out_md: Path) -> None:
    data = _load_report(report_json)
    generated = data.get("generated_at", "")
    ports = data.get("ports", [])

    rows: list[SummaryRow] = []
    for hostrec in data.get("results", []):
        host = hostrec.get("host", "")
        open_ports = [str(p["port"]) for p in hostrec.get("ports", []) if p.get("open")]
        closed_or_filtered = [p for p in hostrec.get("ports", []) if not p.get("open")]
        notes = ""
        if not open_ports:
            # show one representative error if we have it
            err = next((p.get("error") for p in closed_or_filtered if p.get("error")), "")
            notes = err or "no open ports (in scanned set)"
        rows.append(SummaryRow(host=host, open_ports=", ".join(open_ports) if open_ports else "-", notes=notes))

    lines: list[str] = []
    lines.append(f"# Recon Report")
    lines.append("")
    lines.append(f"- Generated: `{generated}`")
    lines.append(f"- Ports scanned: `{ports}`")
    lines.append(f"- Report file: `{report_json.name}`")
    lines.append("")
    lines.append("| Host | Open Ports | Notes |")
    lines.append("|---|---:|---|")
    for r in rows:
        lines.append(f"| `{r.host}` | `{r.open_ports}` | {r.notes} |")
    lines.append("")
    out_md.write_text("\n".join(lines), encoding="utf-8")
