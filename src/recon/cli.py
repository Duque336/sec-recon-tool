import argparse
import json
from datetime import datetime
from pathlib import Path

from recon.report import write_markdown
from recon.scanner import tcp_check
from recon.targets import parse_targets


def _parse_ports(s: str) -> list[int]:
    ports: list[int] = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        ports.append(int(part))
    seen = set()
    out: list[int] = []
    for p in ports:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="recon", description="Authorized recon & reporting toolkit")
    p.add_argument("--targets", required=True, help="Target(s): single IP, CIDR, or comma-separated list")
    p.add_argument("--targets-file", help="File with one target per line (IP or CIDR). Lines starting with # are ignored.")
    p.add_argument("--limit", type=int, default=20, help="Preview limit: how many expanded hosts to print")
    p.add_argument("--ports", default="22,80,443", help="Comma-separated TCP ports to check (default: 22,80,443)")
    p.add_argument("--timeout", type=float, default=0.5, help="TCP connect timeout in seconds (default: 0.5)")
    p.add_argument("--out", default="reports", help="Output directory for JSON/MD reports (default: reports)")
    p.add_argument("--md", action="store_true", help="Also write reports/latest.md (markdown summary)")
    return p


def main() -> int:
    args = build_parser().parse_args()
    ts = parse_targets(args.targets, file=args.targets_file)
    ports = _parse_ports(args.ports)

    print(f"sources: {', '.join(ts.sources) if ts.sources else '(none)'}")
    print(f"expanded_hosts: {len(ts.hosts)}")
    print(f"ports: {ports}")

    preview = ts.hosts[: args.limit]
    if preview:
        print("preview:")
        for h in preview:
            print(f"  - {h}")
        if len(ts.hosts) > len(preview):
            print(f"  ... ({len(ts.hosts) - len(preview)} more)")
    else:
        print("preview: (none)")

    results = []
    for host in ts.hosts:
        host_result = {"host": host, "ports": []}
        for port in ports:
            r = tcp_check(host, port, timeout_s=args.timeout)
            host_result["ports"].append(
                {"port": r.port, "open": r.open, "error": r.error, "rtt_ms": r.rtt_ms}
            )
        results.append(host_result)

    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "sources": list(ts.sources),
        "targets": list(ts.hosts),
        "ports": ports,
        "results": results,
    }

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    json_path = out_dir / f"recon_{stamp}.json"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"wrote: {json_path}")

    if args.md:
        md_path = out_dir / "latest.md"
        write_markdown(json_path, md_path)
        print(f"wrote: {md_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
