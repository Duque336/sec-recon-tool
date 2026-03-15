import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from recon.banners import grab_http_server_header, grab_ssh_banner
from recon.diff import diff_reports
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
    p.add_argument("--diff", action="store_true", help="After scan, compare with previous report in --out and print changes")
    p.add_argument("--banners", action="store_true", help="If a port is open, attempt a lightweight banner grab (SSH/HTTP)")
    return p


def _banner_for(host: str, port: int, timeout_s: float) -> str | None:
    if port == 22:
        return grab_ssh_banner(host, port=22, timeout_s=timeout_s)
    if port in (80, 443):
        return grab_http_server_header(host, port=port, timeout_s=timeout_s)
    return None


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
            port_rec = {"port": r.port, "open": r.open, "error": r.error, "rtt_ms": r.rtt_ms}
            if args.banners and r.open:
                banner = _banner_for(host, port, timeout_s=args.timeout)
                if banner:
                    port_rec["banner"] = banner
            host_result["ports"].append(port_rec)
        results.append(host_result)

    generated = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report = {
        "generated_at": generated,
        "sources": list(ts.sources),
        "targets": list(ts.hosts),
        "ports": ports,
        "results": results,
    }

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / f"recon_{stamp}.json"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"wrote: {json_path}")

    if args.md:
        md_path = out_dir / "latest.md"
        write_markdown(json_path, md_path)
        print(f"wrote: {md_path}")

    if args.diff:
        files = sorted(out_dir.glob("recon_*.json"))
        if len(files) >= 2:
            prev_json = files[-2]
            new_hosts, missing_hosts, deltas = diff_reports(prev_json, json_path)
            print("\nDIFF (prev -> current)")
            print(f"prev: {prev_json.name}")
            print(f"curr: {json_path.name}")
            if new_hosts:
                print(f"new hosts: {new_hosts}")
            if missing_hosts:
                print(f"missing hosts: {missing_hosts}")
            if deltas:
                for d in deltas:
                    if d.opened:
                        print(f"{d.host} newly open: {list(d.opened)}")
                    if d.closed:
                        print(f"{d.host} newly closed: {list(d.closed)}")
            if not (new_hosts or missing_hosts or deltas):
                print("no changes detected")
        else:
            print("\nDIFF: need at least 2 reports in output dir")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
