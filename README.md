<<'EOF'
# sec-recon-tool

A small **authorized-only** recon & reporting toolkit for red-team style workflows.

This tool is designed for:
- your own lab / VMs
- environments where you have explicit permission to scan

It performs **safe recon**:
- target expansion (single IP, CIDR, lists, file input)
- TCP connect checks on a small port set
- optional lightweight banner grabs (SSH / HTTP / HTTPS)
- JSON + Markdown reporting
- diff mode to show changes between scans

## Features
- Expand targets:
  - `--targets "10.0.0.5,10.0.0.0/30"`
  - `--targets-file targets.txt` (one per line, `#` comments allowed)
- Scan ports safely with timeouts: `--ports 22,80,443 --timeout 0.5`
- `--md` writes `reports/latest.md`
- `--diff` compares current scan vs previous scan in `reports/`
- `--banners` grabs SSH/HTTP banners for open services (lightweight)

## Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip pytest rich

