#!/usr/bin/env python3
"""
SOC Log Analyzer — CLI

Examples:
  python3 src/log_analyzer.py sample_auth.log
  python3 src/log_analyzer.py /var/log/auth.log /var/log/apache2/access.log -o report.json
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # make soc_analyzer importable

from soc_analyzer import VERSION, analyze_files, format_text       # noqa: E402


def main(argv=None):
    p = argparse.ArgumentParser(description="Detect SSH brute force, web attacks and suspicious DNS in Linux logs.")
    p.add_argument("logs", nargs="*", default=["/var/log/auth.log"],
                   help="log files to analyze (auth.log, access.log, named log; default: /var/log/auth.log)")
    p.add_argument("-o", "--output", default="report_output.json", help="JSON report path (default: %(default)s)")
    p.add_argument("--year", type=int, help="year for syslog lines without one (default: inferred)")
    p.add_argument("--geo", action="store_true", help="add IP geolocation (sends IPs to ip-api.com)")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = p.parse_args(argv)

    try:
        report = analyze_files(args.logs, year=args.year, geo=args.geo)
    except OSError as e:
        print(f"[ERROR] {e.filename}: {e.strerror}", file=sys.stderr)
        return 1

    print(format_text(report, color=sys.stdout.isatty() and not args.no_color))
    Path(args.output).write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"  [+] JSON report saved → {args.output}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
