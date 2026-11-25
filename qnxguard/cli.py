"""Command-line interface for QNXGuard."""
import argparse
import json
import sys
from pathlib import Path
from . import __version__
from .models import SEVERITY_ORDER
from .scanner import scan_path
from .reporters.sarif import to_sarif
from .reporters.html_report import to_html
from .qemu_gen import generate_qemu_harness


def _print_text_report(report) -> None:
    s = report.to_dict()["summary"]
    by = s["by_severity"]
    print("=" * 78)
    print(f"QNXGuard v{__version__} — QNX SDP 8.0 Static Safety, Buildfile & RTOS Auditor")
    print("=" * 78)
    print(f"Target       : {report.target_dir}")
    print(f"Files Scanned: {s['files_scanned']} ({s['buildfiles_scanned']} buildfiles, {s['c_files_scanned']} C/C++, {s['toolchain_files_scanned']} toolchain)")
    print(f"Safety Score : {report.score}/100")
    print(f"Findings     : {s['total_findings']} total (CRITICAL={by['CRITICAL']}, HIGH={by['HIGH']}, MEDIUM={by['MEDIUM']}, LOW={by['LOW']})")
    print("-" * 78)
    if not report.findings:
        print("[PASS] Zero issues found. Target satisfies all QNX 8.0 audit rules.")
        return
    for f in report.sorted_findings():
        print(f"[{f.severity:<8}] {f.rule_id:<12} {f.file}:{f.line}")
        print(f"  Title : {f.title}")
        print(f"  Code  : {f.snippet}")
        print(f"  Fix   : {f.remediation}")
        print()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="qnxguard",
        description="Host-side static safety, mkifs buildfile & real-time auditor for QNX SDP 8.0",
    )
    parser.add_argument("--version", action="version", version=f"qnxguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Audit a QNX 8.0 project directory or file")
    p_scan.add_argument("target", help="Path to QNX project directory or file")
    p_scan.add_argument("--format", choices=["text", "json", "sarif", "html"], default="text")
    p_scan.add_argument("--output", "-o", help="Write report output to file instead of stdout")
    p_scan.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"],
        default="NONE",
        help="Return exit code 2 if any finding meets or exceeds this severity (CI gate)",
    )

    p_qemu = sub.add_parser("init-qemu", help="Generate a QNX 8.0 mkifs + QEMU boot/test harness script")
    p_qemu.add_argument("--arch", choices=["x86_64", "aarch64"], default="x86_64")
    p_qemu.add_argument("--out-dir", default=".", help="Output directory for generated script")

    args = parser.parse_args(argv)

    if args.command == "init-qemu":
        out = generate_qemu_harness(Path(args.out_dir), arch=args.arch)
        print(f"Generated QNX 8.0 QEMU harness: {out}")
        return 0

    target = Path(args.target)
    if not target.exists():
        print(f"Error: target path does not exist: {target}", file=sys.stderr)
        return 1

    report = scan_path(target)

    if args.format == "json":
        rendered = json.dumps(report.to_dict(), indent=2)
    elif args.format == "sarif":
        rendered = to_sarif(report)
    elif args.format == "html":
        rendered = to_html(report)
    else:
        rendered = None

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if rendered is None:
            # Capture text summary cleanly
            import io, contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                _print_text_report(report)
            out_path.write_text(buf.getvalue(), encoding="utf-8")
        else:
            out_path.write_text(rendered, encoding="utf-8")
        print(f"Report written to {out_path} (score={report.score}/100, findings={len(report.findings)})")
    else:
        if rendered is None:
            _print_text_report(report)
        else:
            print(rendered)

    if args.fail_on != "NONE":
        threshold = SEVERITY_ORDER[args.fail_on]
        if report.max_severity_rank() >= threshold:
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
