"""Directory scanner orchestrating all QNX 8.0 analyzers."""
from pathlib import Path
from typing import Iterable, Set
from .models import AuditReport
from .analyzers.buildfile import is_qnx_buildfile, analyze_buildfile
from .analyzers.c_rtos import is_c_source, analyze_c_file
from .analyzers.toolchain import is_toolchain_file, analyze_toolchain_file

DEFAULT_IGNORE_DIRS: Set[str] = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "build", "dist", "out", ".idea", ".vscode",
}


def iter_files(target: Path) -> Iterable[Path]:
    if target.is_file():
        yield target
        return
    for p in sorted(target.rglob("*")):
        if p.is_dir():
            continue
        if any(part in DEFAULT_IGNORE_DIRS for part in p.parts):
            continue
        yield p


def scan_path(target_dir: Path) -> AuditReport:
    target_dir = target_dir.resolve()
    report = AuditReport(target_dir=str(target_dir))
    base = target_dir if target_dir.is_dir() else target_dir.parent

    for fpath in iter_files(target_dir):
        rel = str(fpath.relative_to(base)).replace("\\", "/")
        matched = False
        if is_qnx_buildfile(fpath):
            report.buildfiles_scanned += 1
            report.findings.extend(analyze_buildfile(fpath, rel))
            matched = True
        if is_c_source(fpath):
            report.c_files_scanned += 1
            report.findings.extend(analyze_c_file(fpath, rel))
            matched = True
        if is_toolchain_file(fpath):
            report.toolchain_files_scanned += 1
            report.findings.extend(analyze_toolchain_file(fpath, rel))
            matched = True
        if matched:
            report.files_scanned += 1

    return report
