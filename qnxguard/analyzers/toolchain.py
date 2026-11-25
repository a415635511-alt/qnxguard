"""QNX SDP 8.0 build system (Makefile / common.mk / CMakeLists.txt) hardening & migration analyzer."""
import re
from pathlib import Path
from typing import List
from ..models import Finding


def is_toolchain_file(path: Path) -> bool:
    name = path.name.lower()
    return name in {"makefile", "gnumakefile", "common.mk", "cmakelists.txt"} or name.endswith(".mk") or name.endswith(".cmake")


def analyze_toolchain_file(path: Path, rel_path: str) -> List[Finding]:
    findings: List[Finding] = []
    text = path.read_text(encoding="utf-8", errors="ignore")
    lines = text.splitlines()

    uses_qcc = bool(re.search(r"\b(qcc|q\+\+|ntoaarch64|ntox86_64|QNX_TARGET|QNX_HOST|qmacros\.mk)\b", text))
    if not uses_qcc:
        return findings

    has_stack_prot = "-fstack-protector" in text
    has_relro = "relro" in text and "now" in text
    has_fortify = "_FORTIFY_SOURCE" in text

    for idx, raw in enumerate(lines, 1):
        code = raw.split("#", 1)[0].strip()
        if not code:
            continue

        # QNX-TC-001: Deprecated 32-bit x86 / armle-v7 targets dropped in QNX 8.0 (QNX 8.0 is 64-bit only: x86_64 & aarch64le!)
        if re.search(r"(?:^|[\s=-]|-V)(gcc_ntox86(?!_64)|gcc_ntoarmv7le|ntox86(?!_64)-gcc|ntoarmv7-gcc)\b", code):
            findings.append(Finding(
                rule_id="QNX-TC-001",
                severity="CRITICAL",
                category="QNX 8.0 Migration",
                title="Unsupported 32-bit QNX target variant in QNX SDP 8.0",
                file=rel_path,
                line=idx,
                snippet=raw.strip()[:120],
                message="QNX SDP 8.0 supports 64-bit targets (`x86_64` and `aarch64le`) only; 32-bit `x86` and `armv7le` variants fail to compile.",
                remediation="Switch compiler variant to `-Vgcc_ntox86_64` or `-Vgcc_ntoaarch64le`.",
                qnx_doc_ref="https://www.qnx.com/developers/docs/8.0/com.qnx.doc.qnxsdp.migration/topic/overview.html",
            ))

        # QNX-TC-002: Hardcoded absolute QNX SDP 7.x path
        if re.search(r"/opt/qnx7[01]0|C:[/\\]qnx7[01]0", code, re.IGNORECASE):
            findings.append(Finding(
                rule_id="QNX-TC-002",
                severity="HIGH",
                category="Build Portability",
                title="Hardcoded QNX 7.x SDP installation path",
                file=rel_path,
                line=idx,
                snippet=raw.strip()[:120],
                message="Hardcoding QNX 7.0/7.1 paths breaks builds on QNX SDP 8.0 hosts and CI runners.",
                remediation="Reference `$(QNX_HOST)` and `$(QNX_TARGET)` populated by `qnxsdp-env.sh` (or `qnxsdp-env.bat`).",
                qnx_doc_ref="https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.getting_started/topic/s1_env_vars.html",
            ))

    if not has_stack_prot or not has_relro or not has_fortify:
        missing = []
        if not has_stack_prot:
            missing.append("-fstack-protector-strong")
        if not has_fortify:
            missing.append("-D_FORTIFY_SOURCE=2")
        if not has_relro:
            missing.append("-Wl,-z,relro,-z,now")
        findings.append(Finding(
            rule_id="QNX-TC-003",
            severity="MEDIUM",
            category="Binary Hardening",
            title=f"QNX `qcc` build omits recommended binary hardening flags: {', '.join(missing)}",
            file=rel_path,
            line=1,
            snippet=f"Missing flags in {rel_path}",
            message="Safety-critical automotive/medical/robotics QNX 8.0 binaries should enable stack canaries, fortified libc checks, and full RELRO.",
            remediation=f"Add `{' '.join(missing)}` to `CFLAGS` / `LDFLAGS` (or `add_compile_options` / `add_link_options` in CMake).",
            qnx_doc_ref="https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.security/topic/manual/compiling_secure.html",
        ))

    return findings
