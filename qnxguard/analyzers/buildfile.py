"""QNX SDP 8.0 mkifs Image Filesystem (*.build) static analyzer."""
import re
from pathlib import Path
from typing import List
from ..models import Finding


def is_qnx_buildfile(path: Path) -> bool:
    if path.suffix.lower() in {".build", ".ifs"}:
        return True
    if path.name.lower().endswith(".build.in"):
        return True
    return False


def analyze_buildfile(path: Path, rel_path: str) -> List[Finding]:
    findings: List[Finding] = []
    text = path.read_text(encoding="utf-8", errors="ignore")
    lines = text.splitlines()

    has_compress = False
    has_slogger2 = False
    has_procnto = False
    procnto_line = 0
    procnto_text = ""
    aps_budgets = []  # list of (line_no, name, budget_pct)

    for idx, raw in enumerate(lines, 1):
        # Strip buildfile comments (#...) outside quotes
        code = raw.split("#", 1)[0].strip()
        if not code:
            continue

        if "+compress" in code or "compress=" in code:
            has_compress = True
        if re.search(r"\bslogger2\b", code):
            has_slogger2 = True

        # QNX-IFS-001: Deprecated io-pkt network stack in QNX 8.0 (replaced by io-sock)
        if re.search(r"\bio-pkt(?:-[a-zA-Z0-9_]+)?\b", code):
            findings.append(Finding(
                rule_id="QNX-IFS-001",
                severity="CRITICAL",
                category="QNX 8.0 Migration",
                title="Deprecated io-pkt networking stack in QNX 8.0 buildfile",
                file=rel_path,
                line=idx,
                snippet=raw.strip()[:120],
                message="QNX SDP 8.0 removed the legacy io-pkt stack and standardized on the High-Performance Networking Stack (io-sock).",
                remediation="Replace `io-pkt*` binaries and `devnp-*.so` drivers with `io-sock` and FreeBSD-derived `devs-*.so` / `mods-*.so` modules.",
                qnx_doc_ref="https://www.qnx.com/developers/docs/8.0/com.qnx.doc.qnxsdp.migration/topic/bsp_support.html",
            ))

        # QNX-IFS-002: Remote debug daemon qconn included in IFS image
        if re.search(r"\bqconn\b", code):
            findings.append(Finding(
                rule_id="QNX-IFS-002",
                severity="CRITICAL",
                category="IFS Security",
                title="Unauthenticated debug agent `qconn` embedded in boot image",
                file=rel_path,
                line=idx,
                snippet=raw.strip()[:120],
                message="`qconn` exposes remote process launch, memory inspection, and filesystem access on port 8000 without authentication.",
                remediation="Remove `qconn` from production IFS buildfiles, or guard it behind a strictly dev-only build variant.",
                qnx_doc_ref="https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/q/qconn.html",
            ))

        # QNX-IFS-003: Legacy slogger (replaced by slogger2)
        if re.search(r"\bslogger\b(?!2)", code):
            findings.append(Finding(
                rule_id="QNX-IFS-003",
                severity="HIGH",
                category="QNX 8.0 Migration",
                title="Legacy `slogger` daemon referenced instead of `slogger2`",
                file=rel_path,
                line=idx,
                snippet=raw.strip()[:120],
                message="Legacy `slogger` is obsolete in QNX 8.0; system services expect `slogger2` structured logging buffers.",
                remediation="Replace `slogger` with `slogger2` (e.g., `slogger2 -U 21:21` running as a non-root user).",
                qnx_doc_ref="https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/s/slogger2.html",
            ))

        # QNX-IFS-004: Dangerous mkifs file permissions (setuid/setgid or world-writable 0777/0666)
        m_perm = re.search(r"perms\s*=\s*([^\s\]]+)", code)
        if m_perm:
            pval = m_perm.group(1)
            if "+s" in pval or re.search(r"\b[467][0-7]{3}\b", pval) or re.search(r"\b0?[0-7]{2}[2367]\b", pval):
                findings.append(Finding(
                    rule_id="QNX-IFS-004",
                    severity="HIGH",
                    category="IFS Security",
                    title=f"Overly permissive or setuid IFS file attribute (`perms={pval}`)",
                    file=rel_path,
                    line=idx,
                    snippet=raw.strip()[:120],
                    message=f"IFS attribute `perms={pval}` grants setuid/setgid escalation or world-writable access inside the OS image.",
                    remediation="Restrict binaries to `perms=0555` or `perms=0755` and drop privileges with `procmgr_ability()` instead of setuid root.",
                    qnx_doc_ref="https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/m/mkifs.html",
                ))

        # QNX-IFS-005: Kernel procnto-smp-instr check for QNX 8.0 hardening flags (-m)
        if re.search(r"\bprocnto-smp(?:-instr)?\b", code):
            has_procnto = True
            procnto_line = idx
            procnto_text = code
            if "procnto-smp-instr" not in code:
                findings.append(Finding(
                    rule_id="QNX-IFS-005",
                    severity="HIGH",
                    category="QNX 8.0 Migration",
                    title="Non-instrumented `procnto-smp` variant referenced",
                    file=rel_path,
                    line=idx,
                    snippet=raw.strip()[:120],
                    message="In QNX SDP 8.0, `procnto-smp-instr` is the unified kernel/process manager binary; legacy `procnto-smp` names fail mkifs.",
                    remediation="Use `procnto-smp-instr` with memory-protection flags (e.g., `procnto-smp-instr -m ~e -m r`).",
                    qnx_doc_ref="https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.building/topic/os_images/images_about.html",
                ))
            elif "-m" not in code:
                findings.append(Finding(
                    rule_id="QNX-IFS-006",
                    severity="MEDIUM",
                    category="Kernel Hardening",
                    title="`procnto-smp-instr` launched without explicit memory-hardening `-m` options",
                    file=rel_path,
                    line=idx,
                    snippet=raw.strip()[:120],
                    message="Explicit `-m` flags enforce W^X (`~e`) and ASLR randomization (`r`) across all spawned QNX processes.",
                    remediation="Pass explicit hardening flags such as `procnto-smp-instr -m ~e -m r` in `.bootstrap`.",
                    qnx_doc_ref="https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/p/procnto.html",
                ))

        # QNX-IFS-007: Adaptive Partitioning Scheduler (aps create) budget math & bankruptcy check
        m_aps = re.search(r"\baps\s+create\b(.*)", code)
        if m_aps:
            args = m_aps.group(1)
            m_b = re.search(r"-b\s*(\d+)", args)
            name_m = re.findall(r"([a-zA-Z0-9_.-]+)\s*$", args.strip())
            pname = name_m[0] if name_m else f"line-{idx}"
            if m_b:
                pct = int(m_b.group(1))
                aps_budgets.append((idx, pname, pct))
                if pct == 0:
                    findings.append(Finding(
                        rule_id="QNX-IFS-007",
                        severity="MEDIUM",
                        category="Real-Time Scheduling",
                        title=f"Adaptive partition `{pname}` created with 0% guaranteed CPU budget",
                        file=rel_path,
                        line=idx,
                        snippet=raw.strip()[:120],
                        message="A 0% APS budget allows the partition to starve completely under full CPU load from higher-budget partitions.",
                        remediation="Assign a non-zero guaranteed CPU percentage (`-b <pct>`) for every safety/control partition.",
                        qnx_doc_ref="https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/a/aps.html",
                    ))

    if aps_budgets:
        total_pct = sum(p for _, _, p in aps_budgets)
        if total_pct > 100:
            first_line = aps_budgets[0][0]
            findings.append(Finding(
                rule_id="QNX-IFS-007",
                severity="CRITICAL",
                category="Real-Time Scheduling",
                title=f"Adaptive Partitioning (`aps`) CPU budgets sum to {total_pct}% (> 100%)",
                file=rel_path,
                line=first_line,
                snippet=", ".join(f"{n}={p}%" for _, n, p in aps_budgets),
                message=f"Total `aps create` budgets equal {total_pct}%, which causes `aps` partition creation to fail at boot.",
                remediation="Rebalance `aps create -b <pct>` budgets so all partitions plus the System partition total <= 100%.",
                qnx_doc_ref="https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/a/aps.html",
            ))

    if has_procnto and not has_compress:
        findings.append(Finding(
            rule_id="QNX-IFS-008",
            severity="LOW",
            category="IFS Optimization",
            title="Bootable IFS buildfile omits `[+compress]`",
            file=rel_path,
            line=procnto_line or 1,
            snippet=procnto_text[:120],
            message="Uncompressed IFS images consume significantly more flash/RAM and increase boot load time on embedded targets.",
            remediation="Add `[+compress]` before bootable binary lists unless XIP (execute-in-place) is explicitly required.",
            qnx_doc_ref="https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/m/mkifs.html",
        ))

    if has_procnto and not has_slogger2 and not any(f.rule_id == "QNX-IFS-003" for f in findings):
        findings.append(Finding(
            rule_id="QNX-IFS-009",
            severity="LOW",
            category="Observability",
            title="No `slogger2` logging daemon detected in bootable IFS",
            file=rel_path,
            line=procnto_line or 1,
            snippet=procnto_text[:120],
            message="Without `slogger2`, QNX 8.0 drivers (`io-sock`, `devb-*`) drop diagnostic and fault telemetry.",
            remediation="Start `slogger2` early in the boot script before launching network/block drivers.",
            qnx_doc_ref="https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/s/slogger2.html",
        ))

    return findings
