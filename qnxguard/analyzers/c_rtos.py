"""QNX Neutrino 8.0 C/C++ real-time, ISR, IPC, and least-privilege static analyzer."""
import re
from pathlib import Path
from typing import List, Set
from ..models import Finding

C_EXTS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp"}


def is_c_source(path: Path) -> bool:
    return path.suffix.lower() in C_EXTS


def _find_function_body(text: str, func_name: str):
    """Best-effort extractor of a C function body by name for ISR context checking."""
    pat = re.compile(rf"\b{re.escape(func_name)}\s*\([^)]*\)\s*\{{", re.MULTILINE)
    m = pat.search(text)
    if not m:
        return None, 0
    start_line = text[:m.start()].count("\n") + 1
    depth = 1
    i = m.end()
    while i < len(text) and depth > 0:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    return text[m.end():i], start_line


def analyze_c_file(path: Path, rel_path: str) -> List[Finding]:
    findings: List[Finding] = []
    text = path.read_text(encoding="utf-8", errors="ignore")
    lines = text.splitlines()

    # Check whether file looks QNX-related or generic POSIX RTOS code
    has_procmgr_ability = "procmgr_ability" in text
    has_prio_inherit = "PTHREAD_PRIO_INHERIT" in text
    has_timer_timeout = "TimerTimeout" in text
    has_msg_reply = bool(re.search(r"\b(MsgReply|MsgReplyv|MsgError)\s*\(", text))

    isr_handlers: Set[str] = set()

    for idx, raw in enumerate(lines, 1):
        code = raw.split("//", 1)[0]
        if not code.strip():
            continue

        # QNX-RT-001: InterruptAttach() usage (discouraged in QNX 8.0 vs InterruptAttachEvent; also capture handler name!)
        m_ia = re.search(r"\bInterruptAttach\s*\(\s*[^,]+,\s*([a-zA-Z_][a-zA-Z0-9_]*)", code)
        if m_ia:
            handler_name = m_ia.group(1)
            isr_handlers.add(handler_name)
            findings.append(Finding(
                rule_id="QNX-RT-001",
                severity="HIGH",
                category="Interrupt Safety",
                title=f"Kernel-context `InterruptAttach` used with ISR `{handler_name}`",
                file=rel_path,
                line=idx,
                snippet=raw.strip()[:120],
                message="In QNX Neutrino 8.0, `InterruptAttach()` executes in kernel ISR context with severe restrictions and higher crash blast radius.",
                remediation="Prefer `InterruptAttachEvent()` + a dedicated high-priority IST thread using `InterruptWait()` whenever latency budgets permit.",
                qnx_doc_ref="https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/i/interruptattachevent.html",
            ))

        # QNX-RT-002: Deprecated QNX 7.x io-pkt headers
        if re.search(r'#\s*include\s*[<"]io-pkt/', code):
            findings.append(Finding(
                rule_id="QNX-RT-002",
                severity="CRITICAL",
                category="QNX 8.0 Migration",
                title="Deprecated `<io-pkt/...>` header included",
                file=rel_path,
                line=idx,
                snippet=raw.strip()[:120],
                message="`<io-pkt/...>` headers do not exist in QNX SDP 8.0 (`io-pkt` was removed in favor of `io-sock`).",
                remediation="Migrate driver/app includes to QNX 8.0 `io-sock` / standard BSD socket headers.",
                qnx_doc_ref="https://www.qnx.com/developers/docs/8.0/com.qnx.doc.qnxsdp.migration/topic/migrate_app.html",
            ))

        # QNX-RT-003: MsgReceive() without pulse handling (rcvid == 0) or MsgReply/MsgError
        if re.search(r"\bMsgReceive(?:v)?\s*\(", code):
            # Look ahead 25 lines for rcvid == 0 check
            window = "\n".join(lines[idx - 1: min(len(lines), idx + 25)])
            if not re.search(r"==\s*0|!=\s*0|<=\s*0|>\s*0", window) or not has_msg_reply:
                findings.append(Finding(
                    rule_id="QNX-RT-003",
                    severity="HIGH",
                    category="IPC Deadlock",
                    title="`MsgReceive()` loop missing pulse (`rcvid == 0`) or `MsgReply`/`MsgError` handling",
                    file=rel_path,
                    line=idx,
                    snippet=raw.strip()[:120],
                    message="Failing to distinguish pulses (`rcvid == 0`) or failing to reply to every `rcvid > 0` leaves QNX clients permanently REPLY-blocked.",
                    remediation="Explicitly handle `rcvid == -1` (error), `rcvid == 0` (pulse), and call `MsgReply()` or `MsgError()` on every `rcvid > 0` path.",
                    qnx_doc_ref="https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/m/msgreceive.html",
                ))

        # QNX-RT-004: pthread_mutex_init without PTHREAD_PRIO_INHERIT
        if re.search(r"\bpthread_mutex_init\s*\([^,]+,\s*NULL\s*\)", code) or (
            re.search(r"\bpthread_mutex_init\s*\(", code) and not has_prio_inherit
        ):
            findings.append(Finding(
                rule_id="QNX-RT-004",
                severity="HIGH",
                category="Priority Inversion",
                title="`pthread_mutex_init()` configured without `PTHREAD_PRIO_INHERIT`",
                file=rel_path,
                line=idx,
                snippet=raw.strip()[:120],
                message="Default mutex attributes without priority inheritance allow medium-priority threads to preempt a low-priority lock holder, starving high-priority real-time threads.",
                remediation="Initialize a `pthread_mutexattr_t` with `pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT)` before `pthread_mutex_init()`.",
                qnx_doc_ref="https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/p/pthread_mutexattr_setprotocol.html",
            ))

        # QNX-RT-005: Unbounded MsgSend without TimerTimeout
        if re.search(r"\bMsgSend(?:v|nc)?\s*\(", code) and not has_timer_timeout:
            findings.append(Finding(
                rule_id="QNX-RT-005",
                severity="MEDIUM",
                category="Real-Time Determinism",
                title="Unbounded `MsgSend()` without kernel `TimerTimeout()` guard",
                file=rel_path,
                line=idx,
                snippet=raw.strip()[:120],
                message="If the target server stalls or crashes mid-reply, an unguarded `MsgSend()` blocks the real-time thread indefinitely and violates WCET bounds.",
                remediation="Wrap safety-critical `MsgSend()` calls with `TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_SEND | _NTO_TIMEOUT_REPLY, NULL, &nsec, NULL)`.",
                qnx_doc_ref="https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/t/timertimeout.html",
            ))

        # QNX-RT-006: ChannelCreate(0) missing protective channel flags
        if re.search(r"\bChannelCreate\s*\(\s*0\s*\)", code):
            findings.append(Finding(
                rule_id="QNX-RT-006",
                severity="MEDIUM",
                category="IPC Security",
                title="`ChannelCreate(0)` omits `_NTO_CHF_UNBLOCK` / `_NTO_CHF_DISCONNECT` / `_NTO_CHF_PRIVATE`",
                file=rel_path,
                line=idx,
                snippet=raw.strip()[:120],
                message="A bare `ChannelCreate(0)` cannot clean up client state on disconnect/unblock pulses and allows cross-process attach unless `_NTO_CHF_PRIVATE` is set.",
                remediation="Pass explicit flags such as `ChannelCreate(_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK)` (and `_NTO_CHF_PRIVATE` for intra-process channels).",
                qnx_doc_ref="https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/c/channelcreate.html",
            ))

        # QNX-RT-007: resmgr_attach without procmgr_ability() privilege dropping
        if re.search(r"\bresmgr_attach\s*\(", code) and not has_procmgr_ability:
            findings.append(Finding(
                rule_id="QNX-RT-007",
                severity="HIGH",
                category="Least Privilege",
                title="Resource manager attaches namespace without `procmgr_ability()` least-privilege hardening",
                file=rel_path,
                line=idx,
                snippet=raw.strip()[:120],
                message="Resource managers that register paths via `resmgr_attach()` often start as root; retaining unrestricted root abilities widens attack surface.",
                remediation="Drop unnecessary abilities with `procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | ..., PROCMGR_AID_EOL)` and switch to a non-root UID/GID after startup.",
                qnx_doc_ref="https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/p/procmgr_ability.html",
            ))

        # QNX-RT-008: Hardcoded thread priority > 63 without PROCMGR_AID_PRIORITY check
        m_prio = re.search(r"sched_priority\s*=\s*(\d+)", code)
        if m_prio and int(m_prio.group(1)) > 63 and "PROCMGR_AID_PRIORITY" not in text:
            pval = int(m_prio.group(1))
            findings.append(Finding(
                rule_id="QNX-RT-008",
                severity="MEDIUM",
                category="Real-Time Scheduling",
                title=f"Hardcoded `sched_priority = {pval}` exceeds QNX 8.0 non-root default ceiling (63)",
                file=rel_path,
                line=idx,
                snippet=raw.strip()[:120],
                message=f"Setting priority {pval} fails with `EPERM` when running as non-root unless `PROCMGR_AID_PRIORITY` is explicitly granted.",
                remediation="Keep non-root priorities <= 63, or explicitly configure `PROCMGR_AID_PRIORITY` via `procmgr_ability()` / `secpol`.",
                qnx_doc_ref="https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.sys_arch/topic/kernel_Scheduling.html",
            ))

    # Inspect bodies of any ISR handlers registered via InterruptAttach()!
    for hname in sorted(isr_handlers):
        body, start_line = _find_function_body(text, hname)
        if not body:
            continue
        unsafe_calls = re.findall(r"\b(malloc|calloc|realloc|free|printf|fprintf|sprintf|slog2f|pthread_mutex_lock|MsgSend|open|read|write|sleep|usleep)\s*\(", body)
        if unsafe_calls:
            uniq = ", ".join(sorted(set(unsafe_calls)))
            findings.append(Finding(
                rule_id="QNX-RT-009",
                severity="CRITICAL",
                category="Interrupt Safety",
                title=f"Forbidden non-ISR-safe call(s) `{uniq}` inside ISR `{hname}()`",
                file=rel_path,
                line=start_line,
                snippet=f"ISR {hname}() invokes: {uniq}",
                message="Calling heap allocators, stdio, mutexes, or kernel IPC inside a QNX `InterruptAttach` ISR causes immediate kernel faults or deadlocks.",
                remediation="Move all logging, memory allocation, and IPC out of the ISR; return a `struct sigevent *` to wake an IST thread instead.",
                qnx_doc_ref="https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.prog/topic/inthandler_Writing_ISR.html",
            ))

    return findings
