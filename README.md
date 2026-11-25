# QNXGuard — Static Safety, `mkifs` Buildfile & Real-Time Auditor for QNX SDP 8.0

**Category**: Developer Tooling & Host Tools (QNX Global Hackathon 2026)  
**Target**: QNX Software Development Platform (SDP) 8.0 (`x86_64`, `aarch64le`, QEMU)  
**Host Platforms**: Windows, macOS, Linux (zero external runtime dependencies — pure Python 3 stdlib)

QNXGuard catches QNX 7.x → 8.0 migration breakage, `mkifs` boot-image security flaws, Adaptive Partitioning (`aps`) budget overflows, ISR kernel-crash hazards, priority inversion bugs, and IPC deadlock patterns **before** you flash hardware or boot QEMU.

---

## Why QNXGuard?

Building safety-critical automotive, robotics, and medical workloads on **QNX Neutrino 8.0** requires strict compliance across three separate layers:
1. **`mkifs` OS Image Buildfiles (`*.build`)**: `io-pkt` was removed in QNX 8.0 in favor of `io-sock`; `procnto-smp-instr` is the unified kernel; leaving `qconn` or `perms=4755` in production images opens root compromise; miscalculated `aps create -b` budgets abort boot.
2. **Neutrino C/C++ Real-Time & IPC Code**: Calling `malloc`/`printf` inside an `InterruptAttach` ISR crashes the kernel; omitting `PTHREAD_PRIO_INHERIT` causes unbounded priority inversion; missing `rcvid == 0` pulse handling or `MsgReply` leaves clients permanently `REPLY`-blocked; unbounded `MsgSend` breaks WCET determinism; `resmgr_attach` without `procmgr_ability()` retains unnecessary root capabilities.
3. **`qcc` / `Makefile` / `CMake` Cross-Compilation**: QNX 8.0 is 64-bit only (`-Vgcc_ntox86_64` / `-Vgcc_ntoaarch64le`), dropping 32-bit `gcc_ntox86` and `gcc_ntoarmv7le`, while safety builds require stack canaries, `_FORTIFY_SOURCE=2`, and full RELRO.

---

## Audit Rule Catalog (18+ QNX 8.0 Rules)

| Layer | Rule IDs | What QNXGuard Detects |
| --- | --- | --- |
| **`mkifs` Buildfiles** | `QNX-IFS-001` – `009` | Deprecated `io-pkt`, exposed `qconn`, legacy `slogger` vs `slogger2`, setuid/world-writable `perms=`, legacy `procnto-smp` vs `procnto-smp-instr`, missing `-m` ASLR/W^X flags, `aps create` budget > 100% or 0%, missing `+compress` |
| **Neutrino C/C++ RTOS** | `QNX-RT-001` – `009` | Non-ISR-safe calls (`malloc`, `printf`, `pthread_mutex_lock`, `MsgSend`) inside `InterruptAttach` ISR, `InterruptAttach` vs `InterruptAttachEvent`, `<io-pkt/...>` headers, `MsgReceive` pulse/reply deadlocks, missing `PTHREAD_PRIO_INHERIT`, unbounded `MsgSend` without `TimerTimeout`, bare `ChannelCreate(0)`, `resmgr_attach` without `procmgr_ability`, non-root priority > 63 |
| **Build & Toolchain** | `QNX-TC-001` – `003` | Dropped 32-bit `gcc_ntox86`/`gcc_ntoarmv7le` variants, hardcoded QNX 7.x paths, missing `-fstack-protector-strong` / `-D_FORTIFY_SOURCE=2` / `-Wl,-z,relro,-z,now` |

---

## Quick Start (Zero Dependencies)

```bash
# 1. Audit the included legacy QNX 7.1 -> 8.0 ADAS ECU sample (triggers 19 findings, score 0/100)
python -m qnxguard scan examples/adas_ecu_legacy

# 2. Audit the hardened QNX 8.0 ADAS ECU sample (0 findings, score 100/100)
python -m qnxguard scan examples/adas_ecu_hardened --fail-on LOW

# 3. Export SARIF 2.1.0 for GitHub Code Scanning
python -m qnxguard scan examples/adas_ecu_legacy --format sarif -o qnxguard.sarif

# 4. Export an interactive self-contained HTML dashboard
python -m qnxguard scan examples/adas_ecu_legacy --format html -o qnxguard_report.html

# 5. Generate a QNX 8.0 mkifs + QEMU boot & CI smoke-test harness
python -m qnxguard init-qemu --arch x86_64 --out-dir ./scripts
python -m qnxguard init-qemu --arch aarch64 --out-dir ./scripts
```

## Verification & Tests

```bash
python -m unittest discover -s tests -v
```

All 5 end-to-end test suites verify every rule category, CI `--fail-on` exit codes, SARIF 2.1.0 schema compliance, HTML report rendering, and QEMU 8.0 harness generation.
