# Codelab: Hardening & Migrating a QNX 7.1 ADAS Sensor Stack to QNX SDP 8.0 with QNXGuard

> **Estimated Time**: 25 minutes  
> **Target OS**: QNX Neutrino RTOS 8.0 (QNX SDP 8.0 / QNX Everywhere — `x86_64` & `aarch64le` / QEMU)  
> **Host OS**: Windows, macOS, or Linux (Python 3.9+, zero third-party packages required)  
> **Repository**: `https://github.com/a415635511-alt/qnxguard`

---

## What You Will Learn

By the end of this hands-on codelab, you will be able to:
1. Audit a legacy QNX 7.1 automotive/robotics codebase (`*.build`, C/C++ resource manager, and `Makefile`) against **19 QNX SDP 8.0 safety, migration, and real-time rules** in under 100 milliseconds.
2. Migrate a `mkifs` OS image from removed QNX 7.1 components (`io-pkt`, `procnto-smp`, `slogger`, `qconn`, unsafe `perms=4755`, overflowing `aps` budgets) to a hardened QNX 8.0 image (`io-sock`, `procnto-smp-instr -m ~e -m r`, `slogger2 -U 21:21`, `+compress`).
3. Eliminate four catastrophic Neutrino RTOS bugs: kernel-crash ISR calls (`malloc`/`printf` in `InterruptAttach`), unbounded priority inversion (`pthread_mutex_init` without `PTHREAD_PRIO_INHERIT`), `REPLY`-blocked IPC deadlocks (`MsgReceive` without pulse/`MsgReply`), and unbounded `MsgSend` blocking (`TimerTimeout`).
4. Enforce least privilege in QNX resource managers with `procmgr_ability()` and harden `qcc` 64-bit binaries with stack canaries, `_FORTIFY_SOURCE=2`, and full RELRO.
5. Wire QNXGuard into GitHub Code Scanning (**SARIF 2.1.0**), interactive HTML reports, and a headless **QNX 8.0 `mkifs` + QEMU** CI smoke-test pipeline.

---

## Step 1: Clone & Verify QNXGuard (2 min)

```bash
git clone https://github.com/a415635511-alt/qnxguard.git
cd qnxguard
python -m unittest discover -s tests -v
```

Expected output:
```text
Ran 5 tests in 0.014s
OK
```

---

## Step 2: Baseline Audit of the Legacy ADAS ECU (`0/100`, 19 Findings) (4 min)

Inspect our realistic QNX 7.1 ADAS Lidar ECU project in `examples/adas_ecu_legacy/`:
- `ecu.build` — `mkifs` boot image buildfile
- `sensor_resmgr.c` — Neutrino interrupt handler + resource manager + IPC client/server
- `Makefile` — `qcc` cross-compile build config

Run QNXGuard with a CI severity gate:

```bash
python -m qnxguard scan examples/adas_ecu_legacy --fail-on HIGH
```

You will see **19 findings** (5 CRITICAL, 8 HIGH, 5 MEDIUM, 1 LOW) and exit code `2` (CI gate blocked!):
- `QNX-IFS-001` (CRITICAL): `io-pkt-v6-hc` referenced — `io-pkt` was removed in QNX SDP 8.0 in favor of `io-sock`.
- `QNX-IFS-002` (CRITICAL): `qconn port=8000 &` left in the IFS boot image — unauthenticated remote command execution on port 8000.
- `QNX-IFS-007` (CRITICAL): `aps create -b 65` + `aps create -b 45` sums to **110% (> 100%)**, failing partition initialization at boot.
- `QNX-RT-009` (CRITICAL): `lidar_isr()` invokes `malloc`, `printf`, and `free` inside a kernel-context `InterruptAttach` ISR.
- `QNX-TC-001` (CRITICAL): `qcc -Vgcc_ntox86` targets 32-bit x86, which was dropped in 64-bit-only QNX SDP 8.0.

Export an interactive HTML dashboard to inspect findings visually in your browser:

```bash
python -m qnxguard scan examples/adas_ecu_legacy --format html -o legacy_audit.html
```

---

## Step 3: Migrate & Harden the `mkifs` Buildfile (`ecu.build` → `ecu_qnx8.build`) (5 min)

Compare `examples/adas_ecu_legacy/ecu.build` against `examples/adas_ecu_hardened/ecu_qnx8.build`:

| Issue Detected | Legacy QNX 7.1 | Hardened QNX 8.0 |
| --- | --- | --- |
| Unified kernel + W^X/ASLR | `procnto-smp` | `procnto-smp-instr -m ~e -m r` |
| High-performance networking | `io-pkt-v6-hc -d e1000` | `io-sock -m pci -d igb &` |
| Structured logging (non-root) | `slogger &` | `slogger2 -U 21:21 &` |
| Debug surface | `qconn port=8000 &` | Removed from production IFS |
| Adaptive Partitioning math | `65% + 45% = 110%` | `55% + 25% = 80%` (leaves 20% System headroom) |
| Image compression & perms | No `+compress`, `[perms=4755]` | `[virtual=x86_64,bios +compress]`, `[perms=0555]`, `on -u 100:100` |

---

## Step 4: Fix Real-Time, ISR & IPC Bugs in `sensor_resmgr.c` (6 min)

### 4.1 Replace Kernel ISR with `InterruptAttachEvent()`
Never call `malloc`, `free`, `printf`, or `pthread_mutex_lock` in a kernel ISR. Instead, wake an Interrupt Service Thread (IST):
```c
InterruptAttachEvent(11, &g_event, _NTO_INTR_FLAGS_TRK_MSK);
```

### 4.2 Prevent Priority Inversion with `PTHREAD_PRIO_INHERIT`
```c
pthread_mutexattr_t mattr;
pthread_mutexattr_init(&mattr);
pthread_mutexattr_setprotocol(&mattr, PTHREAD_PRIO_INHERIT);
pthread_mutex_init(&g_frame_lock, &mattr);
```

### 4.3 Bound IPC Latency & Handle Pulses Cleanly
```c
int chid = ChannelCreate(_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK | _NTO_CHF_PRIVATE);
int rcvid = MsgReceive(chid, buf, sizeof(buf), NULL);
if (rcvid == 0) {
    return 0; // pulse handled cleanly
} else if (rcvid > 0) {
    MsgReply(rcvid, EOK, NULL, 0); // never leave client REPLY-blocked
}

uint64_t timeout_ns = 5000000ULL; // 5 ms deterministic WCET cap
TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_SEND | _NTO_TIMEOUT_REPLY, NULL, &timeout_ns, NULL);
MsgSend(coid, buf, sizeof(buf), reply, sizeof(reply));
```

### 4.4 Drop Root Privileges After `resmgr_attach()`
```c
procmgr_ability(0,
    PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_INTERRUPT,
    PROCMGR_ADN_ROOT | PROCMGR_AOP_DENY | PROCMGR_AID_EOL);
```

---

## Step 5: Upgrade the `qcc` Makefile for 64-Bit QNX 8.0 + Binary Hardening (3 min)

```makefile
CC = $(QNX_HOST)/usr/bin/qcc -Vgcc_ntox86_64
CFLAGS = -O2 -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS = -Wl,-z,relro,-z,now
all:
	$(CC) $(CFLAGS) sensor_resmgr.c $(LDFLAGS) -o sensor_resmgr
```

---

## Step 6: Verify `100/100 PASS` + Generate SARIF & QEMU 8.0 Boot Harness (5 min)

Re-run QNXGuard on the hardened project:

```bash
python -m qnxguard scan examples/adas_ecu_hardened --fail-on LOW
```

Expected output:
```text
Safety Score : 100/100
Findings     : 0 total (CRITICAL=0, HIGH=0, MEDIUM=0, LOW=0)
[PASS] Zero issues found. Target satisfies all QNX 8.0 audit rules.
```

Generate a ready-to-run QNX 8.0 `mkifs` + QEMU smoke-test script and SARIF 2.1.0 artifact for GitHub Code Scanning:

```bash
python -m qnxguard init-qemu --arch x86_64 --out-dir ./scripts
python -m qnxguard scan examples/adas_ecu_hardened --format sarif -o qnxguard.sarif
```

Now run `./scripts/run_qnx8_qemu_x86_64.sh examples/adas_ecu_hardened/ecu_qnx8.build` inside any host with QNX SDP 8.0 (`source ~/qnx800/qnxsdp-env.sh`) and QEMU installed to gate, build, and boot your hardened QNX 8.0 image automatically!
