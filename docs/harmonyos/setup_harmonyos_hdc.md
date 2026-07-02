# Setup: fuzzing the OpenHarmony / HarmonyOS Linux kernel over `hdc`

This document describes how to point syzkaller at the **OpenHarmony / HarmonyOS
"standard system" Linux kernel** using the `hdc` (OpenHarmony Device Connector)
VM backend added in this fork, plus the OpenHarmony-specific driver descriptions
that ship with it.

> **Note: fuzzing a kernel on a real device may brick it.** Prefer the emulator
> or a spare device. See also the general
> [Android device setup](/docs/linux/setup_linux-host_android-device_arm-kernel.md),
> which this backend is modelled on.

## 1. Scope — what this can and cannot fuzz

Read this first; it saves a lot of wasted effort.

* **In scope — the OpenHarmony standard-system Linux kernel.** OpenHarmony's
  "standard system" runs a Linux kernel (5.10 LTS at the time of writing) with
  the OpenHarmony patch set: HDF drivers, the (mainline-removed) `ashmem`,
  dma-buf heaps, and Huawei security modules such as `xpm`, `dec`, `code_sign`.
  This is a normal `arm64`/`amd64` Linux target: coverage via **KCOV**, crashes
  via the kernel log. The **OpenHarmony emulator is a real Linux 5.10 kernel**
  and is the easiest target to start with.

* **Out of scope — the "HarmonyOS NEXT" HongMeng microkernel.** Flagship
  HarmonyOS NEXT devices boot the proprietary **HongMeng (鸿蒙) microkernel**,
  *not* Linux. It exposes no KCOV, a private/undocumented syscall ABI, and runs
  the Linux kernel only as a userspace "devhost" whose ioctl surface is further
  restricted by seccomp for normal apps. syzkaller (a coverage-guided *syscall*
  fuzzer for monolithic kernels) has no target for HongMeng, and adding one is
  not a description exercise — it would be a from-scratch OS port with no public
  ABI. **Do not expect this backend to fuzz the flagship microkernel.**

* **Not what this is for — userspace IPC / System-Ability fuzzing.** Several
  recent findings in this research line (persistent AudioPolicy DoS, RenderService
  typeface fd race, cross-app render capture, …) were found by mutating raw IPC
  *parcels* sent to OpenHarmony **System Abilities** (`safuzz`/`typefuzz`). Those
  live in a *userspace* service process; syzkaller's kernel KCOV does not observe
  them and its executor does not speak OHOS binder-SA transactions. Keep using
  the existing parcel-fuzzer for that layer. syzkaller is the right tool for the
  **kernel-driver** leads (ashmem, dma-buf, mali/maleoon GPU, xpm, dec,
  code_sign, jit_memory) — see the mapping in §7.

## 2. What this fork adds

* **`vm/hdc`** — a VM backend that drives a physical or emulated OpenHarmony
  device over `hdc`, the OpenHarmony counterpart of `adb`. It is a close
  adaptation of [`vm/adb`](/vm/adb/adb.go); every bridge call is translated
  (`hdc -t DEV shell`, `hdc file send`, `hdc rport`, `hdc wait`, `hdc target
  boot`, `hdc shell dmesg -w` for the console).
* **OpenHarmony driver descriptions** under `sys/linux/`:
  * `dev_ohos_xpm.txt` — `/dev/xpm` eXecute-only-Memory / owner-id module.
  * `dev_ohos_dec.txt` — `/dev/dec` data-access-control path-rule parser.
  * `dev_ohos_code_sign.txt` — `/dev/code_sign` certificate-chain ingest.
  * `dev_ashmem_ohos.txt` — OpenHarmony purgeable-ashmem ioctl extensions,
    layered on the mainline `dev_ashmem.txt`.

  These use `meta noextract` with hand-provided `*.const` values (the OHOS UAPI
  headers are not in any mainline tree, so `syz-extract` can't see them). The
  constants were computed directly from the OpenHarmony kernel sources; the
  source path for each is cited in the `.txt` header.

## 3. Build a fuzzable kernel (KCOV + KASAN)

Coverage-guided fuzzing needs a kernel built with at least:

```
CONFIG_KCOV=y
CONFIG_KCOV_INSTRUMENT_ALL=y
CONFIG_KASAN=y
CONFIG_KASAN_INLINE=y
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_FS=y
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y
```

Build the OpenHarmony kernel (`kernel/linux/linux-5.10` in an OpenHarmony
checkout) with these enabled, using the OpenHarmony/clang toolchain, and flash
or boot the resulting image on your emulator/device. See
[kernel_configs.md](/docs/linux/kernel_configs.md) for the full recommended set.

If you cannot build a KCOV kernel yet, you can still do **blind** (coverage-less)
fuzzing by setting `"cover": false` in the manager config — far less effective,
but it exercises the descriptions and still catches KASAN/BUG crashes.

### SELinux

`/dev/dec` and `/dev/code_sign` are **SELinux-gated on retail images** (the ioctl
requires a specific caller context; a normal process gets `EACCES` at `open`).
`/dev/xpm` and `ashmem` are reachable by a normal process. To fuzz the gated
modules, run a debug image with SELinux **permissive** (`setenforce 0`) or a
relaxed test policy — otherwise those calls just bounce at `open`.

## 4. Build syzkaller

```bash
# arm64 device / arm64 emulator
make TARGETOS=linux TARGETARCH=arm64
# or x86_64 emulator
make TARGETOS=linux TARGETARCH=amd64
```

The OpenHarmony descriptions are compiled in automatically (they are ordinary
`sys/linux/*.txt` files).

## 5. Manager config

Save the following as `openharmony_emulator.cfg` (syzkaller `.gitignore`s
`*.cfg`, so keep your config outside the tree) and edit the paths:

```json
{
	"target": "linux/arm64",
	"http": "127.0.0.1:56741",
	"workdir": "/syzkaller/workdir",
	"kernel_obj": "/path/to/openharmony/out/kernel/vmlinux-dir",
	"kernel_src": "/path/to/openharmony/kernel/linux/linux-5.10",
	"syzkaller": "/path/to/syzkaller",
	"cover": true,
	"procs": 4,
	"sandbox": "none",
	"type": "hdc",
	"vm": {
		"hdc": "hdc",
		"devices": ["127.0.0.1:5555"],
		"target_reboot": true,
		"boot_service": "foundation"
	}
}
```

`vm` fields (see [`vm/hdc/hdc.go`](/vm/hdc/hdc.go)):

| field | meaning |
|---|---|
| `hdc` | `hdc` binary name/path (default `hdc`). |
| `devices` | list of hdc connect keys: a USB serial, or `ip:port` for the emulator / a TCP device (e.g. the local emulator on `127.0.0.1:5555`). |
| `target_reboot` | reboot the device (`hdc target boot`) between runs (default `true`). |
| `boot_service` | process to wait for as the boot-complete signal (default `foundation`, the OHOS core-services host). Set `""` to skip. |
| `repair_script` / `startup_script` | optional host scripts run before/after startup. |
| `console` / `console_cmd` | optional serial console; without one the backend falls back to `hdc shell dmesg -w`. |

Notes:
* syz-manager itself runs on a **Linux host**. `hdc` must be installed there and
  the device/emulator reachable (over USB, or `hdc tconn ip:port` for TCP).
* The executor is pushed to `/data/local/tmp` on the device.
* A serial console (via `console`/`console_cmd`) makes crash capture far more
  reliable than the `dmesg -w` fallback.

## 6. Run

```bash
hdc list targets                       # confirm the device/emulator is visible
./bin/syz-manager -config=openharmony_emulator.cfg
# status page: http://127.0.0.1:56741
```

Add `-debug` to syz-manager to see every `hdc` invocation while bringing a new
target up.

## 7. Kernel attack surface → descriptions

Mapping the kernel-level leads from this research line to the syzkaller
descriptions that exercise them:

| Lead (workspace) | Device / subsystem | Description | Notes |
|---|---|---|---|
| purgeable-ashmem fileless-unpin NULL deref | `/dev/ashmem` | `dev_ashmem.txt` + `dev_ashmem_ohos.txt` | OHOS `SET_PURGEABLE`/`UNPIN` extensions added here. |
| xpm XOM region / owner-id validation | `/dev/xpm` | `dev_ohos_xpm.txt` | reachable by a normal process. |
| dec path-rule parser (CWE-862 leads) | `/dev/dec` | `dev_ohos_dec.txt` | SELinux-gated on retail; fuzz permissive. |
| code_sign cert-chain ingest | `/dev/code_sign` | `dev_ohos_code_sign.txt` | SELinux `key_enable` gated; fuzz permissive. |
| dma-buf heap off-by-one (`vmf->pgoff`) | `/dev/dma_heap/*` | mainline `dev_dma_heap.txt` | already described upstream. |
| Maleoon / Mali GPU submit path | `/dev/mali`, `/dev/hvgr*` | mainline `dev_mali.txt` / `dev_bifrost.txt` | Mali covered upstream; **Maleoon KMD is closed-source** and needs RE before it can be described. |
| enhanced binder | `/dev/binder` | mainline `dev_binder.txt` | OHOS binder is Android-derived. |
| jit_memory W^X rb-tree UAF | HCK hooks (`mmap`/`mprotect`/`exit`) | base `mmap`/`mprotect` | reached indirectly via the JS/WebView renderer; needs a dedicated harness, not plain syscall fuzzing. |

## 8. Extending

To add another OpenHarmony driver:

1. Find its ioctl definitions in the OpenHarmony kernel sources (e.g.
   `kernel_linux_common_modules/<module>/…`).
2. Write a `sys/linux/dev_ohos_<name>.txt` describing the `openat$…` + `ioctl$…`
   calls and arg structs (mirror the four files above).
3. Compute the ioctl command numbers and struct sizes from the source and put
   them in `sys/linux/dev_ohos_<name>.txt.const` with `meta noextract` and
   `meta arches["amd64", "arm64"]`. (A one-file C program that `#include`s or
   re-declares the struct and prints `_IOW(...)` etc. is the reliable way.)
4. Regenerate + validate: `make descriptions`, then confirm the new
   `openat$…`/`ioctl$…` names appear in the `linux/arm64` target.
