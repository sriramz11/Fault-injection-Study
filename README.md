# Fault-injection-Study
syscall fault-injection framework using kretprobes. The framework injects controlled errno failures into selected filesystem syscalls, executes workloads inside a sandbox, and analyzes failure propagation, cascades, and error realism. Extensive way to study syscalls and error codes generated. Sometimes makes you think kernel code is not perfect.
---

## Motivation

Error-handling paths in operating systems are rarely exercised under normal workloads,
yet they are a common source of bugs and system instability.

Filesystem syscalls are particularly interesting because:
- They interact with global namespace state (paths, directories, permissions)
- They expose a rich and meaningful set of error codes
- They frequently produce cascading failures when assumptions break
- They can be safely isolated using a sandbox directory

This project provides a systematic way to explore these behaviors.

---

## Key Contributions

- Kernel-level fault injection using `kretprobes`
- Metadata-driven error selection via JSON
- Strict PID-based injection isolation
- Sandbox-based experimental design
- Classification of syscalls into path-centric, FD-centric, and hybrid categories
- Quantitative analysis of cascade length and error realism (EDI)

---

## System Architecture
<img width="1562" height="644" alt="image" src="https://github.com/user-attachments/assets/ad7cbfae-5cc8-48ca-96b2-91f4726129c1" />

The framework consists of three main components:

### 1. Server (`server.c`)
- Executes filesystem workloads in distinct modes
- Each mode targets a specific syscall family
- All operations are confined to `fs_sandbox/`

### 2. Controller (`controller.py`)
- Reads syscall error metadata from JSON
- Detects the active server mode
- Configures the kernel injector with target PID, syscall symbol, and errno

### 3. Kernel Injector (`fs_injector.ko`)
- Attaches `kretprobes` to selected syscall return paths
- Overrides return values with injected `errno`
- Ensures injection affects only the target process

---

## Sandbox Design

All filesystem operations are restricted to a dedicated directory:
This sandbox ensures:
- No real filesystem data is modified
- Experiments are repeatable
- Destructive syscalls (unlink, rename, rmdir) are safe
- Kernel stability is preserved

The sandbox is persistent across runs, which intentionally exposes
state-related anomalies such as existence-based cascades.

---

## Fault Injection Model

Faults are defined using a metadata-driven approach:

- Each syscall maps to a set of possible error variants
- Errors are injected one at a time
- Injection occurs at syscall return using `kretprobes`
- No syscall code or kernel source is modified

This design enables controlled exploration of rarely executed error paths.

---

## Analysis Metrics

### Cascade Length
Measures how many consecutive failures occur after a single injected fault.

- Path-centric syscalls often show long cascades
- FD-centric syscalls usually contain failures locally

### Error Distortion Index (EDI)
Measures how realistic an injected error is relative to the workload and environment.

- Low EDI: Natural filesystem errors (EEXIST, ENOENT, EACCES)
- High EDI: Semantically invalid errors (EADDRINUSE, ENETUNREACH)

---

## Key Findings

- Path-based syscalls propagate failures across multiple operations
- FD-based syscalls isolate failures to a single call
- Hybrid syscalls (`open*`) bridge path and FD domains
- Unrealistic error injection distorts behavior and must be filtered
- Experimental design strongly influences observed error distributions

---

## Dangerous Syscalls (Excluded)

Syscalls operating on mount and superblock state were intentionally excluded:

- `fsconfig`
- `fsopen`
- `fsmount`
- `mount_setattr`
- `open_by_handle_at`

These syscalls interact with global kernel state and can destabilize the OS
if fault-injected without container-level isolation.

---

## Limitations

- Sandbox persistence biases results toward existence-related errors
- Error sets are broader than realistic for some syscalls
- Only return-value fault injection is performed
- Single filesystem type and kernel version tested

---

## Future Work

- Reset or randomize sandbox paths per experiment
- Restrict error variants per syscall based on realism
- Extend analysis to multi-fault scenarios
- Explore mount-level fault injection in containerized environments
- Integrate automated cascade and EDI scoring

---

## Requirements

- Linux kernel with kprobe support
- Root privileges
- Python 3
- GCC / Make

---

## Disclaimer

This project performs kernel-level fault injection.
It should only be run in a controlled environment such as a virtual machine.
Do **not** run on production systems.

---

## License

This project is intended for research and educational use.
