#!/usr/bin/env python3
import os
import sys
import json
import time
import subprocess

# ---- PATH CONFIG (adjust if needed) ----

BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # test1/controller
ROOT_DIR = os.path.abspath(os.path.join(BASE_DIR, ".."))

JSON_PATH = os.path.join(ROOT_DIR, "json", "file_system.json")

MODULE_PATH = os.path.join(ROOT_DIR, "reader", "fs_injector.ko")
MODULE_NAME = "fs_injector"
SYSFS_BASE = f"/sys/module/{MODULE_NAME}/parameters"


# ---- HELPER: filesystem metadata ----

def load_fs_metadata():
    """
    Load file_system.json and index entries by syscall name.
    Only entries with category == "file" are kept.
    """
    with open(JSON_PATH, "r") as f:
        data = json.load(f)

    by_name = {}
    for entry in data:
        if entry.get("category") != "file":
            continue
        name = entry.get("name")
        if not name:
            continue
        by_name[name] = entry
    return by_name


# ---- HELPER: find running server and its mode ----

def find_server_pid_explicit():
    """
    If user gave --pid=PID, parse it.
    """
    for arg in sys.argv[1:]:
        if arg.startswith("--pid="):
            try:
                return int(arg.split("=", 1)[1])
            except ValueError:
                print(f"[CTRL] Invalid --pid value: {arg}", file=sys.stderr)
                sys.exit(1)
    return None


def find_server_pid_auto():
    """
    Automatically find a running 'server' process using pidof.
    If multiple, pick the highest PID (most recent).
    """
    try:
        out = subprocess.check_output(["pidof", "server"], text=True).strip()
    except subprocess.CalledProcessError:
        return None

    if not out:
        return None

    pids = [int(p) for p in out.split()]
    return max(pids)


def read_server_mode_from_cmdline(pid):
    """
    Read /proc/<pid>/cmdline and decode the --mode=<name> argument.
    """
    path = f"/proc/{pid}/cmdline"
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        raise RuntimeError(f"Process {pid} disappeared or /proc not readable")

    parts = raw.split(b"\0")
    for part in parts:
        if part.startswith(b"--mode="):
            mode = part[len(b"--mode="):].decode("utf-8", errors="replace")
            return mode

    raise RuntimeError(f"No --mode= argument found in cmdline for PID {pid}")


# ---- HELPER: kernel module management ----

def rmmod_module():
    subprocess.run(["rmmod", MODULE_NAME],
                   stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)


def insmod_module(symbol, pid, max_inj=1000, unsafe=1):
    """
    Insert fs_injector.ko with given symbol and target PID.
    """
    rmmod_module()
    args = [
        "insmod",
        MODULE_PATH,
        f"target_symbol={symbol}",
        f"target_pid={pid}",
        f"inject_errno=1",       # will be changed per variant
        f"max_injections={max_inj}",
        f"unsafe_mode={unsafe}",
    ]
    print(f"[CTRL] insmod: {' '.join(args)}")
    subprocess.run(args, check=True)
    # small delay to let sysfs params appear
    time.sleep(0.1)


def read_param(name):
    path = os.path.join(SYSFS_BASE, name)
    with open(path, "r") as f:
        return int(f.read().strip())


def write_param(name, value):
    path = os.path.join(SYSFS_BASE, name)
    with open(path, "w") as f:
        f.write(f"{value}\n")


def wait_for_injection(prev_count, timeout_sec=5.0):
    """
    Poll injections_done until it increases beyond prev_count or timeout.
    """
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            current = read_param("injections_done")
        except FileNotFoundError:
            time.sleep(0.05)
            continue
        if current > prev_count:
            return True
        time.sleep(0.05)
    return False


# ---- MAIN CONTROL FLOW ----

def main():
    # 1) Find server PID
    pid = find_server_pid_explicit()
    if pid is None:
        pid = find_server_pid_auto()

    if pid is None:
        print("[CTRL] ERROR: No running 'server' process found. "
              "Start './server --mode=...' first.", file=sys.stderr)
        sys.exit(1)

    print(f"[CTRL] Using server PID: {pid}")

    # 2) Detect mode from /proc/<pid>/cmdline
    try:
        mode = read_server_mode_from_cmdline(pid)
    except RuntimeError as e:
        print(f"[CTRL] ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[CTRL] Detected server mode: {mode}")

    # 3) Load FS syscall metadata and find matching entry
    fs_meta = load_fs_metadata()

    if mode not in fs_meta:
        print(f"[CTRL] ERROR: No metadata entry for syscall '{mode}' "
              f"in {JSON_PATH}", file=sys.stderr)
        sys.exit(1)

    entry = fs_meta[mode]
    symbol = entry.get("symbol_to_probe") or entry.get("canonical_guess")
    if not symbol:
        print(f"[CTRL] ERROR: No symbol_to_probe/canonical_guess for '{mode}'",
              file=sys.stderr)
        sys.exit(1)

    variants = entry.get("error_variants") or []
    if not variants:
        print(f"[CTRL] WARNING: No error_variants for '{mode}', nothing to do.")
        sys.exit(0)

    print(f"[CTRL] Syscall '{mode}' has {len(variants)} error variants.")
    print(f"[CTRL] Will hook kernel symbol: {symbol}")

    # 4) Load kernel module for this symbol + PID
    try:
        insmod_module(symbol, pid, max_inj=1000, unsafe=1)
    except subprocess.CalledProcessError as e:
        print(f"[CTRL] ERROR: insmod failed: {e}", file=sys.stderr)
        sys.exit(1)

    # 5) Iterate over error variants
    try:
        for idx, ev in enumerate(variants):
            errno_num = ev.get("errno_num")
            errno_name = ev.get("errno_name")
            if errno_num is None or errno_num <= 0:
                print(f"[CTRL]  Variant {idx}: invalid errno_num, skipping")
                continue

            print(f"[CTRL]  Variant {idx+1}/{len(variants)}: "
                  f"{errno_name}({errno_num})")

            try:
                prev = read_param("injections_done")
            except FileNotFoundError:
                print("[CTRL]  ERROR: injections_done not available; "
                      "module not loaded?", file=sys.stderr)
                break

            # Set errno to inject
            write_param("inject_errno", errno_num)

            ok = wait_for_injection(prev, timeout_sec=10.0)
            if not ok:
                print(f"[CTRL]  WARNING: timeout waiting for injection "
                      f"for errno={errno_num}")
                continue

            print(f"[CTRL]  Injection observed for errno={errno_num}")
    finally:
        # 6) Always unload module at end
        rmmod_module()
        print("[CTRL] Done. Module unloaded.")


if __name__ == "__main__":
    main()

