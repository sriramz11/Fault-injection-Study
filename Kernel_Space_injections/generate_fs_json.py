#!/usr/bin/env python3
import json
import errno
from pathlib import Path

# --------------------------------------------------------------------
# 1. The full set of modes supported by server.c
# --------------------------------------------------------------------
MODES = [
    "access",
    "chdir",
    "chmod",
    "chown",
    "close",
    "copy_file_range",
    "faccessat2",
    "fallocate",
    "fchdir",
    "fchmod",
    "fchmodat",
    "fchown",
    "fchownat",
    "fdatasync",
    "fsconfig",
    "fsetxattr",
    "fsmount",
    "fsopen",
    "fspick",
    "fstat",
    "fstatfs",
    "fsync",
    "ftruncate",
    "getdents",
    "getdents64",
    "lchown",
    "link",
    "linkat",
    "lstat",
    "mkdir",
    "mkdirat",
    "mknod",
    "mknodat",
    "mount",
    "mount_setattr",
    "open",
    "open_by_handle_at",
    "open_tree",
    "openat",
    "openat2",
    "readahead",
    "readlink",
    "readlinkat",
    "rename",
    "renameat",
    "renameat2",
    "rmdir",
    "sendfile",
    "splice",
    "stat",
    "statfs",
    "statx",
    "symlink",
    "symlinkat",
    "sync",
    "tee",
    "truncate",
    "unlink",
    "unlinkat",
    "utime",
    "utimensat",
    "utimes",
    "vmsplice",
]

# --------------------------------------------------------------------
# 2. x86_64 syscall symbol mapping (Ubuntu 6.8 x86_64)
#    Names taken from syscall_64.tbl and mount/fsopen sources. :contentReference[oaicite:1]{index=1}
# --------------------------------------------------------------------
SYSCALL_SYMBOLS = {
    "access":           "__x64_sys_access",
    "chdir":            "__x64_sys_chdir",
    "chmod":            "__x64_sys_chmod",
    "chown":            "__x64_sys_chown",
    "close":            "__x64_sys_close",
    "copy_file_range":  "__x64_sys_copy_file_range",
    "faccessat2":       "__x64_sys_faccessat2",
    "fallocate":        "__x64_sys_fallocate",
    "fchdir":           "__x64_sys_fchdir",
    "fchmod":           "__x64_sys_fchmod",
    "fchmodat":         "__x64_sys_fchmodat",
    "fchown":           "__x64_sys_fchown",
    "fchownat":         "__x64_sys_fchownat",
    "fdatasync":        "__x64_sys_fdatasync",
    "fsconfig":         "__x64_sys_fsconfig",
    "fsetxattr":        "__x64_sys_fsetxattr",
    "fsmount":          "__x64_sys_fsmount",
    "fsopen":           "__x64_sys_fsopen",
    "fspick":           "__x64_sys_fspick",
    "fstat":            "__x64_sys_newfstat",
    "fstatfs":          "__x64_sys_fstatfs",
    "fsync":            "__x64_sys_fsync",
    "ftruncate":        "__x64_sys_ftruncate",
    "getdents":         "__x64_sys_getdents",
    "getdents64":       "__x64_sys_getdents64",
    "lchown":           "__x64_sys_lchown",
    "link":             "__x64_sys_link",
    "linkat":           "__x64_sys_linkat",
    "lstat":            "__x64_sys_newlstat",
    "mkdir":            "__x64_sys_mkdir",
    "mkdirat":          "__x64_sys_mkdirat",
    "mknod":            "__x64_sys_mknod",
    "mknodat":          "__x64_sys_mknodat",
    "mount":            "__x64_sys_mount",
    "mount_setattr":    "__x64_sys_mount_setattr",
    "open":             "__x64_sys_open",
    "open_by_handle_at":"__x64_sys_open_by_handle_at",
    "open_tree":        "__x64_sys_open_tree",
    "openat":           "__x64_sys_openat",
    "openat2":          "__x64_sys_openat2",
    "readahead":        "__x64_sys_readahead",
    "readlink":         "__x64_sys_readlink",
    "readlinkat":       "__x64_sys_readlinkat",
    "rename":           "__x64_sys_rename",
    "renameat":         "__x64_sys_renameat",
    "renameat2":        "__x64_sys_renameat2",
    "rmdir":            "__x64_sys_rmdir",
    "sendfile":         "__x64_sys_sendfile",
    "splice":           "__x64_sys_splice",
    "stat":             "__x64_sys_newstat",
    "statfs":           "__x64_sys_statfs",
    "statx":            "__x64_sys_statx",
    "symlink":          "__x64_sys_symlink",
    "symlinkat":        "__x64_sys_symlinkat",
    "sync":             "__x64_sys_sync",
    "tee":              "__x64_sys_tee",
    "truncate":         "__x64_sys_truncate",
    "unlink":           "__x64_sys_unlink",
    "unlinkat":         "__x64_sys_unlinkat",
    "utime":            "__x64_sys_utime",
    "utimensat":        "__x64_sys_utimensat",
    "utimes":           "__x64_sys_utimes",
    "vmsplice":         "__x64_sys_vmsplice",
}

# --------------------------------------------------------------------
# 3. Candidate errno set for FS / mount / IO syscalls
#    (Enough variety for fault injection research.)
# --------------------------------------------------------------------
ERRNO_NAMES = [
    "EPERM",
    "EACCES",
    "EBADF",
    "EFAULT",
    "EFBIG",
    "EINTR",
    "EINVAL",
    "EIO",
    "EISDIR",
    "ELOOP",
    "EMFILE",
    "ENAMETOOLONG",
    "ENFILE",
    "ENODEV",
    "ENOENT",
    "ENOMEM",
    "ENOSPC",
    "ENOTDIR",
    "ENOTEMPTY",
    "ENXIO",
    "EOVERFLOW",
    "EROFS",
    "ETIMEDOUT",
    "ETXTBSY",
    "EXDEV",
    "EBUSY",
    "EOPNOTSUPP",
]

def build_error_variants():
    variants = []
    for name in ERRNO_NAMES:
        num = getattr(errno, name, None)
        if num is None:
            continue
        variants.append({
            "errno_name": name,
            "errno_num": num,
            "kernel_ret": -num,
            "userspace_return_pattern": f"-1 and errno set to {num}",
            "source": "candidates",
            "note": "automatic candidate list",
            "forceable": True,
            "side_effects": "maybe",
            "safety_level": "low",
        })
    return variants

# --------------------------------------------------------------------
# 4. Build full JSON structure
# --------------------------------------------------------------------
def main():
    base = Path(__file__).resolve().parent
    json_dir = base / "json"
    json_dir.mkdir(exist_ok=True)
    out_path = json_dir / "file_system.json"

    variants = build_error_variants()
    entries = []

    for name in MODES:
        sym = SYSCALL_SYMBOLS.get(name)
        entry = {
            "name": name,
            "canonical_guess": sym,
            "symbol_to_probe": None,          # controller will fill / override if needed
            "probeable": bool(sym),
            "category": "file",               # treat all as FS for this project
            "nr_args": 0,                     # not needed for return-value injection
            "args": [],
            "return_type": "long",
            "forceable_by_type": True,
            "side_effects_note": "maybe",
            "error_variants": variants,
            "probe_commands_suggestion": None,
            "notes": "Generated by generate_fs_json.py for FS fault-injection project.",
        }
        entries.append(entry)

    with out_path.open("w") as f:
        json.dump(entries, f, indent=2, sort_keys=False)

    print(f"[GEN] Wrote {len(entries)} syscall entries to {out_path}")

if __name__ == "__main__":
    main()

