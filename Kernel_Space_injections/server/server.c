#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <linux/stat.h>
#include <linux/openat2.h>
#include <sys/sendfile.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <utime.h>
#include <sys/mount.h>
#include <time.h>


/* ============================================================
   MODES — MUST MATCH file_system.json "name" FIELDS
   ============================================================ */

static const char *modes[] = {
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
    "vmsplice"
};

enum { MODE_COUNT = sizeof(modes) / sizeof(modes[0]) };


/* ============================================================
   UTILITIES
   ============================================================ */

static void usage(void)
{
    printf("Usage: ./server --mode=<name>\n");
    printf("Available modes:\n");
    for (int i = 0; i < MODE_COUNT; i++)
        printf("  %s\n", modes[i]);
}

static int mode_index(const char *arg)
{
    for (int i = 0; i < MODE_COUNT; i++) {
        if (strcmp(arg, modes[i]) == 0)
            return i;
    }
    return -1;
}

static void log_fail(const char *sc, const char *detail, int ret)
{
    printf("[SERVER] %s FAIL ret=%d errno=%d (%s) detail=%s\n",
           sc, ret, errno, strerror(errno),
           detail ? detail : "");
    fflush(stdout);
}

static void sandbox_init(void)
{
    mkdir("fs_sandbox", 0700);
    if (chdir("fs_sandbox") < 0) {
        perror("chdir fs_sandbox");
        exit(1);
    }

    /* Basic files */
    int fd = open("file_ok.txt", O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd >= 0) {
        write(fd, "hello\n", 6);
        close(fd);
    }

    int fd2 = open("file_ro.txt", O_CREAT | O_WRONLY | O_TRUNC, 0400);
    if (fd2 >= 0) {
        write(fd2, "read only\n", 10);
        close(fd2);
    }

    /* Log / temp files */
    int fd3 = open("tmp_trunc.log", O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd3 >= 0) {
        write(fd3, "truncate\n", 9);
        close(fd3);
    }

    int fd4 = open("tmp_fsync.log", O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd4 >= 0) {
        write(fd4, "fsync\n", 6);
        close(fd4);
    }

    int fd5 = open("tmp_fdatasync.log", O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd5 >= 0) {
        write(fd5, "fdatasync\n", 10);
        close(fd5);
    }

    int fd6 = open("tmp_copy_src.bin", O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd6 >= 0) {
        char buf[1024];
        memset(buf, 'A', sizeof(buf));
        write(fd6, buf, sizeof(buf));
        close(fd6);
    }

    /* Symlinks */
    symlink("file_ok.txt", "link1");
    symlink("missing_target", "broken1");

    /* Directories */
    mkdir("dir1", 0700);
    mkdir("dir1/deep", 0700);
    mkdir("tmp", 0700);
    mkdir("tree", 0700);
    mkdir("tree/a", 0700);
    mkdir("tree/b", 0700);
    mkdir("tree/c", 0700);
    mkdir("rmdir_test", 0700);

    int fd7 = open("tmp/unlink_me", O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd7 >= 0) {
        write(fd7, "unlink data\n", 12);
        close(fd7);
    }

    int fd8 = open("tmp/sendfile_src", O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd8 >= 0) {
        char buf2[2048];
        memset(buf2, 'B', sizeof(buf2));
        write(fd8, buf2, sizeof(buf2));
        close(fd8);
    }
}

/* ============================================================
   SCENARIO FUNCTIONS — ONE PER SYSCALL
   ============================================================ */

/* 0: access */
static void sc_access(void)
{
    int ret = access("file_ok.txt", R_OK);
    if (ret < 0) log_fail("access", "file_ok.txt", ret);
}

/* 1: chdir */
static void sc_chdir(void)
{
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd)))
        return;
    int ret = chdir("dir1");
    if (ret < 0) {
        log_fail("chdir", "dir1", ret);
        return;
    }
    /* restore cwd so repeated calls behave similarly */
    chdir(cwd);
}

/* 2: chmod */
static void sc_chmod(void)
{
    int ret = chmod("file_ok.txt", 0600);
    if (ret < 0) log_fail("chmod", "file_ok.txt", ret);
}

/* 3: chown */
static void sc_chown(void)
{
    int ret = chown("file_ok.txt", getuid(), getgid());
    if (ret < 0) log_fail("chown", "file_ok.txt", ret);
}

/* 4: close */
static void sc_close(void)
{
    int fd = open("file_ok.txt", O_RDONLY);
    if (fd < 0) return;
    int ret = close(fd);
    if (ret < 0) log_fail("close", "file_ok.txt", ret);
}

/* 5: copy_file_range */
static void sc_copy_file_range(void)
{
#ifdef SYS_copy_file_range
    int src = open("tmp_copy_src.bin", O_RDONLY);
    int dst = open("tmp_copy_dst.bin", O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (src < 0 || dst < 0) {
        if (src >= 0) close(src);
        if (dst >= 0) close(dst);
        return;
    }
    loff_t off = 0;
    ssize_t ret = syscall(SYS_copy_file_range, src, &off, dst, NULL, 1024, 0);
    if (ret < 0) log_fail("copy_file_range", "tmp_copy_src.bin", (int)ret);
    close(src);
    close(dst);
#else
    log_fail("copy_file_range", "unavailable", -1);
#endif
}

/* 6: faccessat2 */
static void sc_faccessat2(void)
{
#ifdef SYS_faccessat2
    int ret = syscall(SYS_faccessat2, AT_FDCWD, "file_ok.txt", R_OK, 0);
    if (ret < 0) log_fail("faccessat2", "file_ok.txt", ret);
#else
    log_fail("faccessat2", "unavailable", -1);
#endif
}

/* 7: fallocate */
static void sc_fallocate(void)
{
#ifdef SYS_fallocate
    int fd = open("tmp/falloc.bin", O_CREAT | O_RDWR, 0600);
    if (fd < 0) return;
    int ret = syscall(SYS_fallocate, fd, 0, 0, 4096);
    if (ret < 0) log_fail("fallocate", "tmp/falloc.bin", ret);
    close(fd);
#else
    log_fail("fallocate", "unavailable", -1);
#endif
}

/* 8: fchdir */
static void sc_fchdir(void)
{
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd)))
        return;
    int fd = open("dir1", O_RDONLY | O_DIRECTORY);
    if (fd < 0) return;
    int ret = fchdir(fd);
    if (ret < 0) log_fail("fchdir", "dir1", ret);
    close(fd);
    chdir(cwd);
}

/* 9: fchmod */
static void sc_fchmod(void)
{
    int fd = open("file_ok.txt", O_RDONLY);
    if (fd < 0) return;
    int ret = fchmod(fd, 0644);
    if (ret < 0) log_fail("fchmod", "file_ok.txt", ret);
    close(fd);
}

/* 10: fchmodat */
static void sc_fchmodat(void)
{
    int dfd = open(".", O_RDONLY);
    if (dfd < 0) return;
    int ret = fchmodat(dfd, "file_ok.txt", 0644, 0);
    if (ret < 0) log_fail("fchmodat", "file_ok.txt", ret);
    close(dfd);
}

/* 11: fchown */
static void sc_fchown(void)
{
    int fd = open("file_ok.txt", O_RDONLY);
    if (fd < 0) return;
    int ret = fchown(fd, getuid(), getgid());
    if (ret < 0) log_fail("fchown", "file_ok.txt", ret);
    close(fd);
}

/* 12: fchownat */
static void sc_fchownat(void)
{
    int dfd = open(".", O_RDONLY);
    if (dfd < 0) return;
    int ret = fchownat(dfd, "file_ok.txt", getuid(), getgid(), 0);
    if (ret < 0) log_fail("fchownat", "file_ok.txt", ret);
    close(dfd);
}

/* 13: fdatasync */
static void sc_fdatasync(void)
{
    int fd = open("tmp_fdatasync.log", O_CREAT | O_WRONLY | O_APPEND, 0600);
    if (fd < 0) return;
    write(fd, "fdatasync\n", 10);
    int ret = fdatasync(fd);
    if (ret < 0) log_fail("fdatasync", "tmp_fdatasync.log", ret);
    close(fd);
}

/* 14: fsconfig — not exercised (needs real mount plumbing) */
static void sc_fsconfig(void)
{
    log_fail("fsconfig", "not exercised in server", -1);
}

/* 15: fsetxattr */
static void sc_fsetxattr(void)
{
#ifdef SYS_fsetxattr
    int fd = open("file_ok.txt", O_RDONLY);
    if (fd < 0) return;
    const char *name = "user.test";
    const char *value = "abc";
    int ret = syscall(SYS_fsetxattr, fd, name, value, strlen(value), 0);
    if (ret < 0) log_fail("fsetxattr", "file_ok.txt", ret);
    close(fd);
#else
    log_fail("fsetxattr", "unavailable", -1);
#endif
}

/* 16: fsmount — not exercised */
static void sc_fsmount(void)
{
    log_fail("fsmount", "not exercised in server", -1);
}

/* 17: fsopen — not exercised */
static void sc_fsopen(void)
{
    log_fail("fsopen", "not exercised in server", -1);
}

/* 18: fspick — not exercised */
static void sc_fspick(void)
{
    log_fail("fspick", "not exercised in server", -1);
}

/* 19: fstat */
static void sc_fstat(void)
{
    int fd = open("file_ok.txt", O_RDONLY);
    if (fd < 0) return;
    struct stat st;
    int ret = fstat(fd, &st);
    if (ret < 0) log_fail("fstat", "file_ok.txt", ret);
    close(fd);
}

/* 20: fstatfs */
static void sc_fstatfs(void)
{
    int fd = open(".", O_RDONLY);
    if (fd < 0) return;
    struct statfs s;
    int ret = fstatfs(fd, &s);
    if (ret < 0) log_fail("fstatfs", ".", ret);
    close(fd);
}

/* 21: fsync */
static void sc_fsync(void)
{
    int fd = open("tmp_fsync.log", O_CREAT | O_WRONLY | O_APPEND, 0600);
    if (fd < 0) return;
    write(fd, "fsync\n", 6);
    int ret = fsync(fd);
    if (ret < 0) log_fail("fsync", "tmp_fsync.log", ret);
    close(fd);
}

/* 22: ftruncate */
static void sc_ftruncate(void)
{
    int fd = open("tmp_trunc.log", O_RDWR);
    if (fd < 0) return;
    int ret = ftruncate(fd, 0);
    if (ret < 0) log_fail("ftruncate", "tmp_trunc.log", ret);
    close(fd);
}

/* 23: getdents */
static void sc_getdents(void)
{
#ifdef SYS_getdents
    int fd = open(".", O_RDONLY | O_DIRECTORY);
    if (fd < 0) return;
    char buf[4096];
    int ret = syscall(SYS_getdents, fd, buf, sizeof(buf));
    if (ret < 0) log_fail("getdents", ".", ret);
    close(fd);
#else
    log_fail("getdents", "unavailable", -1);
#endif
}

/* 24: getdents64 */
static void sc_getdents64(void)
{
#ifdef SYS_getdents64
    int fd = open(".", O_RDONLY | O_DIRECTORY);
    if (fd < 0) return;
    char buf[4096];
    int ret = syscall(SYS_getdents64, fd, buf, sizeof(buf));
    if (ret < 0) log_fail("getdents64", ".", ret);
    close(fd);
#else
    log_fail("getdents64", "unavailable", -1);
#endif
}

/* 25: lchown */
static void sc_lchown(void)
{
    int ret = lchown("link1", getuid(), getgid());
    if (ret < 0) log_fail("lchown", "link1", ret);
}

/* 26: link */
static void sc_link(void)
{
    unlink("hardlink1");
    int ret = link("file_ok.txt", "hardlink1");
    if (ret < 0) {
        log_fail("link", "file_ok.txt -> hardlink1", ret);
        return;
    }
    unlink("hardlink1");
}

/* 27: linkat */
static void sc_linkat(void)
{
    unlink("hardlink2");
    int ret = linkat(AT_FDCWD, "file_ok.txt",
                     AT_FDCWD, "hardlink2", 0);
    if (ret < 0) {
        log_fail("linkat", "file_ok.txt -> hardlink2", ret);
        return;
    }
    unlink("hardlink2");
}

/* 28: lstat */
static void sc_lstat(void)
{
    struct stat st;
    int ret = lstat("link1", &st);
    if (ret < 0) log_fail("lstat", "link1", ret);
}

/* 29: mkdir */
static void sc_mkdir(void)
{
    int ret = mkdir("tmp/mkdir_test", 0700);
    if (ret < 0)
        log_fail("mkdir", "tmp/mkdir_test", ret);

    int ret2 = rmdir("tmp/mkdir_test");
    if (ret2 < 0)
        log_fail("rmdir", "tmp/mkdir_test", ret2);
}

/* 30: mkdirat */
static void sc_mkdirat(void)
{
    int dfd = open("tmp", O_RDONLY);
    if (dfd < 0) return;
    mkdirat(dfd, "mkdirat_test", 0700);
    int ret = unlinkat(dfd, "mkdirat_test", AT_REMOVEDIR);
    if (ret < 0) log_fail("mkdirat", "tmp/mkdirat_test", ret);
    close(dfd);
}

/* 31: mknod */
static void sc_mknod(void)
{
    unlink("tmp/node1");
    int ret = mknod("tmp/node1", S_IFREG | 0600, 0);
    if (ret < 0) {
        log_fail("mknod", "tmp/node1", ret);
        return;
    }
    unlink("tmp/node1");
}

/* 32: mknodat */
static void sc_mknodat(void)
{
    int dfd = open("tmp", O_RDONLY);
    if (dfd < 0) return;
    unlinkat(dfd, "node2", 0);
    int ret = mknodat(dfd, "node2", S_IFREG | 0600, 0);
    if (ret < 0) {
        log_fail("mknodat", "tmp/node2", ret);
        close(dfd);
        return;
    }
    unlinkat(dfd, "node2", 0);
    close(dfd);
}

/* 33: mount — not exercised (too dangerous) */
static void sc_mount(void)
{
    log_fail("mount", "not exercised in server", -1);
}

/* 34: mount_setattr — not exercised */
static void sc_mount_setattr(void)
{
    log_fail("mount_setattr", "not exercised in server", -1);
}

/* 35: open */
static void sc_open(void)
{
    int fd = open("file_ok.txt", O_RDONLY);
    if (fd < 0) log_fail("open", "file_ok.txt", fd);
    else close(fd);
}

/* 36: open_by_handle_at — not exercised */
static void sc_open_by_handle_at(void)
{
    log_fail("open_by_handle_at", "not exercised in server", -1);
}

/* 37: open_tree */
static void sc_open_tree(void)
{
#ifdef SYS_open_tree
    int ret = syscall(SYS_open_tree, AT_FDCWD, "tree", 0);
    if (ret < 0) log_fail("open_tree", "tree", ret);
    else close(ret);
#else
    log_fail("open_tree", "unavailable", -1);
#endif
}

/* 38: openat */
static void sc_openat(void)
{
    int dfd = open("dir1", O_RDONLY);
    if (dfd < 0) return;
    int fd = openat(dfd, "deep", O_RDONLY | O_DIRECTORY);
    if (fd < 0) log_fail("openat", "dir1/deep", fd);
    if (fd >= 0) close(fd);
    close(dfd);
}

/* 39: openat2 */
static void sc_openat2(void)
{
#ifdef SYS_openat2
    struct open_how how = { .flags = O_RDONLY };
    int fd = syscall(SYS_openat2, AT_FDCWD, "file_ok.txt", &how, sizeof(how));
    if (fd < 0) log_fail("openat2", "file_ok.txt", fd);
    else close(fd);
#else
    log_fail("openat2", "unavailable", -1);
#endif
}

/* 40: readahead */
static void sc_readahead(void)
{
#ifdef SYS_readahead
    int fd = open("file_ok.txt", O_RDONLY);
    if (fd < 0) return;
    int ret = syscall(SYS_readahead, fd, 0, 4096);
    if (ret < 0) log_fail("readahead", "file_ok.txt", ret);
    close(fd);
#else
    log_fail("readahead", "unavailable", -1);
#endif
}

/* 41: readlink */
static void sc_readlink(void)
{
    char b[128];
    int ret = readlink("link1", b, sizeof(b)-1);
    if (ret < 0) log_fail("readlink", "link1", ret);
}

/* 42: readlinkat */
static void sc_readlinkat(void)
{
    int dfd = open(".", O_RDONLY);
    if (dfd < 0) return;
    char b[128];
    int ret = readlinkat(dfd, "link1", b, sizeof(b)-1);
    if (ret < 0) log_fail("readlinkat", "link1", ret);
    close(dfd);
}

/* 43: rename */
static void sc_rename(void)
{
    rename("tmp/unlink_me", "tmp/unlink_tmp");
    int ret = rename("tmp/unlink_tmp", "tmp/unlink_me");
    if (ret < 0) log_fail("rename", "tmp", ret);
}

/* 44: renameat */
static void sc_renameat(void)
{
    int dfd = open("tmp", O_RDONLY);
    if (dfd < 0) return;
    renameat(dfd, "unlink_me", dfd, "unlink_tmp2");
    int ret = renameat(dfd, "unlink_tmp2", dfd, "unlink_me");
    if (ret < 0) log_fail("renameat", "tmp", ret);
    close(dfd);
}

/* 45: renameat2 */
static void sc_renameat2(void)
{
#ifdef SYS_renameat2
    int dfd = open("tmp", O_RDONLY);
    if (dfd < 0) return;
    int ret = syscall(SYS_renameat2, dfd, "unlink_me", dfd, "unlink_tmp3", 0);
    if (ret < 0) log_fail("renameat2", "tmp/unlink_me", ret);
    close(dfd);
#else
    log_fail("renameat2", "unavailable", -1);
#endif
}

/* 46: rmdir */
static void sc_rmdir(void)
{
    mkdir("rmdir_test", 0700);
    int ret = rmdir("rmdir_test");
    if (ret < 0) log_fail("rmdir", "rmdir_test", ret);
}

/* 47: sendfile */
static void sc_sendfile(void)
{
    int src = open("tmp/sendfile_src", O_RDONLY);
    int dst = open("tmp/sendfile_dst", O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (src < 0 || dst < 0) {
        if (src >= 0) close(src);
        if (dst >= 0) close(dst);
        return;
    }
    off_t offset = 0;
    ssize_t ret = sendfile(dst, src, &offset, 1024);
    if (ret < 0) log_fail("sendfile", "tmp/sendfile_src", (int)ret);
    close(src);
    close(dst);
}

/* 48: splice */
static void sc_splice(void)
{
#ifdef SYS_splice
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        log_fail("splice", "pipe", -1);
        return;
    }
    int fd = open("file_ok.txt", O_RDONLY);
    if (fd < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return;
    }
    ssize_t ret = syscall(SYS_splice, fd, NULL, pipefd[1], NULL, 64, 0);
    if (ret < 0) log_fail("splice", "file_ok.txt", (int)ret);
    close(fd);
    close(pipefd[0]);
    close(pipefd[1]);
#else
    log_fail("splice", "unavailable", -1);
#endif
}

/* 49: stat */
static void sc_stat(void)
{
    struct stat st;
    int ret = stat("file_ok.txt", &st);
    if (ret < 0) log_fail("stat", "file_ok.txt", ret);
}

/* 50: statfs */
static void sc_statfs(void)
{
    struct statfs s;
    int ret = statfs(".", &s);
    if (ret < 0) log_fail("statfs", ".", ret);
}

/* 51: statx */
static void sc_statx(void)
{
#ifdef SYS_statx
    struct statx sx;
    int ret = syscall(SYS_statx, AT_FDCWD, "file_ok.txt",
                      AT_STATX_SYNC_AS_STAT,
                      STATX_BASIC_STATS, &sx);
    if (ret < 0) log_fail("statx", "file_ok.txt", ret);
#else
    log_fail("statx", "unavailable", -1);
#endif
}

/* 52: symlink */
static void sc_symlink(void)
{
    unlink("sym2");
    int ret = symlink("file_ok.txt", "sym2");
    if (ret < 0) {
        log_fail("symlink", "file_ok.txt -> sym2", ret);
        return;
    }
    unlink("sym2");
}

/* 53: symlinkat */
static void sc_symlinkat(void)
{
    unlink("sym3");
    int ret = symlinkat("file_ok.txt", AT_FDCWD, "sym3");
    if (ret < 0) {
        log_fail("symlinkat", "file_ok.txt -> sym3", ret);
        return;
    }
    unlink("sym3");
}

/* 54: sync */
static void sc_sync(void)
{
    /* sync has no explicit error return, but if errno changes we log */
    errno = 0;
    sync();
    if (errno != 0)
        log_fail("sync", "", 0);
}

/* 55: tee */
static void sc_tee(void)
{
#ifdef SYS_tee
    int p1[2], p2[2];
    if (pipe(p1) < 0 || pipe(p2) < 0) {
        if (p1[0] >= 0) { close(p1[0]); close(p1[1]); }
        if (p2[0] >= 0) { close(p2[0]); close(p2[1]); }
        log_fail("tee", "pipe", -1);
        return;
    }
    /* put some data into p1[1] */
    write(p1[1], "data", 4);
    ssize_t ret = syscall(SYS_tee, p1[0], p2[1], 4, 0);
    if (ret < 0) log_fail("tee", "pipe", (int)ret);
    close(p1[0]); close(p1[1]);
    close(p2[0]); close(p2[1]);
#else
    log_fail("tee", "unavailable", -1);
#endif
}

/* 56: truncate */
static void sc_truncate(void)
{
    int ret = truncate("tmp_trunc.log", 0);
    if (ret < 0) log_fail("truncate", "tmp_trunc.log", ret);
}

/* 57: unlink */
static void sc_unlink(void)
{
    int fd = open("tmp/unlink_me", O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd >= 0) {
        write(fd, "again", 5);
        close(fd);
    }
    int ret = unlink("tmp/unlink_me");
    if (ret < 0) log_fail("unlink", "tmp/unlink_me", ret);
}

/* 58: unlinkat */
static void sc_unlinkat(void)
{
    int dfd = open("tmp", O_RDONLY);
    if (dfd < 0) return;
    int fd = openat(dfd, "unlink_me", O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd >= 0) {
        write(fd, "again", 5);
        close(fd);
    }
    int ret = unlinkat(dfd, "unlink_me", 0);
    if (ret < 0) log_fail("unlinkat", "tmp/unlink_me", ret);
    close(dfd);
}

/* 59: utime */
static void sc_utime(void)
{
    int ret = utime("file_ok.txt", NULL);
    if (ret < 0) log_fail("utime", "file_ok.txt", ret);
}

/* 60: utimensat */
static void sc_utimensat(void)
{
#ifdef SYS_utimensat
    struct timespec ts[2];
    clock_gettime(CLOCK_REALTIME, &ts[0]);
    ts[1] = ts[0];
    int ret = syscall(SYS_utimensat, AT_FDCWD, "file_ok.txt", ts, 0);
    if (ret < 0) log_fail("utimensat", "file_ok.txt", ret);
#else
    log_fail("utimensat", "unavailable", -1);
#endif
}

/* 61: utimes */
static void sc_utimes(void)
{
    struct timeval tv[2];
    gettimeofday(&tv[0], NULL);
    tv[1] = tv[0];
    int ret = utimes("file_ok.txt", tv);
    if (ret < 0) log_fail("utimes", "file_ok.txt", ret);
}

/* 62: vmsplice */
static void sc_vmsplice(void)
{
#ifdef SYS_vmsplice
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        log_fail("vmsplice", "pipe", -1);
        return;
    }
    char buf[16] = "vmsplice-test";
    struct iovec iov = {
        .iov_base = buf,
        .iov_len = strlen(buf)
    };
    ssize_t ret = syscall(SYS_vmsplice, pipefd[1], &iov, 1, 0);
    if (ret < 0) log_fail("vmsplice", "pipe", (int)ret);
    close(pipefd[0]);
    close(pipefd[1]);
#else
    log_fail("vmsplice", "unavailable", -1);
#endif
}

/* ============================================================
   DISPATCH TABLE
   ============================================================ */

typedef void (*sc_fn)(void);

static sc_fn dispatch[] = {
    sc_access,          /* 0  access */
    sc_chdir,           /* 1  chdir */
    sc_chmod,           /* 2  chmod */
    sc_chown,           /* 3  chown */
    sc_close,           /* 4  close */
    sc_copy_file_range, /* 5  copy_file_range */
    sc_faccessat2,      /* 6  faccessat2 */
    sc_fallocate,       /* 7  fallocate */
    sc_fchdir,          /* 8  fchdir */
    sc_fchmod,          /* 9  fchmod */
    sc_fchmodat,        /* 10 fchmodat */
    sc_fchown,          /* 11 fchown */
    sc_fchownat,        /* 12 fchownat */
    sc_fdatasync,       /* 13 fdatasync */
    sc_fsconfig,        /* 14 fsconfig (stub) */
    sc_fsetxattr,       /* 15 fsetxattr */
    sc_fsmount,         /* 16 fsmount (stub) */
    sc_fsopen,          /* 17 fsopen (stub) */
    sc_fspick,          /* 18 fspick (stub) */
    sc_fstat,           /* 19 fstat */
    sc_fstatfs,         /* 20 fstatfs */
    sc_fsync,           /* 21 fsync */
    sc_ftruncate,       /* 22 ftruncate */
    sc_getdents,        /* 23 getdents */
    sc_getdents64,      /* 24 getdents64 */
    sc_lchown,          /* 25 lchown */
    sc_link,            /* 26 link */
    sc_linkat,          /* 27 linkat */
    sc_lstat,           /* 28 lstat */
    sc_mkdir,           /* 29 mkdir */
    sc_mkdirat,         /* 30 mkdirat */
    sc_mknod,           /* 31 mknod */
    sc_mknodat,         /* 32 mknodat */
    sc_mount,           /* 33 mount (stub) */
    sc_mount_setattr,   /* 34 mount_setattr (stub) */
    sc_open,            /* 35 open */
    sc_open_by_handle_at, /* 36 open_by_handle_at (stub) */
    sc_open_tree,       /* 37 open_tree */
    sc_openat,          /* 38 openat */
    sc_openat2,         /* 39 openat2 */
    sc_readahead,       /* 40 readahead */
    sc_readlink,        /* 41 readlink */
    sc_readlinkat,      /* 42 readlinkat */
    sc_rename,          /* 43 rename */
    sc_renameat,        /* 44 renameat */
    sc_renameat2,       /* 45 renameat2 */
    sc_rmdir,           /* 46 rmdir */
    sc_sendfile,        /* 47 sendfile */
    sc_splice,          /* 48 splice */
    sc_stat,            /* 49 stat */
    sc_statfs,          /* 50 statfs */
    sc_statx,           /* 51 statx */
    sc_symlink,         /* 52 symlink */
    sc_symlinkat,       /* 53 symlinkat */
    sc_sync,            /* 54 sync */
    sc_tee,             /* 55 tee */
    sc_truncate,        /* 56 truncate */
    sc_unlink,          /* 57 unlink */
    sc_unlinkat,        /* 58 unlinkat */
    sc_utime,           /* 59 utime */
    sc_utimensat,       /* 60 utimensat */
    sc_utimes,          /* 61 utimes */
    sc_vmsplice         /* 62 vmsplice */
};


/* ============================================================
   MAIN
   ============================================================ */

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage();
        return 1;
    }

    char *arg = NULL;
    if (strncmp(argv[1], "--mode=", 7) == 0)
        arg = argv[1] + 7;
    else {
        usage();
        return 1;
    }

    int idx = mode_index(arg);
    if (idx < 0) {
        usage();
        return 1;
    }

    printf("server PID: %d\n", getpid());
    printf("mode=%s\n", arg);
    fflush(stdout);

    sandbox_init();

    while (1) {
        dispatch[idx]();
        usleep(200000); /* 200 ms */
    }
}

