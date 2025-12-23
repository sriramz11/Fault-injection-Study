// fs_injector.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/ktime.h>
#include <linux/atomic.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("You");
MODULE_DESCRIPTION("Generic FS syscall fault injector using kretprobe");

/*
 * Module parameters:
 *
 *  target_symbol   : symbol name to hook (e.g., "__x64_sys_readlink")
 *  target_pid      : only inject for this PID (0 = all)
 *  inject_errno    : positive errno number to inject (e.g., 13 for EACCES)
 *  max_injections  : maximum number of injections before auto-stop
 *  unsafe_mode     : 0 = only override failing calls, 1 = override successes too
 *  injections_done : (read-only) total injections performed
 */

static char *target_symbol = "__x64_sys_readlink";
module_param(target_symbol, charp, 0644);
MODULE_PARM_DESC(target_symbol,
                 "Kernel symbol name to hook (e.g., \"__x64_sys_readlink\")");

static int target_pid = 0;
module_param(target_pid, int, 0644);
MODULE_PARM_DESC(target_pid, "PID to target. 0 = all tasks");

static int inject_errno = 13;   // default: EACCES
module_param(inject_errno, int, 0644);
MODULE_PARM_DESC(inject_errno,
                 "Errno number to inject (positive). Will use -errno as return value.");

static int max_injections = 1;
module_param(max_injections, int, 0644);
MODULE_PARM_DESC(max_injections,
                 "Number of injections allowed before auto-stop");

static int unsafe_mode = 1;
module_param(unsafe_mode, int, 0644);
MODULE_PARM_DESC(unsafe_mode,
                 "0 = only modify failing calls; 1 = allow overriding successful calls too");

/* Expose injections_done via sysfs as read-only int */
static atomic_t injections_done_atomic = ATOMIC_INIT(0);
static int injections_done;
module_param(injections_done, int, 0444);
MODULE_PARM_DESC(injections_done, "Total number of injections performed (read-only)");

static atomic_t inj_id = ATOMIC_INIT(0);

/* kretprobe handler for target_symbol */
static int fs_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    pid_t pid = current->pid;
    long old_ret = regs->ax;
    long new_ret;

    /* PID filter */
    if (target_pid > 0 && pid != target_pid)
        return 0;

    /* Injection limit */
    if (atomic_read(&injections_done_atomic) >= max_injections)
        return 0;

    /* Safe mode: only override already-failing calls (old_ret < 0) */
    if (!unsafe_mode && old_ret >= 0)
        return 0;

    if (inject_errno <= 0)
        return 0;

    new_ret = -inject_errno;

    /* Timestamp in ns */
    {
        ktime_t kt = ktime_get_real();
        s64 ts_ns = ktime_to_ns(kt);

        pr_info("fs_injector: inj_id=%d pid=%d comm=%s "
                "symbol=%s old_ret=%ld new_ret=%ld ts_ns=%lld unsafe=%d\n",
                atomic_read(&inj_id), pid, current->comm,
                target_symbol ? target_symbol : "(null)",
                old_ret, new_ret, ts_ns, unsafe_mode);
    }

    regs->ax = new_ret;

    atomic_inc(&inj_id);
    atomic_inc(&injections_done_atomic);
    injections_done = atomic_read(&injections_done_atomic);

    return 0;
}

static struct kretprobe fs_kretprobe = {
    .handler = fs_ret_handler,
    .maxactive = 20,
    .kp.symbol_name = NULL,   // filled at init
};

static int __init fs_injector_init(void)
{
    int ret;

    if (!target_symbol || !*target_symbol) {
        pr_err("fs_injector: target_symbol must be non-empty\n");
        return -EINVAL;
    }

    if (inject_errno <= 0) {
        pr_err("fs_injector: inject_errno must be positive, got %d\n",
               inject_errno);
        return -EINVAL;
    }

    atomic_set(&injections_done_atomic, 0);
    atomic_set(&inj_id, 0);
    injections_done = 0;

    fs_kretprobe.kp.symbol_name = target_symbol;

    ret = register_kretprobe(&fs_kretprobe);
    if (ret < 0) {
        pr_err("fs_injector: register_kretprobe(%s) failed: %d\n",
               target_symbol, ret);
        return ret;
    }

    pr_info("fs_injector: loaded. target_symbol=%s target_pid=%d "
            "inject_errno=%d unsafe_mode=%d max_injections=%d\n",
            target_symbol, target_pid, inject_errno,
            unsafe_mode, max_injections);

    return 0;
}

static void __exit fs_injector_exit(void)
{
    unregister_kretprobe(&fs_kretprobe);
    pr_info("fs_injector: unloaded. injections_done=%d\n", injections_done);
}

module_init(fs_injector_init);
module_exit(fs_injector_exit);

