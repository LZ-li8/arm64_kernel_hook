/*
 * lkm.c - Linux内核Hook模块入口
 *
 * 提供ARM64架构下的Android内核Hook功能，并在模块加载时运行
 * 一组本地自测来验证 hook / hook_wrap / fp_hook / fp_hook_wrap。
 */

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/path.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/wait.h>

#include <asm/pgtable.h>
#include <asm/unistd.h>

#include "cache.h"
#include "hook.h"
#include "hmem.h"
#include "hotpatch.h"
#include "kallsyms_name.h"
#include "log.h"
#include "secpass.h"
#include "syscall.h"

#ifndef PTE_GP
#define PTE_GP (1ul << 50) /* BTI guarded */
#endif

#ifndef __NR_openat2
#define __NR_openat2 437
#endif

#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

__u64 mod_base = 0;
__u64 mod_end = 0;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("YY");
MODULE_DESCRIPTION("ARM64 Android Kernel Function Hook Module");
MODULE_VERSION("1.0");

typedef int (*vfs_open_t)(const struct path *path, struct file *file);

static bool enable_selftests = false;
static bool enable_vfs_demo = true;
static bool enable_inline_selftests = false;
static bool enable_fp_selftests = false;
static bool enable_syscall_selftests = false;

static vfs_open_t back_vfs_open;
static void *vfs_open_target;
static uintptr_t vfs_open_origin;
static uint32_t vfs_open_original_insts[TRAMPOLINE_MAX_NUM];
static int vfs_open_original_words;
static bool vfs_hook_installed;
static bool vfs_hook_unloading;
static atomic_t vfs_open_active = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(vfs_open_idle_wq);
static void *text;

module_param(enable_selftests, bool, 0644);
MODULE_PARM_DESC(enable_selftests, "Run local inline/fp hook self-tests during module init");
module_param(enable_vfs_demo, bool, 0644);
MODULE_PARM_DESC(enable_vfs_demo, "Install the demo hook on vfs_open");
module_param(enable_inline_selftests, bool, 0644);
MODULE_PARM_DESC(enable_inline_selftests, "Run inline hook self-tests");
module_param(enable_fp_selftests, bool, 0644);
MODULE_PARM_DESC(enable_fp_selftests, "Run function-pointer hook self-tests");
module_param(enable_syscall_selftests, bool, 0644);
MODULE_PARM_DESC(enable_syscall_selftests, "Run fp hook/wrap self-tests on sys_openat and sys_openat2");

static int selftest_expect_eq(const char *name, long actual, long expected)
{
    if (actual != expected) {
        hook_err("selftest %s failed: actual=%ld expected=%ld\n", name, actual, expected);
        return -EINVAL;
    }

    hook_info("selftest %s ok: %ld\n", name, actual);
    return 0;
}

static __always_inline int selftest_runtime_value(int value)
{
    volatile int runtime = value;
    return runtime;
}

static volatile int selftest_salt = 7;
static volatile int selftest_sink;

static __noinline __attribute__((aligned(64))) int selftest_inline_target(int a, int b)
{
    int salt = READ_ONCE(selftest_salt);
    int adjust = salt & 1;
    int left = a + salt;
    int right = b + adjust;
    int mix = left ^ (right << 1);

    if (mix & 1)
        WRITE_ONCE(selftest_sink, mix);
    else
        WRITE_ONCE(selftest_sink, mix + 1);

    left -= salt;
    right -= adjust;
    asm volatile("" ::: "memory");
    return left + right;
}

static int (*selftest_inline_backup)(int a, int b);
static int selftest_inline_replace_hits;

static __noinline __attribute__((aligned(64))) __nocfi int selftest_inline_replace(int a, int b)
{
    int salt = READ_ONCE(selftest_salt);
    int ret;

    selftest_inline_replace_hits++;
    ret = selftest_inline_backup(a, b) + 1000;

    if ((ret ^ salt) & 1)
        WRITE_ONCE(selftest_sink, ret ^ salt);
    else
        WRITE_ONCE(selftest_sink, ret + salt);

    asm volatile("" ::: "memory");
    return ret;
}

static __noinline __attribute__((aligned(64))) int selftest_wrap_target(int a, int b)
{
    int salt = READ_ONCE(selftest_salt);
    int left = a + (salt & 3);
    int right = b + (salt & 1);

    if ((left + right) & 1)
        WRITE_ONCE(selftest_sink, left - right);
    else
        WRITE_ONCE(selftest_sink, left + right);

    asm volatile("" ::: "memory");
    return left + right - ((salt & 3) + (salt & 1));
}

static int selftest_wrap_before_hits;
static int selftest_wrap_after_hits;

static void selftest_wrap_before(hook_fargs2_t *fargs, void *udata)
{
    selftest_wrap_before_hits++;
    fargs->arg0 += 1;
    fargs->arg1 += 1;
}

static void selftest_wrap_after(hook_fargs2_t *fargs, void *udata)
{
    selftest_wrap_after_hits++;
    fargs->ret += 10;
}

static __noinline int selftest_fp_target(int x)
{
    return x * 2;
}

static __noinline int selftest_fp_replace(int x)
{
    return x * 3;
}

static int (*selftest_fp_slot)(int) = selftest_fp_target;
static void *selftest_fp_backup;

static __noinline int selftest_fp_wrap_target(int a, int b)
{
    return a + b;
}

static int (*selftest_fp_wrap_slot)(int, int) = selftest_fp_wrap_target;
static int selftest_fp_wrap_before_hits;
static int selftest_fp_wrap_after_hits;
static uintptr_t selftest_fp_wrap_target_addr;

static void selftest_fp_wrap_before(hook_fargs2_t *fargs, void *udata)
{
    selftest_fp_wrap_before_hits++;
    fargs->arg0 += 1;
    fargs->arg1 += 1;
}

static void selftest_fp_wrap_after(hook_fargs2_t *fargs, void *udata)
{
    selftest_fp_wrap_after_hits++;
    fargs->ret += 10;
}

#define SELFTEST_OPENAT_NAME_PTR 0x12345000UL
#define SELFTEST_OPENAT2_HOW_PTR 0x12346000UL
#define SELFTEST_OPEN_FLAGS 0x240UL
#define SELFTEST_OPEN_MODE 0600UL
#define SELFTEST_OPENAT2_HOW_SIZE 24UL
#define SELFTEST_FP_HOOK_OPENAT_RET 0x5601L
#define SELFTEST_FP_HOOK_OPENAT2_RET 0x4371L
#define SELFTEST_FP_WRAP_OPENAT_RET 0x5602L
#define SELFTEST_FP_WRAP_OPENAT2_RET 0x4372L

typedef long (*selftest_syscall4_fn)(long arg0, long arg1, long arg2, long arg3);
typedef long (*selftest_syscall_regs_fn)(const struct pt_regs *regs);

static struct task_struct *selftest_syscall_task;
static int selftest_syscall_active_nr;
static void *selftest_syscall_backup;
static int selftest_syscall_replace_hits;
static int selftest_syscall_wrap_before_hits;
static int selftest_syscall_wrap_after_hits;

static bool selftest_syscall_should_intercept(int nr)
{
    return current == READ_ONCE(selftest_syscall_task) &&
           nr == READ_ONCE(selftest_syscall_active_nr);
}

static bool selftest_syscall_args_match(int nr, uint64_t *args)
{
    if (args[0] != (uint64_t)AT_FDCWD)
        return false;
    if (args[1] != SELFTEST_OPENAT_NAME_PTR)
        return false;

    if (nr == __NR_openat)
        return args[2] == SELFTEST_OPEN_FLAGS && args[3] == SELFTEST_OPEN_MODE;
    if (nr == __NR_openat2)
        return args[2] == SELFTEST_OPENAT2_HOW_PTR && args[3] == SELFTEST_OPENAT2_HOW_SIZE;

    return false;
}

static long selftest_syscall_fp_hook_ret(int nr)
{
    return nr == __NR_openat ? SELFTEST_FP_HOOK_OPENAT_RET : SELFTEST_FP_HOOK_OPENAT2_RET;
}

static long selftest_syscall_fp_wrap_ret(int nr)
{
    return nr == __NR_openat ? SELFTEST_FP_WRAP_OPENAT_RET : SELFTEST_FP_WRAP_OPENAT2_RET;
}

static __noinline __nocfi long selftest_sys_openat_replace(long dfd, long filename, long flags, long mode)
{
    selftest_syscall4_fn origin = (selftest_syscall4_fn)READ_ONCE(selftest_syscall_backup);
    uint64_t args[4] = { dfd, filename, flags, mode };

    if (!selftest_syscall_should_intercept(__NR_openat))
        return origin ? origin(dfd, filename, flags, mode) : -ENOENT;

    selftest_syscall_replace_hits++;
    if (!selftest_syscall_args_match(__NR_openat, args))
        return -EINVAL;
    return SELFTEST_FP_HOOK_OPENAT_RET;
}

static __noinline __nocfi long selftest_sys_openat2_replace(long dfd, long filename, long how, long size)
{
    selftest_syscall4_fn origin = (selftest_syscall4_fn)READ_ONCE(selftest_syscall_backup);
    uint64_t args[4] = { dfd, filename, how, size };

    if (!selftest_syscall_should_intercept(__NR_openat2))
        return origin ? origin(dfd, filename, how, size) : -ENOENT;

    selftest_syscall_replace_hits++;
    if (!selftest_syscall_args_match(__NR_openat2, args))
        return -EINVAL;
    return SELFTEST_FP_HOOK_OPENAT2_RET;
}

static __noinline __nocfi long selftest_sys_openat_replace_regs(const struct pt_regs *regs)
{
    selftest_syscall_regs_fn origin = (selftest_syscall_regs_fn)READ_ONCE(selftest_syscall_backup);

    if (!selftest_syscall_should_intercept(__NR_openat))
        return origin ? origin(regs) : -ENOENT;

    selftest_syscall_replace_hits++;
    if (!selftest_syscall_args_match(__NR_openat, (uint64_t *)regs->regs))
        return -EINVAL;
    return SELFTEST_FP_HOOK_OPENAT_RET;
}

static __noinline __nocfi long selftest_sys_openat2_replace_regs(const struct pt_regs *regs)
{
    selftest_syscall_regs_fn origin = (selftest_syscall_regs_fn)READ_ONCE(selftest_syscall_backup);

    if (!selftest_syscall_should_intercept(__NR_openat2))
        return origin ? origin(regs) : -ENOENT;

    selftest_syscall_replace_hits++;
    if (!selftest_syscall_args_match(__NR_openat2, (uint64_t *)regs->regs))
        return -EINVAL;
    return SELFTEST_FP_HOOK_OPENAT2_RET;
}

static void selftest_syscall_wrap_before(hook_fargs0_t *fargs, void *udata)
{
    int nr = (int)(long)udata;
    uint64_t *args;

    if (!selftest_syscall_should_intercept(nr))
        return;

    args = syscall_args(fargs);
    selftest_syscall_wrap_before_hits++;
    fargs->skip_origin = 1;
    fargs->ret = selftest_syscall_args_match(nr, args) ?
                 selftest_syscall_fp_wrap_ret(nr) : (uint64_t)-EINVAL;
}

static void selftest_syscall_wrap_after(hook_fargs0_t *fargs, void *udata)
{
    int nr = (int)(long)udata;

    if (!selftest_syscall_should_intercept(nr))
        return;

    selftest_syscall_wrap_after_hits++;
    if ((long)fargs->ret > 0)
        fargs->ret += 1;
}

static long selftest_call_open_syscall(int nr)
{
    if (nr == __NR_openat) {
        return raw_syscall4(nr, AT_FDCWD, SELFTEST_OPENAT_NAME_PTR,
                            SELFTEST_OPEN_FLAGS, SELFTEST_OPEN_MODE);
    }

    return raw_syscall4(nr, AT_FDCWD, SELFTEST_OPENAT_NAME_PTR,
                        SELFTEST_OPENAT2_HOW_PTR, SELFTEST_OPENAT2_HOW_SIZE);
}

static void selftest_log_exec_pte(const char *name, uintptr_t addr)
{
    pte_t *pte = pte_from_kva(addr);
    u64 val;

    if (!pte) {
        hook_warn("%s pte lookup failed for %px\n", name, (void *)addr);
        return;
    }

    val = pte_val(*pte);
    hook_info("%s addr=%px pte=0x%llx (W=%d PXN=%d UXN=%d)\n",
              name, (void *)addr, val,
              !!(val & PTE_WRITE),
              !!(val & PTE_PXN),
              !!(val & PTE_UXN));
}

static __nocfi int new_vfs_open(const struct path *path, struct file *file)
{
    vfs_open_t origin;
    char *tmp;
    char *pathname;
    int ret;

    atomic_inc(&vfs_open_active);
    origin = READ_ONCE(back_vfs_open);
    if (!origin) {
        ret = -ENOENT;
        goto out;
    }

    if (READ_ONCE(vfs_hook_unloading)) {
        ret = origin(path, file);
        goto out;
    }

    tmp = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
    if (!tmp) {
        ret = -ENOMEM;
        goto out;
    }

    pathname = d_path(path, tmp, PATH_MAX);
    if (IS_ERR(pathname)) {
        hook_info("d_path failed: %ld\n", PTR_ERR(pathname));
        kfree(tmp);
        ret = origin(path, file);
        goto out;
    }

    hook_info("vfs_open hooked: opened file path = %s\n", pathname);
    kfree(tmp);

    ret = origin(path, file);

out:
    if (atomic_dec_and_test(&vfs_open_active))
        wake_up(&vfs_open_idle_wq);
    return ret;
}

static int vfs_open_patch_words(uintptr_t origin)
{
    uint32_t first = READ_ONCE(*(uint32_t *)origin);

    if (first == ARM64_PACIASP || first == ARM64_PACIBSP)
        return 5;
    return 4;
}

static bool vfs_open_origin_restored(void)
{
    int i;

    if (!vfs_open_origin || vfs_open_original_words <= 0)
        return true;

    for (i = 0; i < vfs_open_original_words; i++) {
        if (READ_ONCE(*((uint32_t *)vfs_open_origin + i)) != vfs_open_original_insts[i])
            return false;
    }

    return true;
}

static int vfs_open_force_restore(void)
{
    uint32_t cur_insts[TRAMPOLINE_MAX_NUM];
    int rc;
    int i;

    if (!vfs_open_origin || vfs_open_original_words <= 0)
        return 0;

    if (vfs_open_origin_restored())
        return 0;

    for (i = 0; i < vfs_open_original_words; i++)
        cur_insts[i] = READ_ONCE(*((uint32_t *)vfs_open_origin + i));

    hook_warn("Hook: vfs_open origin still patched/mismatched, force restore origin=%px first=%08x/%08x\n",
              (void *)vfs_open_origin, cur_insts[0], cur_insts[1]);

    rc = hook_patch_text(vfs_open_origin, vfs_open_original_insts, vfs_open_original_words, 0);
    if (rc) {
        hook_err("Hook: force restore vfs_open failed: %d\n", rc);
        return rc;
    }

    if (!vfs_open_origin_restored()) {
        hook_err("Hook: force restore vfs_open verification failed\n");
        return -EFAULT;
    }

    return 0;
}

static void vfs_open_retire_hook_mem(void)
{
    void *hook_mem;

    if (!vfs_open_origin || !vfs_open_origin_restored())
        return;

    hook_mem = hook_get_mem_from_origin(vfs_open_origin);
    if (hook_mem) {
        hook_warn("Hook: retire vfs_open hook memory after force restore\n");
        hook_mem_retire(hook_mem);
    }
}

static void vfs_open_wait_idle(const char *stage, unsigned int timeout_ms)
{
    long left;

    left = wait_event_timeout(vfs_open_idle_wq,
                              atomic_read(&vfs_open_active) == 0,
                              msecs_to_jiffies(timeout_ms));
    if (!left && atomic_read(&vfs_open_active) != 0) {
        hook_warn("Hook: vfs_open wait idle timeout at %s, active=%d\n",
                  stage, atomic_read(&vfs_open_active));
    }
}

static int hook_vfs_open(void)
{
    void *target_func;
    uintptr_t origin;
    hook_err_t err;
    int i;

    target_func = (void *)m_kallsyms_lookup_name("vfs_open");
    if (!target_func) {
        hook_info("Hook: not find vfs_open\n");
        return -ENOENT;
    }

    hook_info("Hook: vfs_open fun = 0x%lx\n", (unsigned long)target_func);
    origin = branch_func_addr((uintptr_t)target_func);
    if (!origin) {
        hook_info("Hook: vfs_open origin invalid\n");
        return -ENOENT;
    }

    vfs_open_original_words = vfs_open_patch_words(origin);
    for (i = 0; i < vfs_open_original_words; i++)
        vfs_open_original_insts[i] = READ_ONCE(*((uint32_t *)origin + i));
    vfs_open_origin = origin;

    err = hook(target_func, new_vfs_open, (void **)&back_vfs_open);
    if (err != HOOK_NO_ERR) {
        hook_info("Hook: Hook vfs_open fail: %d\n", err);
        vfs_open_origin = 0;
        vfs_open_original_words = 0;
        return err;
    }

    vfs_open_target = target_func;
    WRITE_ONCE(vfs_hook_unloading, false);
    vfs_hook_installed = true;
    hook_info("Hook: sucess Hook vfs_open\n");
    return 0;
}

static void unhook_vfs_open(void)
{
    void *target_func;

    if (!vfs_hook_installed)
        return;

    WRITE_ONCE(vfs_hook_unloading, true);
    synchronize_rcu();
    vfs_open_wait_idle("pre-unhook", 1000);

    target_func = vfs_open_target;
    if (!target_func)
        target_func = (void *)m_kallsyms_lookup_name("vfs_open");
    if (!target_func) {
        hook_warn("Hook: not find vfs_open函数, fallback to saved origin restore\n");
    } else {
        unhook(target_func);
    }

    vfs_open_force_restore();
    vfs_open_retire_hook_mem();
    synchronize_rcu();
    msleep(200);
    vfs_open_wait_idle("post-unhook", 1000);
    back_vfs_open = NULL;
    vfs_open_target = NULL;
    vfs_open_origin = 0;
    vfs_open_original_words = 0;
    vfs_hook_installed = false;
    WRITE_ONCE(vfs_hook_unloading, false);
    hook_info("Hook: remove vfs_open Hook\n");
}

static int run_inline_hook_selftest(void)
{
    hook_err_t err;
    int rc = 0;

    selftest_inline_backup = NULL;
    selftest_inline_replace_hits = 0;

    rc = selftest_expect_eq("inline-hook baseline",
                            selftest_inline_target(selftest_runtime_value(2), selftest_runtime_value(3)), 5);
    if (rc)
        return rc;

    err = hook((void *)selftest_inline_target, (void *)selftest_inline_replace, (void **)&selftest_inline_backup);
    if (err)
        return err;

    rc = selftest_expect_eq("inline-hook hooked",
                            selftest_inline_target(selftest_runtime_value(2), selftest_runtime_value(3)), 1005);
    if (rc)
        goto out;
    rc = selftest_expect_eq("inline-hook backup",
                            selftest_inline_backup(selftest_runtime_value(2), selftest_runtime_value(3)), 5);
    if (rc)
        goto out;
    rc = selftest_expect_eq("inline-hook hits", selftest_inline_replace_hits, 1);

out:
    unhook((void *)selftest_inline_target);
    selftest_inline_backup = NULL;
    if (rc)
        return rc;
    return selftest_expect_eq("inline-hook restore",
                              selftest_inline_target(selftest_runtime_value(2), selftest_runtime_value(3)), 5);
}

static int run_inline_wrap_selftest(void)
{
    hook_err_t err;
    int rc = 0;

    selftest_wrap_before_hits = 0;
    selftest_wrap_after_hits = 0;

    rc = selftest_expect_eq("inline-wrap baseline",
                            selftest_wrap_target(selftest_runtime_value(1), selftest_runtime_value(2)), 3);
    if (rc)
        return rc;

    err = hook_wrap2((void *)selftest_wrap_target, selftest_wrap_before, selftest_wrap_after, NULL);
    if (err)
        return err;

    rc = selftest_expect_eq("inline-wrap hooked",
                            selftest_wrap_target(selftest_runtime_value(1), selftest_runtime_value(2)), 15);
    if (rc)
        goto out;
    rc = selftest_expect_eq("inline-wrap before hits", selftest_wrap_before_hits, 1);
    if (rc)
        goto out;
    rc = selftest_expect_eq("inline-wrap after hits", selftest_wrap_after_hits, 1);

out:
    hook_unwrap((void *)selftest_wrap_target, selftest_wrap_before, selftest_wrap_after);
    if (rc)
        return rc;
    return selftest_expect_eq("inline-wrap restore",
                              selftest_wrap_target(selftest_runtime_value(1), selftest_runtime_value(2)), 3);
}

static int run_fp_hook_selftest(void)
{
    int rc;

    selftest_fp_slot = selftest_fp_target;
    selftest_fp_backup = NULL;

    rc = selftest_expect_eq("fp-hook baseline", selftest_fp_slot(selftest_runtime_value(4)), 8);
    if (rc)
        return rc;

    rc = fp_hook((uintptr_t)&selftest_fp_slot, (void *)selftest_fp_replace, &selftest_fp_backup);
    if (rc)
        return rc;

    rc = selftest_expect_eq("fp-hook hooked", selftest_fp_slot(selftest_runtime_value(4)), 12);
    if (rc)
        goto out;
    rc = selftest_expect_eq("fp-hook backup",
                            ((int (*)(int))selftest_fp_backup)(selftest_runtime_value(4)), 8);

out:
    if (selftest_fp_backup)
        fp_unhook((uintptr_t)&selftest_fp_slot, selftest_fp_backup);
    selftest_fp_backup = NULL;
    selftest_fp_slot = selftest_fp_target;
    if (rc)
        return rc;
    return selftest_expect_eq("fp-hook restore", selftest_fp_slot(selftest_runtime_value(4)), 8);
}

static int run_fp_wrap_selftest(void)
{
    hook_err_t err;
    int rc = 0;

    selftest_fp_wrap_slot = selftest_fp_wrap_target;
    selftest_fp_wrap_before_hits = 0;
    selftest_fp_wrap_after_hits = 0;

    rc = selftest_expect_eq("fp-wrap baseline",
                            selftest_fp_wrap_slot(selftest_runtime_value(1), selftest_runtime_value(2)), 3);
    if (rc)
        return rc;

    err = fp_hook_wrap2((uintptr_t)&selftest_fp_wrap_slot, selftest_fp_wrap_before, selftest_fp_wrap_after, NULL);
    if (err)
        return err;

    selftest_fp_wrap_target_addr = (uintptr_t)selftest_fp_wrap_slot;
    hook_info("selftest fp-wrap slot now points to %px\n", (void *)selftest_fp_wrap_target_addr);
    selftest_log_exec_pte("selftest fp-wrap target", selftest_fp_wrap_target_addr);

    rc = selftest_expect_eq("fp-wrap hooked",
                            selftest_fp_wrap_slot(selftest_runtime_value(1), selftest_runtime_value(2)), 15);
    if (rc)
        goto out;
    rc = selftest_expect_eq("fp-wrap before hits", selftest_fp_wrap_before_hits, 1);
    if (rc)
        goto out;
    rc = selftest_expect_eq("fp-wrap after hits", selftest_fp_wrap_after_hits, 1);

out:
    fp_hook_unwrap((uintptr_t)&selftest_fp_wrap_slot, selftest_fp_wrap_before, selftest_fp_wrap_after);
    selftest_fp_wrap_slot = selftest_fp_wrap_target;
    if (rc)
        return rc;
    return selftest_expect_eq("fp-wrap restore",
                              selftest_fp_wrap_slot(selftest_runtime_value(1), selftest_runtime_value(2)), 3);
}

static void *selftest_syscall_replace_for_nr(int nr)
{
    if (has_syscall_wrapper)
        return nr == __NR_openat ? (void *)selftest_sys_openat_replace_regs :
                                   (void *)selftest_sys_openat2_replace_regs;

    return nr == __NR_openat ? (void *)selftest_sys_openat_replace :
                               (void *)selftest_sys_openat2_replace;
}

static int run_fp_syscall_hook_selftest_one(int nr, const char *name)
{
    uintptr_t fp_addr;
    void *expected_restore;
    long ret;
    int rc = 0;

    if (!sys_call_table) {
        hook_err("selftest %s skipped: sys_call_table not found\n", name);
        return -ENOENT;
    }

    fp_addr = (uintptr_t)(sys_call_table + nr);
    expected_restore = (void *)READ_ONCE(sys_call_table[nr]);
    selftest_syscall_task = current;
    selftest_syscall_active_nr = nr;
    selftest_syscall_backup = NULL;
    selftest_syscall_replace_hits = 0;

    rc = fp_hook(fp_addr, selftest_syscall_replace_for_nr(nr), &selftest_syscall_backup);
    if (rc)
        goto out;

    ret = selftest_call_open_syscall(nr);
    rc = selftest_expect_eq(name, ret, selftest_syscall_fp_hook_ret(nr));
    if (rc)
        goto out;
    rc = selftest_expect_eq("fp-syscall-hook hits", selftest_syscall_replace_hits, 1);

out:
    if (selftest_syscall_backup) {
        int unhook_rc = fp_unhook(fp_addr, selftest_syscall_backup);

        if (!rc && unhook_rc)
            rc = unhook_rc;
        synchronize_rcu();
        msleep(20);
    }

    if (!rc)
        rc = selftest_expect_eq("fp-syscall-hook restore",
                                (long)READ_ONCE(sys_call_table[nr]), (long)expected_restore);

    selftest_syscall_task = NULL;
    selftest_syscall_active_nr = -1;
    selftest_syscall_backup = NULL;
    return rc;
}

static int run_fp_syscall_wrap_selftest_one(int nr, const char *name)
{
    hook_err_t err;
    long ret;
    int rc = 0;

    if (!sys_call_table) {
        hook_err("selftest %s skipped: sys_call_table not found\n", name);
        return -ENOENT;
    }

    selftest_syscall_task = current;
    selftest_syscall_active_nr = nr;
    selftest_syscall_wrap_before_hits = 0;
    selftest_syscall_wrap_after_hits = 0;

    err = fp_wrap_syscalln(nr, 4, 0, selftest_syscall_wrap_before,
                           selftest_syscall_wrap_after, (void *)(long)nr);
    if (err) {
        selftest_syscall_task = NULL;
        selftest_syscall_active_nr = -1;
        return err;
    }

    ret = selftest_call_open_syscall(nr);
    rc = selftest_expect_eq(name, ret, selftest_syscall_fp_wrap_ret(nr) + 1);
    if (rc)
        goto out;
    rc = selftest_expect_eq("fp-syscall-wrap before hits", selftest_syscall_wrap_before_hits, 1);
    if (rc)
        goto out;
    rc = selftest_expect_eq("fp-syscall-wrap after hits", selftest_syscall_wrap_after_hits, 1);

out:
    fp_unwrap_syscalln(nr, 0, selftest_syscall_wrap_before, selftest_syscall_wrap_after);
    synchronize_rcu();
    msleep(20);
    selftest_syscall_task = NULL;
    selftest_syscall_active_nr = -1;
    return rc;
}

static int run_fp_syscall_selftests(void)
{
    int rc;

    syscall_init();
    hook_info("selftest syscall table=%px wrapper=%d openat=%d openat2=%d\n",
              sys_call_table, has_syscall_wrapper, __NR_openat, __NR_openat2);

    rc = run_fp_syscall_hook_selftest_one(__NR_openat, "fp-syscall-hook openat");
    if (rc)
        return rc;
    rc = run_fp_syscall_hook_selftest_one(__NR_openat2, "fp-syscall-hook openat2");
    if (rc)
        return rc;
    rc = run_fp_syscall_wrap_selftest_one(__NR_openat, "fp-syscall-wrap openat");
    if (rc)
        return rc;
    return run_fp_syscall_wrap_selftest_one(__NR_openat2, "fp-syscall-wrap openat2");
}

static int run_hook_selftests(void)
{
    int rc;

    if (enable_inline_selftests) {
        rc = run_inline_hook_selftest();
        if (rc)
            return rc;
        rc = run_inline_wrap_selftest();
        if (rc)
            return rc;
    }

    if (enable_fp_selftests) {
        rc = run_fp_hook_selftest();
        if (rc)
            return rc;
        rc = run_fp_wrap_selftest();
        if (rc)
            return rc;
    }

    if (enable_syscall_selftests) {
        rc = run_fp_syscall_selftests();
        if (rc)
            return rc;
    }

    hook_info("selftest suite passed\n");
    return 0;
}

static int hook_module_prepare_text(void)
{
    size_t i;
    const size_t mem_size = PAGE_SIZE * 10;
    text = hook_alloc(mem_size);
    if (!text) {
        hook_info("text is null\n");
        return -ENOMEM;
    }

    mod_base = (__u64)text;
    mod_end = (__u64)text + mem_size;

    for (i = 0; i < 10; i++) {
        uint64_t *pte = (uint64_t *)pte_from_kva((uint64_t)text + PAGE_SIZE * i);
        if (!pte) {
            hook_info("pte_from_kva is null\n");
            return -EFAULT;
        }
        hook_info("vpte: 0x%llx Flags: (W=%d, PXN=%d, UXN=%d)\n",
                  (uint64_t)*pte,
                  !!(*pte & PTE_WRITE),
                  !!(*pte & PTE_PXN),
                  !!(*pte & PTE_UXN));
        *pte = (*pte | PTE_DBM | PTE_SHARED) & ~PTE_PXN & ~PTE_RDONLY & ~PTE_GP;
    }

    k_flush_tlb_kernel_range((uint64_t)text, (uint64_t)text + mem_size);
    hook_info("modify pte is sucess\n");
    return hook_mem_add((uint64_t)text, mem_size);
}

static void hook_module_cleanup(void)
{
    unhook_vfs_open();
    hook_mem_check_leaks();

    hook_mem_cleanup_all();
    if (text) {
        hook_free(text);
        text = NULL;
    }
    restore_kcfi();
    mod_base = 0;
    mod_end = 0;
}

static int __init hook_module_init(void)
{
    int rc;

    hook_info("init\n");
    hotpatch_init();

    rc = hook_module_prepare_text();
    if (rc)
        goto err;

    rc = bypass_kcfi();
    if (rc) {
        hook_err("bypass_kcfi failed: %d\n", rc);
        goto err;
    }

    if (enable_selftests) {
        rc = run_hook_selftests();
        if (rc)
            goto err;
    }

    if (enable_vfs_demo) {
        rc = hook_vfs_open();
        if (rc)
            goto err;
    }

    return 0;

err:
    hook_module_cleanup();
    return rc;
}

static void __exit hook_module_exit(void)
{
    hook_info("exit\n");
    hook_module_cleanup();
}

module_init(hook_module_init);
module_exit(hook_module_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("niqiuqiux");
MODULE_DESCRIPTION("Android Kernel Hook module for ARM64");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
