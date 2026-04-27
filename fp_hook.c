/*
 * fp_hook.c - 函数指针Hook实现
 * 
 * 提供对函数指针表的Hook支持
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/kallsyms.h>
#include <linux/hugetlb.h> //pmd_huge
#include <asm/cacheflush.h>
//#include <asm/tlbflush.h> //flush_tlb_kernel_range
#include <asm/pgtable.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include "hook.h"
#include "hmem.h"
#include "cache.h"
#include "hook_utils.h"
#include "log.h"
#include "hook_chain_ops.h"
#include "hotpatch.h"

/* 保护fp_hook_wrap/fp_hook_unwrap的查找-创建-销毁流程 */
static DEFINE_MUTEX(fp_hook_wrap_mutex);


static __always_inline fp_hook_chain_t *fp_hook_dispatch_chain(void)
{
    fp_hook_chain_t *chain;

    asm volatile("mov %0, x9" : "=r"(chain));
    return chain;
}

static __noinline __nocfi uint64_t fp_dispatch0(void)
{
    fp_hook_chain_t *hook_chain = fp_hook_dispatch_chain();
    void *before_snapshot[FP_HOOK_CHAIN_NUM];
    void *after_snapshot[FP_HOOK_CHAIN_NUM];
    void *udata_snapshot[FP_HOOK_CHAIN_NUM];
    hook_fargs0_t fargs;
    int32_t snapshot_max;

    fargs.skip_origin = 0;
    fargs.chain = hook_chain;
    snapshot_max = hook_chain_snapshot_common(FP_HOOK_CHAIN_NUM, &hook_chain->lock, &hook_chain->chain_items_max,
                                              hook_chain->states, hook_chain->befores, hook_chain->afters,
                                              hook_chain->udata, before_snapshot, after_snapshot, udata_snapshot);
    for (int32_t i = 0; i < snapshot_max; i++) {
        hook_chain0_callback func = (hook_chain0_callback)before_snapshot[i];
        if (func)
            func(&fargs, udata_snapshot[i]);
    }
    if (!fargs.skip_origin) {
        uint64_t (*origin_func)(void) = (void *)READ_ONCE(hook_chain->hook.origin_fp);
        fargs.ret = origin_func();
    }
    for (int32_t i = snapshot_max - 1; i >= 0; i--) {
        hook_chain0_callback func = (hook_chain0_callback)after_snapshot[i];
        if (func)
            func(&fargs, udata_snapshot[i]);
    }
    return fargs.ret;
}

static __noinline __nocfi uint64_t fp_dispatch4(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    fp_hook_chain_t *hook_chain = fp_hook_dispatch_chain();
    void *before_snapshot[FP_HOOK_CHAIN_NUM];
    void *after_snapshot[FP_HOOK_CHAIN_NUM];
    void *udata_snapshot[FP_HOOK_CHAIN_NUM];
    hook_fargs4_t fargs;
    int32_t snapshot_max;

    fargs.skip_origin = 0;
    fargs.arg0 = arg0;
    fargs.arg1 = arg1;
    fargs.arg2 = arg2;
    fargs.arg3 = arg3;
    fargs.chain = hook_chain;
    snapshot_max = hook_chain_snapshot_common(FP_HOOK_CHAIN_NUM, &hook_chain->lock, &hook_chain->chain_items_max,
                                              hook_chain->states, hook_chain->befores, hook_chain->afters,
                                              hook_chain->udata, before_snapshot, after_snapshot, udata_snapshot);
    for (int32_t i = 0; i < snapshot_max; i++) {
        hook_chain4_callback func = (hook_chain4_callback)before_snapshot[i];
        if (func)
            func(&fargs, udata_snapshot[i]);
    }
    if (!fargs.skip_origin) {
        uint64_t (*origin_func)(uint64_t, uint64_t, uint64_t, uint64_t) =
            (void *)READ_ONCE(hook_chain->hook.origin_fp);
        fargs.ret = origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3);
    }
    for (int32_t i = snapshot_max - 1; i >= 0; i--) {
        hook_chain4_callback func = (hook_chain4_callback)after_snapshot[i];
        if (func)
            func(&fargs, udata_snapshot[i]);
    }
    return fargs.ret;
}

static __noinline __nocfi uint64_t fp_dispatch8(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                                uint64_t arg4, uint64_t arg5, uint64_t arg6, uint64_t arg7)
{
    fp_hook_chain_t *hook_chain = fp_hook_dispatch_chain();
    void *before_snapshot[FP_HOOK_CHAIN_NUM];
    void *after_snapshot[FP_HOOK_CHAIN_NUM];
    void *udata_snapshot[FP_HOOK_CHAIN_NUM];
    hook_fargs8_t fargs;
    int32_t snapshot_max;

    fargs.skip_origin = 0;
    fargs.arg0 = arg0;
    fargs.arg1 = arg1;
    fargs.arg2 = arg2;
    fargs.arg3 = arg3;
    fargs.arg4 = arg4;
    fargs.arg5 = arg5;
    fargs.arg6 = arg6;
    fargs.arg7 = arg7;
    fargs.chain = hook_chain;
    snapshot_max = hook_chain_snapshot_common(FP_HOOK_CHAIN_NUM, &hook_chain->lock, &hook_chain->chain_items_max,
                                              hook_chain->states, hook_chain->befores, hook_chain->afters,
                                              hook_chain->udata, before_snapshot, after_snapshot, udata_snapshot);
    for (int32_t i = 0; i < snapshot_max; i++) {
        hook_chain8_callback func = (hook_chain8_callback)before_snapshot[i];
        if (func)
            func(&fargs, udata_snapshot[i]);
    }
    if (!fargs.skip_origin) {
        uint64_t (*origin_func)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) =
            (void *)READ_ONCE(hook_chain->hook.origin_fp);
        fargs.ret = origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3,
                                fargs.arg4, fargs.arg5, fargs.arg6, fargs.arg7);
    }
    for (int32_t i = snapshot_max - 1; i >= 0; i--) {
        hook_chain8_callback func = (hook_chain8_callback)after_snapshot[i];
        if (func)
            func(&fargs, udata_snapshot[i]);
    }
    return fargs.ret;
}

static __noinline __nocfi uint64_t fp_dispatch12(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                                 uint64_t arg4, uint64_t arg5, uint64_t arg6, uint64_t arg7,
                                                 uint64_t arg8, uint64_t arg9, uint64_t arg10, uint64_t arg11)
{
    fp_hook_chain_t *hook_chain = fp_hook_dispatch_chain();
    void *before_snapshot[FP_HOOK_CHAIN_NUM];
    void *after_snapshot[FP_HOOK_CHAIN_NUM];
    void *udata_snapshot[FP_HOOK_CHAIN_NUM];
    hook_fargs12_t fargs;
    int32_t snapshot_max;

    fargs.skip_origin = 0;
    fargs.arg0 = arg0;
    fargs.arg1 = arg1;
    fargs.arg2 = arg2;
    fargs.arg3 = arg3;
    fargs.arg4 = arg4;
    fargs.arg5 = arg5;
    fargs.arg6 = arg6;
    fargs.arg7 = arg7;
    fargs.arg8 = arg8;
    fargs.arg9 = arg9;
    fargs.arg10 = arg10;
    fargs.arg11 = arg11;
    fargs.chain = hook_chain;
    snapshot_max = hook_chain_snapshot_common(FP_HOOK_CHAIN_NUM, &hook_chain->lock, &hook_chain->chain_items_max,
                                              hook_chain->states, hook_chain->befores, hook_chain->afters,
                                              hook_chain->udata, before_snapshot, after_snapshot, udata_snapshot);
    for (int32_t i = 0; i < snapshot_max; i++) {
        hook_chain12_callback func = (hook_chain12_callback)before_snapshot[i];
        if (func)
            func(&fargs, udata_snapshot[i]);
    }
    if (!fargs.skip_origin) {
        uint64_t (*origin_func)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                                uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) =
            (void *)READ_ONCE(hook_chain->hook.origin_fp);
        fargs.ret = origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3, fargs.arg4, fargs.arg5,
                                fargs.arg6, fargs.arg7, fargs.arg8, fargs.arg9, fargs.arg10, fargs.arg11);
    }
    for (int32_t i = snapshot_max - 1; i >= 0; i--) {
        hook_chain12_callback func = (hook_chain12_callback)after_snapshot[i];
        if (func)
            func(&fargs, udata_snapshot[i]);
    }
    return fargs.ret;
}

static uint64_t fp_dispatcher_addr(int32_t argno)
{
    switch (argno) {
    case 0:
        return (uint64_t)fp_dispatch0;
    case 1:
    case 2:
    case 3:
    case 4:
        return (uint64_t)fp_dispatch4;
    case 5:
    case 6:
    case 7:
    case 8:
        return (uint64_t)fp_dispatch8;
    default:
        return (uint64_t)fp_dispatch12;
    }
}

static hook_err_t hook_chain_prepare(fp_hook_chain_t *chain, int32_t argno)
{
    uint64_t dispatcher = fp_dispatcher_addr(argno);
    uint32_t *transit = chain->transit;
    u64 owner = (u64)chain;

    /*
     * BTI JC
     * LDR X9, #12     -> owner literal
     * LDR X17, #16    -> dispatcher literal
     * BR X17
     * owner[63:0]
     * dispatcher[63:0]
     */
    transit[0] = ARM64_BTI_JC;
    transit[1] = 0x58000069;
    transit[2] = 0x58000091;
    transit[3] = 0xd61f0220;
    transit[4] = (uint32_t)(owner & 0xffffffffu);
    transit[5] = (uint32_t)(owner >> 32);
    transit[6] = (uint32_t)(dispatcher & 0xffffffffu);
    transit[7] = (uint32_t)(dispatcher >> 32);
    return HOOK_NO_ERR;
}

int fp_hook(uintptr_t fp_addr, void *replace, void **backup)
{
    if (!fp_addr || !replace || !backup) {
        return -EINVAL;
    }

    hook_info("fp_addr %lx , replace: %lx ",*(uintptr_t *)fp_addr,replace);

    *(uintptr_t *)backup = *(uintptr_t *)fp_addr;
    int rc = hook_patch_data(fp_addr, &replace, sizeof(replace));
    if (rc) {
        hook_err("fp_hook: patch failed for 0x%lx, rc=%d\n", fp_addr, rc);
        return rc;
    }
    hook_info("fp_hook patched slot %lx -> %lx (backup=%lx)\n",
              fp_addr, *(uintptr_t *)fp_addr, *(uintptr_t *)backup);
    return 0;
}


int fp_unhook(uintptr_t fp_addr, void *backup)
{
    if (!fp_addr) {
        return -EINVAL;
    }

    int rc = hook_patch_data(fp_addr, &backup, sizeof(backup));
    if (rc) {
        hook_err("fp_unhook: patch failed for 0x%lx, rc=%d\n", fp_addr, rc);
        return rc;
    }
    hook_info("fp_unhook restored slot %lx -> %lx\n", fp_addr, *(uintptr_t *)fp_addr);
    return 0;
}


hook_err_t fp_hook_wrap(uintptr_t fp_addr, int32_t argno, void *before, void *after, void *udata)
{
    hook_err_t err = HOOK_NO_ERR;
    unsigned long flags;
    if (is_bad_address((void *)fp_addr)) return -HOOK_BAD_ADDRESS;

    mutex_lock(&fp_hook_wrap_mutex);
    fp_hook_chain_t *chain = hook_get_mem_from_origin(fp_addr);
    if (!chain) {
        chain = (fp_hook_chain_t *)hook_mem_zalloc(fp_addr, FUNCTION_POINTER_CHAIN);
        if (!chain) {
            mutex_unlock(&fp_hook_wrap_mutex);
            return -HOOK_NO_MEM;
        }
        chain->hook.fp_addr = fp_addr;
        chain->hook.replace_addr = (uint64_t)chain->transit;
        spin_lock_init(&chain->lock);
        err = hook_chain_prepare(chain, argno);
        if (err) {
            hook_mem_free(chain);
            mutex_unlock(&fp_hook_wrap_mutex);
            return err;
        }
        flush_icache_all();
        err = fp_hook(chain->hook.fp_addr, (void *)chain->hook.replace_addr, (void **)&chain->hook.origin_fp);
        if (err) {
            hook_mem_free(chain);
            mutex_unlock(&fp_hook_wrap_mutex);
            return err;
        }
    }

    spin_lock_irqsave(&chain->lock, flags);
    err = hook_chain_slots_add_common(FP_HOOK_CHAIN_NUM, &chain->chain_items_max, chain->states, chain->befores,
                                      chain->afters, chain->udata, before, after, udata);
    spin_unlock_irqrestore(&chain->lock, flags);
    if (!err) {
        mutex_unlock(&fp_hook_wrap_mutex);
        hook_debug("Wrap func pointer add: %llx, %llx, %llx successed\n", chain->hook.fp_addr, before, after);
        return HOOK_NO_ERR;
    }
    mutex_unlock(&fp_hook_wrap_mutex);
    hook_debug("Wrap func pointer add: %llx, %llx, %llx failed: %d\n", chain->hook.fp_addr, before, after, err);
    return err;
}


void fp_hook_unwrap(uintptr_t fp_addr, void *before, void *after)
{
    unsigned long flags;

    if (is_bad_address((void *)fp_addr)) return;

    mutex_lock(&fp_hook_wrap_mutex);
    fp_hook_chain_t *chain = (fp_hook_chain_t *)hook_get_mem_from_origin(fp_addr);
    if (!chain) {
        mutex_unlock(&fp_hook_wrap_mutex);
        return;
    }
    spin_lock_irqsave(&chain->lock, flags);
    hook_chain_slots_remove_common(FP_HOOK_CHAIN_NUM, chain->states, chain->befores, chain->afters, chain->udata,
                                   before, after);
    spin_unlock_irqrestore(&chain->lock, flags);
    hook_debug("Wrap func pointer remove: %llx, %llx, %llx\n", chain->hook.fp_addr, before, after);

    spin_lock_irqsave(&chain->lock, flags);
    if (!hook_chain_slots_all_empty_common(FP_HOOK_CHAIN_NUM, chain->states)) {
        spin_unlock_irqrestore(&chain->lock, flags);
        mutex_unlock(&fp_hook_wrap_mutex);
        return;
    }
    spin_unlock_irqrestore(&chain->lock, flags);
    if (fp_unhook(chain->hook.fp_addr, (void *)chain->hook.origin_fp)) {
        mutex_unlock(&fp_hook_wrap_mutex);
        return;
    }
    synchronize_rcu();
    hook_mem_retire(chain);
    mutex_unlock(&fp_hook_wrap_mutex);
    hook_debug("Unwrap func pointer: %llx, %llx, %llx\n", fp_addr, before, after);
}
