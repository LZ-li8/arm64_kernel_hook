/*
 * hook_chain.c - Hook链实现
 * 
 * 提供对函数调用链的Hook支持，允许多个处理函数按顺序执行
 */

#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include "hook.h"
#include "hmem.h"
#include "cache.h"
#include "hook_utils.h"
#include "log.h"
#include "hook_chain_ops.h"
#include "linux/stop_machine.h"
//#include <asm/patching.h>
#include "hotpatch.h"

/* 保护hook_wrap/hook_unwrap_remove的查找-创建-销毁流程 */
static DEFINE_MUTEX(hook_wrap_mutex);

// Hook链状态定义
enum hook_chain_state {
    HOOK_CHAIN_INIT,
    HOOK_CHAIN_ACTIVE,
    HOOK_CHAIN_DISABLED
};

static __always_inline hook_chain_t *hook_dispatch_chain(void)
{
    hook_chain_t *chain;

    asm volatile("mov %0, x9" : "=r"(chain));
    return chain;
}

static __noinline __nocfi uint64_t hook_dispatch0(void)
{
    hook_chain_t *hook_chain = hook_dispatch_chain();
    void *before_snapshot[HOOK_CHAIN_NUM];
    void *after_snapshot[HOOK_CHAIN_NUM];
    void *udata_snapshot[HOOK_CHAIN_NUM];
    hook_fargs0_t fargs;
    int32_t snapshot_max;

    fargs.skip_origin = 0;
    fargs.chain = hook_chain;
    snapshot_max = hook_chain_snapshot_common(HOOK_CHAIN_NUM, &hook_chain->lock, &hook_chain->chain_items_max,
                                              hook_chain->states, hook_chain->befores, hook_chain->afters,
                                              hook_chain->udata, before_snapshot, after_snapshot, udata_snapshot);
    for (int32_t i = 0; i < snapshot_max; i++) {
        hook_chain0_callback func = (hook_chain0_callback)before_snapshot[i];
        if (func)
            func(&fargs, udata_snapshot[i]);
    }
    if (!fargs.skip_origin) {
        uint64_t (*origin_func)(void) = (void *)READ_ONCE(hook_chain->hook.relo_addr);
        fargs.ret = origin_func();
    }
    for (int32_t i = snapshot_max - 1; i >= 0; i--) {
        hook_chain0_callback func = (hook_chain0_callback)after_snapshot[i];
        if (func)
            func(&fargs, udata_snapshot[i]);
    }
    return fargs.ret;
}

static __noinline __nocfi uint64_t hook_dispatch4(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    hook_chain_t *hook_chain = hook_dispatch_chain();
    void *before_snapshot[HOOK_CHAIN_NUM];
    void *after_snapshot[HOOK_CHAIN_NUM];
    void *udata_snapshot[HOOK_CHAIN_NUM];
    hook_fargs4_t fargs;
    int32_t snapshot_max;

    fargs.skip_origin = 0;
    fargs.arg0 = arg0;
    fargs.arg1 = arg1;
    fargs.arg2 = arg2;
    fargs.arg3 = arg3;
    fargs.chain = hook_chain;
    snapshot_max = hook_chain_snapshot_common(HOOK_CHAIN_NUM, &hook_chain->lock, &hook_chain->chain_items_max,
                                              hook_chain->states, hook_chain->befores, hook_chain->afters,
                                              hook_chain->udata, before_snapshot, after_snapshot, udata_snapshot);
    for (int32_t i = 0; i < snapshot_max; i++) {
        hook_chain4_callback func = (hook_chain4_callback)before_snapshot[i];
        if (func)
            func(&fargs, udata_snapshot[i]);
    }
    if (!fargs.skip_origin) {
        uint64_t (*origin_func)(uint64_t, uint64_t, uint64_t, uint64_t) =
            (void *)READ_ONCE(hook_chain->hook.relo_addr);
        fargs.ret = origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3);
    }
    for (int32_t i = snapshot_max - 1; i >= 0; i--) {
        hook_chain4_callback func = (hook_chain4_callback)after_snapshot[i];
        if (func)
            func(&fargs, udata_snapshot[i]);
    }
    return fargs.ret;
}

static __noinline __nocfi uint64_t hook_dispatch8(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                                  uint64_t arg4, uint64_t arg5, uint64_t arg6, uint64_t arg7)
{
    hook_chain_t *hook_chain = hook_dispatch_chain();
    void *before_snapshot[HOOK_CHAIN_NUM];
    void *after_snapshot[HOOK_CHAIN_NUM];
    void *udata_snapshot[HOOK_CHAIN_NUM];
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
    snapshot_max = hook_chain_snapshot_common(HOOK_CHAIN_NUM, &hook_chain->lock, &hook_chain->chain_items_max,
                                              hook_chain->states, hook_chain->befores, hook_chain->afters,
                                              hook_chain->udata, before_snapshot, after_snapshot, udata_snapshot);
    for (int32_t i = 0; i < snapshot_max; i++) {
        hook_chain8_callback func = (hook_chain8_callback)before_snapshot[i];
        if (func)
            func(&fargs, udata_snapshot[i]);
    }
    if (!fargs.skip_origin) {
        uint64_t (*origin_func)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) =
            (void *)READ_ONCE(hook_chain->hook.relo_addr);
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

static __noinline __nocfi uint64_t hook_dispatch12(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                                   uint64_t arg4, uint64_t arg5, uint64_t arg6, uint64_t arg7,
                                                   uint64_t arg8, uint64_t arg9, uint64_t arg10, uint64_t arg11)
{
    hook_chain_t *hook_chain = hook_dispatch_chain();
    void *before_snapshot[HOOK_CHAIN_NUM];
    void *after_snapshot[HOOK_CHAIN_NUM];
    void *udata_snapshot[HOOK_CHAIN_NUM];
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
    snapshot_max = hook_chain_snapshot_common(HOOK_CHAIN_NUM, &hook_chain->lock, &hook_chain->chain_items_max,
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
            (void *)READ_ONCE(hook_chain->hook.relo_addr);
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

static uint64_t hook_dispatcher_addr(int32_t argno)
{
    switch (argno) {
    case 0:
        return (uint64_t)hook_dispatch0;
    case 1:
    case 2:
    case 3:
    case 4:
        return (uint64_t)hook_dispatch4;
    case 5:
    case 6:
    case 7:
    case 8:
        return (uint64_t)hook_dispatch8;
    default:
        return (uint64_t)hook_dispatch12;
    }
}


hook_err_t hook_prepare(hook_t *hook)
{
    if (is_bad_address((void *)hook->func_addr)) return -HOOK_BAD_ADDRESS;
    if (is_bad_address((void *)hook->origin_addr)) return -HOOK_BAD_ADDRESS;
    if (is_bad_address((void *)hook->replace_addr)) return -HOOK_BAD_ADDRESS;
    if (is_bad_address((void *)hook->relo_addr)) return -HOOK_BAD_ADDRESS;



    // backup origin instruction
    for (int i = 0; i < TRAMPOLINE_MAX_NUM; i++) {
        hook->origin_insts[i] = *((uint32_t *)hook->origin_addr + i);
        //hook_debug("origin_insts:%lx",hook->origin_insts[i]);
    }


    // for (int i = 0; i < 10; i++) {
    //     uint32_t origin_insts = *((uint32_t *)hook->origin_addr + i);
    //     hook_debug("origin_insts:%lx",origin_insts);
    // }
    // trampline to replace_addr
    if (hook->origin_insts[0] == ARM64_PACIASP || hook->origin_insts[0] == ARM64_PACIBSP) {
        hook->tramp_insts_num = branch_from_to(&hook->tramp_insts[1], hook->origin_addr, hook->replace_addr);
        hook->tramp_insts[0] = ARM64_BTI_JC;
        hook->tramp_insts_num++;
    } else {
        hook->tramp_insts_num = branch_from_to(hook->tramp_insts, hook->origin_addr, hook->replace_addr);
    }
    
    //hook_debug("hook->tramp_insts_num:%d",hook->tramp_insts_num);
    // relocate
    for (int i = 0; i < sizeof(hook->relo_insts) / sizeof(hook->relo_insts[0]); i++) {
        hook->relo_insts[i] = ARM64_NOP;
    }

    if (is_hooked(hook->origin_insts)) {
      hook_debug("this fun has hooked");
      // LDR X17, #8
      // RET X17
      // addr
      // 0xffff--
      // 更改原先的// LDR X17, #8地址到我们的地址
      // 由于前4个指令是tramp_insts 所以直接用上面设置好的 默认会覆盖调
      // jump back 直接就原先的hook指令
      // 由于是地址跳转 不需要重定位之前的指令  直接用即可
      int relo_len = hook->relo_insts_num;
      // rewrite_trampoline(hook);
      for (int i = 0; i < TRAMPOLINE_NUM; i++) {
        hook->relo_insts[relo_len + i] = hook->origin_insts[i];
      }
      hook->relo_insts_num += 4;
    } else {

      for (int i = 0; i < hook->tramp_insts_num; i++) {
        uint64_t inst_addr = hook->origin_addr + i * 4;
        uint32_t inst = hook->origin_insts[i];
        // 检查边界：每条指令最多重定位为8条，加上跳转4条
        if (hook->relo_insts_num + 8 + 4 > RELOCATE_INST_NUM) {
          hook_debug("relocate buffer overflow: relo_insts_num=%d, max=%d",
                hook->relo_insts_num, RELOCATE_INST_NUM);
          return -HOOK_BAD_RELO;
        }
        hook_err_t relo_res = relocate_inst(hook, inst_addr, inst);
        if (relo_res) {
          return -HOOK_BAD_RELO;
        }
      }
    }

    // jump back
    uint64_t back_src_addr = hook->relo_addr + hook->relo_insts_num * 4;
    uint64_t back_dst_addr = hook->origin_addr + hook->tramp_insts_num * 4;
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;
    // 检查边界：确保跳转指令不会溢出
    if (hook->relo_insts_num + 4 > RELOCATE_INST_NUM) {
      hook_debug("relocate buffer overflow before jump back: relo_insts_num=%d, max=%d",
            hook->relo_insts_num, RELOCATE_INST_NUM);
      return -HOOK_BAD_RELO;
    }
    // 跳转到原函数的后续指令
    hook->relo_insts_num += branch_from_to(buf, back_src_addr, back_dst_addr);
    return HOOK_NO_ERR;
}


// todo:
hook_err_t hook_install(hook_t *hook) {
  int rc = hook_patch_text(hook->origin_addr, hook->tramp_insts, hook->tramp_insts_num, 1);
  if (rc) {
    hook_err("hook_install: patch failed for va=0x%llx, rc=%d\n", hook->origin_addr, rc);
    return rc;
  }
  return HOOK_NO_ERR;
}

hook_err_t hook_uninstall(hook_t *hook)
{
    int rc = hook_patch_text(hook->origin_addr, hook->origin_insts, hook->tramp_insts_num, 0);
    if (rc) {
        hook_err("hook_uninstall: patch failed for va=0x%llx, rc=%d\n", hook->origin_addr, rc);
        return rc;
    }
    return HOOK_NO_ERR;
}


hook_err_t hook(void *func, void *replace, void **backup)
{
    hook_err_t err = HOOK_NO_ERR;
    hook_t *hook;

    if (!func || !replace || !backup) {
        return -HOOK_BAD_ADDRESS;
    }
    uint64_t origin_addr = branch_func_addr((uintptr_t)func);
    //hook_debug("func:%llx  origin_addr:%llx",func,origin_addr);
    mutex_lock(&hook_wrap_mutex);
    if (hook_get_mem_from_origin(origin_addr)) {
        mutex_unlock(&hook_wrap_mutex);
        return -HOOK_DUPLICATED;
    }

    hook = (hook_t *)hook_mem_zalloc(origin_addr, INLINE);
    if (!hook) {
        mutex_unlock(&hook_wrap_mutex);
        return -HOOK_NO_MEM;
    }
    hook->func_addr = (uint64_t)func;
    hook->origin_addr = origin_addr;
    hook->replace_addr = (uint64_t)replace;
    hook->relo_addr = (uint64_t)hook->relo_insts;
    *backup = (void *)hook->relo_addr;
    hook_debug("Hook func: %llx, origin: %llx, replace: %llx, relocate: %llx, chain: %llx\n", hook->func_addr,
          hook->origin_addr, hook->replace_addr, hook->relo_addr, (uint64_t)hook);
    err = hook_prepare(hook);
    if (err) goto out;
    err = hook_install(hook);
    if (err) goto out;
    mutex_unlock(&hook_wrap_mutex);
    hook_debug("Hook func: %llx succsseed\n", hook->func_addr);
    return HOOK_NO_ERR;
out:
    hook_mem_free(hook);
    mutex_unlock(&hook_wrap_mutex);
    hook_debug("Hook func: %llx failed, err: %d\n", hook->func_addr, err);
    return err;
}


void unhook(void *func)
{
    uint64_t origin = branch_func_addr((uint64_t)func);
    hook_t *hook = hook_get_mem_from_origin(origin);
    hook_err_t err;
    if (!hook) return;
    mutex_lock(&hook_wrap_mutex);
    hook = hook_get_mem_from_origin(origin);
    if (!hook) {
        mutex_unlock(&hook_wrap_mutex);
        return;
    }
    err = hook_uninstall(hook);
    if (err) {
        hook_err("Unhook func: %llx failed, err=%d\n", (uint64_t)func, err);
        mutex_unlock(&hook_wrap_mutex);
        return;
    }
    hook_mem_retire(hook);
    mutex_unlock(&hook_wrap_mutex);
    hook_debug("Unhook func: %llx\n", (uint64_t)func);
}


static hook_err_t hook_chain_prepare(hook_chain_t *chain, int32_t argno)
{
    uint32_t *transit = chain->transit;
    uint64_t dispatcher = hook_dispatcher_addr(argno);
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

hook_err_t hook_chain_add(hook_chain_t *chain, void *before, void *after, void *udata)
{
    unsigned long flags;
    hook_err_t ret;
    
    if (!chain) {
        return -HOOK_BAD_ARG;
    }
    // 使用自旋锁保护
    spin_lock_irqsave(&chain->lock, flags);
    ret = hook_chain_slots_add_common(HOOK_CHAIN_NUM, &chain->chain_items_max, chain->states, chain->befores,
                                      chain->afters, chain->udata, before, after, udata);
    if (!ret) {
        hook_debug("Wrap chain add: %llx, %llx, %llx successed\n", chain->hook.func_addr, before, (uint64_t)after);
        goto out;
    }
    hook_debug("Wrap chain add: %llx, %llx, %llx failed: %d\n", chain->hook.func_addr, before, (uint64_t)after, ret);
out:
    spin_unlock_irqrestore(&chain->lock, flags);
    return ret;
}


void hook_chain_remove(hook_chain_t *chain, void *before, void *after)
{
    unsigned long flags;

    if (!chain) {
        return ;
    }
    spin_lock_irqsave(&chain->lock, flags);
    hook_chain_slots_remove_common(HOOK_CHAIN_NUM, chain->states, chain->befores, chain->afters, chain->udata, before,
                                   after);
    spin_unlock_irqrestore(&chain->lock, flags);
    hook_debug("Wrap chain remove: %llx, %llx, %llx\n", chain->hook.func_addr, before, (uint64_t)after);
}


hook_err_t hook_wrap(void *func, int32_t argno, void *before, void *after, void *udata)
{
    if (is_bad_address(func)) return -HOOK_BAD_ADDRESS;
    uint64_t faddr = (uint64_t)func;
    uint64_t origin = branch_func_addr(faddr);
    if (is_bad_address(func)) return -HOOK_BAD_ADDRESS;

    mutex_lock(&hook_wrap_mutex);
    hook_chain_t *chain = (hook_chain_t *)hook_get_mem_from_origin(origin);
    if (chain) {
        mutex_unlock(&hook_wrap_mutex);
        return hook_chain_add(chain, before, after, udata);
    }
    chain = (hook_chain_t *)hook_mem_zalloc(origin, INLINE_CHAIN);
    if (!chain) {
        mutex_unlock(&hook_wrap_mutex);
        return -HOOK_NO_MEM;
    }
    spin_lock_init(&chain->lock);
    chain->chain_items_max = 0;
    hook_t *hook = &chain->hook;
    hook->func_addr = faddr;
    hook->origin_addr = origin;
    hook->replace_addr = (uint64_t)chain->transit;
    hook->relo_addr = (uint64_t)hook->relo_insts;
    hook_debug("Wrap func: %llx, origin: %llx, replace: %llx, relocate: %llx, chain: %llx\n", hook->func_addr,
          hook->origin_addr, hook->replace_addr, hook->relo_addr, (uint64_t)chain);
    hook_err_t err = hook_prepare(hook);
    if (err) goto err;
    err = hook_chain_prepare(chain, argno);
    if (err) goto err;
    err = hook_chain_add(chain, before, after, udata);
    if (err) goto err;
    err = hook_chain_install(chain);
    if (err) goto err;
    mutex_unlock(&hook_wrap_mutex);
    hook_debug("Wrap func: %llx succsseed\n", hook->func_addr);
    return HOOK_NO_ERR;
err:
    hook_mem_free(chain);
    mutex_unlock(&hook_wrap_mutex);
    hook_debug("Wrap func: %llx failed, err: %d\n", hook->func_addr, err);
    return err;
}


void hook_unwrap_remove(void *func, void *before, void *after, int remove)
{
    if (is_bad_address(func)) return;
    uint64_t faddr = (uint64_t)func;
    uint64_t origin = branch_func_addr(faddr);
    if (is_bad_address(func)) return;
    mutex_lock(&hook_wrap_mutex);
    hook_chain_t *chain = (hook_chain_t *)hook_get_mem_from_origin(origin);
    if (!chain) {
        mutex_unlock(&hook_wrap_mutex);
        return;
    }
    hook_chain_remove(chain, before, after);
    if (!remove) {
        mutex_unlock(&hook_wrap_mutex);
        return;
    }
    // todo:
    if (!hook_chain_slots_all_empty_common(HOOK_CHAIN_NUM, chain->states)) {
        mutex_unlock(&hook_wrap_mutex);
        return;
    }
    if (hook_chain_uninstall(chain)) {
        mutex_unlock(&hook_wrap_mutex);
        return;
    }
    synchronize_rcu();
    hook_mem_retire(chain);
    mutex_unlock(&hook_wrap_mutex);
    hook_debug("Unwrap func: %llx\n", (uint64_t)func);
}
