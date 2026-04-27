/* 
 * hook_lkm.h - Linux内核Hook框架头文件
 * 
 * 移植自KernelPatch项目的hook实现
 * 提供ARM64架构下的内核函数拦截和修改能力
 */

#ifndef __HOOK_LKM_H__
#define __HOOK_LKM_H__

#include "hook_types.h"
#include "hook_runtime.h"

/*
 * 指令处理函数
 */

 bool is_hooked(uint32_t *inst);
 void rewrite_trampoline(hook_t *hook, uint64_t addr) ;

/**
 * 创建从一个地址到另一个地址的分支指令
 * @param tramp_buf 目标缓冲区
 * @param src_addr 源地址
 * @param dst_addr 目标地址
 * @return 写入的指令数量
 */
int32_t branch_from_to(uint32_t *tramp_buf, uint64_t src_addr, uint64_t dst_addr);

/**
 * 创建相对跳转指令
 * @param buf 目标缓冲区
 * @param src_addr 源地址
 * @param dst_addr 目标地址
 * @return 写入的指令数量
 */
int32_t branch_relative(uint32_t *buf, uint64_t src_addr, uint64_t dst_addr);

/**
 * 创建绝对跳转指令
 * @param buf 目标缓冲区
 * @param addr 目标地址
 * @return 写入的指令数量
 */
int32_t branch_absolute(uint32_t *buf, uint64_t addr);

uint64_t branch_func_addr_once(uint64_t addr);

uint64_t branch_func_addr(uint64_t addr);

/**
 * 创建绝对返回指令
 * @param buf 目标缓冲区
 * @param addr 目标地址
 * @return 写入的指令数量
 */
int32_t ret_absolute(uint32_t *buf, uint64_t addr);


/**
 * 重定位指令
 * @param hook Hook结构指针
 * @param inst_addr 指令地址
 * @param inst 指令
 * @return 错误码
 */
hook_err_t relocate_inst(hook_t *hook, uint64_t inst_addr, uint32_t inst);


/*
 * 基本Hook操作函数
 */

/**
 * 准备Hook
 * @param hook Hook结构指针
 * @return 错误码
 */
hook_err_t hook_prepare(hook_t *hook);

/**
 * 安装Hook
 * @param hook Hook结构指针
 */
hook_err_t hook_install(hook_t *hook);

/**
 * 卸载Hook
 * @param hook Hook结构指针
 */
hook_err_t hook_uninstall(hook_t *hook);

/**
 * 一步完成Hook操作
 * @param func 目标函数地址
 * @param replace 替换函数地址
 * @param backup 原始函数备份地址指针
 * @return 错误码
 */
hook_err_t hook(void *func, void *replace, void **backup);

/**
 * 卸载Hook
 * @param func 目标函数地址
 */
void unhook(void *func);

/*
 * Hook链操作函数
 */

/**
 * 向Hook链添加回调
 * @param chain Hook链指针
 * @param before 前置回调函数
 * @param after 后置回调函数
 * @param udata 用户数据
 * @return 错误码
 */
hook_err_t hook_chain_add(hook_chain_t *chain, void *before, void *after, void *udata);

/**
 * 从Hook链移除回调
 * @param chain Hook链指针
 * @param before 前置回调函数
 * @param after 后置回调函数
 */
void hook_chain_remove(hook_chain_t *chain, void *before, void *after);

/**
 * 包装函数调用，添加前置和后置回调
 * @param func 目标函数地址
 * @param argno 参数数量
 * @param before 前置回调函数
 * @param after 后置回调函数
 * @param udata 用户数据
 * @return 错误码
 */
hook_err_t hook_wrap(void *func, int32_t argno, void *before, void *after, void *udata);

/**
 * 解除函数包装
 * @param func 目标函数地址
 * @param before 前置回调函数
 * @param after 后置回调函数
 * @param remove 是否完全移除
 */
void hook_unwrap_remove(void *func, void *before, void *after, int remove);

/**
 * 解除函数包装并移除
 * @param func 目标函数地址
 * @param before 前置回调函数
 * @param after 后置回调函数
 */
static inline void hook_unwrap(void *func, void *before, void *after) {
    hook_unwrap_remove(func, before, after, 1);
}

/*
 * 函数指针Hook操作函数
 */

/**
 * Hook函数指针
 * @param fp_addr 函数指针地址
 * @param replace 替换函数地址
 * @param backup 原始函数备份地址指针
 */
int fp_hook(uintptr_t fp_addr, void *replace, void **backup);

/**
 * 卸载函数指针Hook
 * @param fp_addr 函数指针地址
 * @param backup 原始函数备份地址
 */
int fp_unhook(uintptr_t fp_addr, void *backup);

/**
 * 包装函数指针调用，添加前置和后置回调
 * @param fp_addr 函数指针地址
 * @param argno 参数数量
 * @param before 前置回调函数
 * @param after 后置回调函数
 * @param udata 用户数据
 * @return 错误码
 */
hook_err_t fp_hook_wrap(uintptr_t fp_addr, int32_t argno, void *before, void *after, void *udata);

/**
 * 解除函数指针包装
 * @param fp_addr 函数指针地址
 * @param before 前置回调函数
 * @param after 后置回调函数
 */
void fp_hook_unwrap(uintptr_t fp_addr, void *before, void *after);

static inline void *fp_get_origin_func(void *hook_args)
{
    hook_fargs0_t *args = (hook_fargs0_t *)hook_args;
    fp_hook_chain_t *chain = (fp_hook_chain_t *)args->chain;
    return (void *)chain->hook.origin_fp;
}

static inline hook_err_t hook_chain_install(hook_chain_t *chain)
{
    return hook_install(&chain->hook);
}

static inline hook_err_t hook_chain_uninstall(hook_chain_t *chain)
{
    return hook_uninstall(&chain->hook);
}

#define HOOK_WRAP_ARITY_LIST(X)        \
    X(0)                               \
    X(1)                               \
    X(2)                               \
    X(3)                               \
    X(4)                               \
    X(5)                               \
    X(6)                               \
    X(7)                               \
    X(8)                               \
    X(9)                               \
    X(10)                              \
    X(11)                              \
    X(12)

#define DEFINE_HOOK_WRAP_HELPER(n)                                                                  \
    static inline hook_err_t hook_wrap##n(void *func, hook_chain##n##_callback before,             \
                                          hook_chain##n##_callback after, void *udata)              \
    {                                                                                               \
        return hook_wrap(func, n, before, after, udata);                                            \
    }

#define DEFINE_FP_HOOK_WRAP_HELPER(n)                                                               \
    static inline hook_err_t fp_hook_wrap##n(uintptr_t fp_addr, hook_chain##n##_callback before,   \
                                             hook_chain##n##_callback after, void *udata)           \
    {                                                                                               \
        return fp_hook_wrap(fp_addr, n, before, after, udata);                                      \
    }

HOOK_WRAP_ARITY_LIST(DEFINE_HOOK_WRAP_HELPER)
HOOK_WRAP_ARITY_LIST(DEFINE_FP_HOOK_WRAP_HELPER)

#undef DEFINE_HOOK_WRAP_HELPER
#undef DEFINE_FP_HOOK_WRAP_HELPER
#undef HOOK_WRAP_ARITY_LIST


#endif /* __HOOK_LKM_H__ */
