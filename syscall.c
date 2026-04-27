/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include "syscall.h"
#include "hook_utils.h"
#include "log.h"
#include "linux/compiler_types.h"


#include <uapi/asm-generic/errno.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/kernel.h>


uintptr_t *sys_call_table = 0;
//KP_EXPORT_SYMBOL(sys_call_table);

uintptr_t *compat_sys_call_table = 0;
//KP_EXPORT_SYMBOL(compat_sys_call_table);

int has_syscall_wrapper = 0;
//KP_EXPORT_SYMBOL(has_syscall_wrapper);

int has_config_compat = 0;
//KP_EXPORT_SYMBOL(has_config_compat);


//fs/exec.c to get_user_arg_ptr


typedef long (*warp_raw_syscall_f)(const struct pt_regs *regs);
typedef long (*raw_syscall0_f)(void);

static __always_inline void init_raw_syscall_regs(struct pt_regs *regs, long nr)
{
    *regs = (struct pt_regs){ 0 };
    regs->syscallno = nr;
    regs->regs[8] = nr;
}

#define RAW_SYSCALL_ARITY_LIST(X)                                                                                  \
    X(1, (long arg0), regs.regs[0] = arg0;, arg0)                                                                  \
    X(2, (long arg0, long arg1), regs.regs[0] = arg0; regs.regs[1] = arg1;, arg0, arg1)                           \
    X(3, (long arg0, long arg1, long arg2),                                                                         \
      regs.regs[0] = arg0; regs.regs[1] = arg1; regs.regs[2] = arg2;, arg0, arg1, arg2)                           \
    X(4, (long arg0, long arg1, long arg2, long arg3),                                                              \
      regs.regs[0] = arg0; regs.regs[1] = arg1; regs.regs[2] = arg2; regs.regs[3] = arg3;,                        \
      arg0, arg1, arg2, arg3)                                                                                       \
    X(5, (long arg0, long arg1, long arg2, long arg3, long arg4),                                                   \
      regs.regs[0] = arg0; regs.regs[1] = arg1; regs.regs[2] = arg2; regs.regs[3] = arg3; regs.regs[4] = arg4;, \
      arg0, arg1, arg2, arg3, arg4)                                                                                 \
    X(6, (long arg0, long arg1, long arg2, long arg3, long arg4, long arg5),                                        \
      regs.regs[0] = arg0; regs.regs[1] = arg1; regs.regs[2] = arg2; regs.regs[3] = arg3; regs.regs[4] = arg4;  \
          regs.regs[5] = arg5;,                                                                                     \
      arg0, arg1, arg2, arg3, arg4, arg5)

#define RAW_SYSCALL_UNWRAP(...) __VA_ARGS__
#define DEFINE_RAW_SYSCALL_TYPE(n, decl_tuple, set_regs, ...) \
    typedef long (*raw_syscall##n##_f)(RAW_SYSCALL_UNWRAP decl_tuple);
RAW_SYSCALL_ARITY_LIST(DEFINE_RAW_SYSCALL_TYPE)
#undef DEFINE_RAW_SYSCALL_TYPE

#define DEFINE_RAW_SYSCALL0()                                                \
    __nocfi long raw_syscall0(long nr)                                       \
    {                                                                        \
        uintptr_t addr = syscalln_addr(nr, 0);                               \
        if (has_syscall_wrapper) {                                            \
            struct pt_regs regs;                                              \
            init_raw_syscall_regs(&regs, nr);                                 \
            return ((warp_raw_syscall_f)addr)(&regs);                         \
        }                                                                    \
        return ((raw_syscall0_f)addr)();                                      \
    }

#define DEFINE_RAW_SYSCALL(n, decl_tuple, set_regs, ...)                       \
    __nocfi long raw_syscall##n(long nr, RAW_SYSCALL_UNWRAP decl_tuple)        \
    {                                                                          \
        uintptr_t addr = syscalln_addr(nr, 0);                                 \
        if (has_syscall_wrapper) {                                              \
            struct pt_regs regs;                                                \
            init_raw_syscall_regs(&regs, nr);                                   \
            set_regs                                                            \
            return ((warp_raw_syscall_f)addr)(&regs);                           \
        }                                                                      \
        return ((raw_syscall##n##_f)addr)(__VA_ARGS__);                        \
    }

__nocfi
uintptr_t syscalln_name_addr(int nr, int is_compat)
{
    const char *name = 0;
    if (!is_compat) {
        if (syscall_name_table[nr].addr) {
            return syscall_name_table[nr].addr;
        }
        name = syscall_name_table[nr].name;
    } else {
        if (compat_syscall_name_table[nr].addr) {
            return compat_syscall_name_table[nr].addr;
        }
        name = compat_syscall_name_table[nr].name;
    }

    if (!name) return 0;

    const char *prefix[2];
    prefix[0] = "__arm64_";
    prefix[1] = "";
    const char *suffix[3];
    suffix[0] = ".cfi_jt";
    suffix[1] = ".cfi";
    suffix[2] = "";

    uintptr_t addr = 0;

    char buffer[256];
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 3; j++) {
            snprintf(buffer, sizeof(buffer), "%s%s%s", prefix[i], name, suffix[j]);
            addr = m_kallsyms_lookup_name(buffer);
            if (addr) break;
        }
        if (addr) break;
    }
    if (!is_compat) {
        syscall_name_table[nr].addr = addr;
    } else {
        compat_syscall_name_table[nr].addr = addr;
    }
    return addr;
}
//KP_EXPORT_SYMBOL(syscalln_name_addr);

uintptr_t syscalln_addr(int nr, int is_compat)
{
    if (!is_compat && sys_call_table) return sys_call_table[nr];
    if (is_compat && compat_sys_call_table) return compat_sys_call_table[nr];
    return syscalln_name_addr(nr, is_compat);
}
//KP_EXPORT_SYMBOL(syscalln_addr);

DEFINE_RAW_SYSCALL0()
RAW_SYSCALL_ARITY_LIST(DEFINE_RAW_SYSCALL)

#undef DEFINE_RAW_SYSCALL0
#undef DEFINE_RAW_SYSCALL
#undef RAW_SYSCALL_UNWRAP
#undef RAW_SYSCALL_ARITY_LIST

hook_err_t fp_wrap_syscalln(int nr, int narg, int is_compat, void *before, void *after, void *udata)
{
    if (!is_compat) {
        if (!sys_call_table) return HOOK_BAD_ADDRESS;
        uintptr_t fp_addr = (uintptr_t)(sys_call_table + nr);
        if (has_syscall_wrapper) narg = 1;
        return fp_hook_wrap(fp_addr, narg, before, after, udata);
    } else {
        if (!compat_sys_call_table) return HOOK_BAD_ADDRESS;
        uintptr_t fp_addr = (uintptr_t)(compat_sys_call_table + nr);
        if (has_syscall_wrapper) narg = 1;
        return fp_hook_wrap(fp_addr, narg, before, after, udata);
    }
}
//KP_EXPORT_SYMBOL(fp_wrap_syscalln);

void fp_unwrap_syscalln(int nr, int is_compat, void *before, void *after)
{
    if (!is_compat) {
        if (!sys_call_table) return;
        uintptr_t fp_addr = (uintptr_t)(sys_call_table + nr);
        fp_hook_unwrap(fp_addr, before, after);
    } else {
        if (!compat_sys_call_table) return;
        uintptr_t fp_addr = (uintptr_t)(compat_sys_call_table + nr);
        fp_hook_unwrap(fp_addr, before, after);
    }
}
//KP_EXPORT_SYMBOL(fp_unwrap_syscalln);

/*
sys_xxx.cfi_jt

hint #0x22  # bti c
b #0xfffffffffeb452f4
*/
hook_err_t inline_wrap_syscalln(int nr, int narg, int is_compat, void *before, void *after, void *udata)
{
    uintptr_t addr = syscalln_name_addr(nr, is_compat);
    if (!addr) return -HOOK_BAD_ADDRESS;
    if (has_syscall_wrapper) narg = 1;
    return hook_wrap((void *)addr, narg, before, after, udata);
}
//KP_EXPORT_SYMBOL(inline_wrap_syscalln);

void inline_unwrap_syscalln(int nr, int is_compat, void *before, void *after)
{
    uintptr_t addr = syscalln_name_addr(nr, is_compat);
    hook_unwrap((void *)addr, before, after);
}
//KP_EXPORT_SYMBOL(inline_unwrap_syscalln);

hook_err_t hook_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
    if (sys_call_table) return fp_wrap_syscalln(nr, narg, 0, before, after, udata);
    return inline_wrap_syscalln(nr, narg, 0, before, after, udata);
}
//KP_EXPORT_SYMBOL(hook_syscalln);

void unhook_syscalln(int nr, void *before, void *after)
{
    if (sys_call_table) return fp_unwrap_syscalln(nr, 0, before, after);
    return inline_unwrap_syscalln(nr, 0, before, after);
}
//KP_EXPORT_SYMBOL(unhook_syscalln);

hook_err_t hook_compat_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
    if (compat_sys_call_table) return fp_wrap_syscalln(nr, narg, 1, before, after, udata);
    return inline_wrap_syscalln(nr, narg, 1, before, after, udata);
}
//KP_EXPORT_SYMBOL(hook_compat_syscalln);

void unhook_compat_syscalln(int nr, void *before, void *after)
{
    if (compat_sys_call_table) return fp_unwrap_syscalln(nr, 1, before, after);
    return inline_unwrap_syscalln(nr, 1, before, after);
}
//KP_EXPORT_SYMBOL(unhook_compat_syscalln);

void syscall_init(void)
{
    // for (int i = 0; i < sizeof(syscall_name_table) / sizeof(syscall_name_table[0]); i++) {
    //     uintptr_t *addr = (uintptr_t *)&syscall_name_table[i].name;
    //     *addr = link2runtime(*addr);
    // }

    // for (int i = 0; i < sizeof(compat_syscall_name_table) / sizeof(compat_syscall_name_table[0]); i++) {
    //     uintptr_t *addr = (uintptr_t *)&compat_syscall_name_table[i].name;
    //     *addr = link2runtime(*addr);
    // }

    sys_call_table = (typeof(sys_call_table))m_kallsyms_lookup_name("sys_call_table");
    //log_boot("sys_call_table addr: %llx\n", sys_call_table);

    compat_sys_call_table = (typeof(compat_sys_call_table))m_kallsyms_lookup_name("compat_sys_call_table");
    //log_boot("compat_sys_call_table addr: %llx\n", compat_sys_call_table);

    has_config_compat = 0;
    has_syscall_wrapper = 0;

    if (m_kallsyms_lookup_name("__arm64_compat_sys_openat")) {
        has_config_compat = 1;
        has_syscall_wrapper = 1;
    } else {
        if (m_kallsyms_lookup_name("compat_sys_call_table") || m_kallsyms_lookup_name("compat_sys_openat")) {
            has_config_compat = 1;
        }
        if (m_kallsyms_lookup_name("__arm64_sys_openat")) {
            has_syscall_wrapper = 1;
        }
    }

    hook_debug("syscall config_compat: %d\n", has_config_compat);
    hook_debug("syscall has_wrapper: %d\n", has_syscall_wrapper);
}
