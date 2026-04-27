/*
 * hook_transit_ops.h - hook/fp_hook共享的transit函数生成宏
 */

#ifndef __HOOK_TRANSIT_OPS_H__
#define __HOOK_TRANSIT_OPS_H__

#include "hook_chain_ops.h"

static __always_inline void *hook_transit_owner_ptr(void)
{
    void *owner;

    asm volatile(
        "ldr %x0, 1f\n"
        "b 2f\n"
        ".align 3\n"
        "1: .quad %1\n"
        "2:\n"
        : "=r"(owner)
        : "i"(HOOK_TRANSIT_OWNER_MAGIC));

    return owner;
}

#define DEFINE_TRANSIT_FUNC0(name, end_name, section_name, chain_type, origin_field, max_items)           \
    uint64_t __noinline __attribute__((section(section_name))) name(void)                                  \
    {                                                                                                      \
        void *before_snapshot[max_items];                                                                  \
        void *after_snapshot[max_items];                                                                   \
        void *udata_snapshot[max_items];                                                                   \
        int32_t snapshot_max;                                                                              \
        uint64_t origin_addr;                                                                              \
        chain_type *hook_chain = (chain_type *)hook_transit_owner_ptr();                                   \
        hook_fargs0_t fargs;                                                                               \
        fargs.skip_origin = 0;                                                                             \
        fargs.chain = hook_chain;                                                                          \
        snapshot_max = hook_chain_snapshot_common(max_items, &hook_chain->lock, &hook_chain->chain_items_max, \
                                                  hook_chain->states, hook_chain->befores,                 \
                                                  hook_chain->afters, hook_chain->udata,                   \
                                                  before_snapshot, after_snapshot, udata_snapshot);        \
        origin_addr = READ_ONCE(hook_chain->origin_field);                                                 \
        for (int32_t i = 0; i < snapshot_max; i++) {                                                       \
            hook_chain0_callback func = (hook_chain0_callback)before_snapshot[i];                          \
            if (func)                                                                                      \
                func(&fargs, udata_snapshot[i]);                                                           \
        }                                                                                                  \
        if (!fargs.skip_origin) {                                                                          \
            uint64_t (*origin_func)(void) = (void *)origin_addr;                                           \
            fargs.ret = origin_func();                                                                     \
        }                                                                                                  \
        for (int32_t i = snapshot_max - 1; i >= 0; i--) {                                                 \
            hook_chain0_callback func = (hook_chain0_callback)after_snapshot[i];                           \
            if (func)                                                                                      \
                func(&fargs, udata_snapshot[i]);                                                           \
        }                                                                                                  \
        return fargs.ret;                                                                                  \
    }                                                                                                      \
    __noinline __attribute__((section(section_name))) void end_name(void)                                  \
    {                                                                                                      \
    }

#define DEFINE_TRANSIT_FUNC4(name, end_name, section_name, chain_type, origin_field, max_items)           \
    uint64_t __noinline __attribute__((section(section_name)))                                             \
    name(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3)                                      \
    {                                                                                                      \
        void *before_snapshot[max_items];                                                                  \
        void *after_snapshot[max_items];                                                                   \
        void *udata_snapshot[max_items];                                                                   \
        int32_t snapshot_max;                                                                              \
        uint64_t origin_addr;                                                                              \
        chain_type *hook_chain = (chain_type *)hook_transit_owner_ptr();                                   \
        hook_fargs4_t fargs;                                                                               \
        fargs.skip_origin = 0;                                                                             \
        fargs.arg0 = arg0;                                                                                 \
        fargs.arg1 = arg1;                                                                                 \
        fargs.arg2 = arg2;                                                                                 \
        fargs.arg3 = arg3;                                                                                 \
        fargs.chain = hook_chain;                                                                          \
        snapshot_max = hook_chain_snapshot_common(max_items, &hook_chain->lock, &hook_chain->chain_items_max, \
                                                  hook_chain->states, hook_chain->befores,                 \
                                                  hook_chain->afters, hook_chain->udata,                   \
                                                  before_snapshot, after_snapshot, udata_snapshot);        \
        origin_addr = READ_ONCE(hook_chain->origin_field);                                                 \
        for (int32_t i = 0; i < snapshot_max; i++) {                                                       \
            hook_chain4_callback func = (hook_chain4_callback)before_snapshot[i];                          \
            if (func)                                                                                      \
                func(&fargs, udata_snapshot[i]);                                                           \
        }                                                                                                  \
        if (!fargs.skip_origin) {                                                                          \
            uint64_t (*origin_func)(uint64_t, uint64_t, uint64_t, uint64_t) = (void *)origin_addr;       \
            fargs.ret = origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3);                      \
        }                                                                                                  \
        for (int32_t i = snapshot_max - 1; i >= 0; i--) {                                                 \
            hook_chain4_callback func = (hook_chain4_callback)after_snapshot[i];                           \
            if (func)                                                                                      \
                func(&fargs, udata_snapshot[i]);                                                           \
        }                                                                                                  \
        return fargs.ret;                                                                                  \
    }                                                                                                      \
    __noinline __attribute__((section(section_name))) void end_name(void)                                  \
    {                                                                                                      \
    }

#define DEFINE_TRANSIT_FUNC8(name, end_name, section_name, chain_type, origin_field, max_items)           \
    uint64_t __noinline __attribute__((section(section_name)))                                             \
    name(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5,       \
         uint64_t arg6, uint64_t arg7)                                                                     \
    {                                                                                                      \
        void *before_snapshot[max_items];                                                                  \
        void *after_snapshot[max_items];                                                                   \
        void *udata_snapshot[max_items];                                                                   \
        int32_t snapshot_max;                                                                              \
        uint64_t origin_addr;                                                                              \
        chain_type *hook_chain = (chain_type *)hook_transit_owner_ptr();                                   \
        hook_fargs8_t fargs;                                                                               \
        fargs.skip_origin = 0;                                                                             \
        fargs.arg0 = arg0;                                                                                 \
        fargs.arg1 = arg1;                                                                                 \
        fargs.arg2 = arg2;                                                                                 \
        fargs.arg3 = arg3;                                                                                 \
        fargs.arg4 = arg4;                                                                                 \
        fargs.arg5 = arg5;                                                                                 \
        fargs.arg6 = arg6;                                                                                 \
        fargs.arg7 = arg7;                                                                                 \
        fargs.chain = hook_chain;                                                                          \
        snapshot_max = hook_chain_snapshot_common(max_items, &hook_chain->lock, &hook_chain->chain_items_max, \
                                                  hook_chain->states, hook_chain->befores,                 \
                                                  hook_chain->afters, hook_chain->udata,                   \
                                                  before_snapshot, after_snapshot, udata_snapshot);        \
        origin_addr = READ_ONCE(hook_chain->origin_field);                                                 \
        for (int32_t i = 0; i < snapshot_max; i++) {                                                       \
            hook_chain8_callback func = (hook_chain8_callback)before_snapshot[i];                          \
            if (func)                                                                                      \
                func(&fargs, udata_snapshot[i]);                                                           \
        }                                                                                                  \
        if (!fargs.skip_origin) {                                                                          \
            uint64_t (*origin_func)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,          \
                                    uint64_t, uint64_t) = (void *)origin_addr;                            \
            fargs.ret = origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3, fargs.arg4,          \
                                    fargs.arg5, fargs.arg6, fargs.arg7);                                  \
        }                                                                                                  \
        for (int32_t i = snapshot_max - 1; i >= 0; i--) {                                                 \
            hook_chain8_callback func = (hook_chain8_callback)after_snapshot[i];                           \
            if (func)                                                                                      \
                func(&fargs, udata_snapshot[i]);                                                           \
        }                                                                                                  \
        return fargs.ret;                                                                                  \
    }                                                                                                      \
    __noinline __attribute__((section(section_name))) void end_name(void)                                  \
    {                                                                                                      \
    }

#define DEFINE_TRANSIT_FUNC12(name, end_name, section_name, chain_type, origin_field, max_items)          \
    uint64_t __noinline __attribute__((section(section_name)))                                             \
    name(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5,       \
         uint64_t arg6, uint64_t arg7, uint64_t arg8, uint64_t arg9, uint64_t arg10, uint64_t arg11)     \
    {                                                                                                      \
        void *before_snapshot[max_items];                                                                  \
        void *after_snapshot[max_items];                                                                   \
        void *udata_snapshot[max_items];                                                                   \
        int32_t snapshot_max;                                                                              \
        uint64_t origin_addr;                                                                              \
        chain_type *hook_chain = (chain_type *)hook_transit_owner_ptr();                                   \
        hook_fargs12_t fargs;                                                                              \
        fargs.skip_origin = 0;                                                                             \
        fargs.arg0 = arg0;                                                                                 \
        fargs.arg1 = arg1;                                                                                 \
        fargs.arg2 = arg2;                                                                                 \
        fargs.arg3 = arg3;                                                                                 \
        fargs.arg4 = arg4;                                                                                 \
        fargs.arg5 = arg5;                                                                                 \
        fargs.arg6 = arg6;                                                                                 \
        fargs.arg7 = arg7;                                                                                 \
        fargs.arg8 = arg8;                                                                                 \
        fargs.arg9 = arg9;                                                                                 \
        fargs.arg10 = arg10;                                                                               \
        fargs.arg11 = arg11;                                                                               \
        fargs.chain = hook_chain;                                                                          \
        snapshot_max = hook_chain_snapshot_common(max_items, &hook_chain->lock, &hook_chain->chain_items_max, \
                                                  hook_chain->states, hook_chain->befores,                 \
                                                  hook_chain->afters, hook_chain->udata,                   \
                                                  before_snapshot, after_snapshot, udata_snapshot);        \
        origin_addr = READ_ONCE(hook_chain->origin_field);                                                 \
        for (int32_t i = 0; i < snapshot_max; i++) {                                                       \
            hook_chain12_callback func = (hook_chain12_callback)before_snapshot[i];                        \
            if (func)                                                                                      \
                func(&fargs, udata_snapshot[i]);                                                           \
        }                                                                                                  \
        if (!fargs.skip_origin) {                                                                          \
            uint64_t (*origin_func)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,          \
                                    uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) =        \
                (void *)origin_addr;                                                                       \
            fargs.ret = origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3, fargs.arg4,          \
                                    fargs.arg5, fargs.arg6, fargs.arg7, fargs.arg8, fargs.arg9,          \
                                    fargs.arg10, fargs.arg11);                                             \
        }                                                                                                  \
        for (int32_t i = snapshot_max - 1; i >= 0; i--) {                                                 \
            hook_chain12_callback func = (hook_chain12_callback)after_snapshot[i];                         \
            if (func)                                                                                      \
                func(&fargs, udata_snapshot[i]);                                                           \
        }                                                                                                  \
        return fargs.ret;                                                                                  \
    }                                                                                                      \
    __noinline __attribute__((section(section_name))) void end_name(void)                                  \
    {                                                                                                      \
    }

#define DEFINE_TRANSIT_SET(prefix, section_prefix, chain_type, origin_field, max_items)                     \
    DEFINE_TRANSIT_FUNC0(prefix##0, prefix##0##_end, section_prefix "0.text", chain_type, origin_field, max_items) \
    DEFINE_TRANSIT_FUNC4(prefix##4, prefix##4##_end, section_prefix "4.text", chain_type, origin_field, max_items) \
    DEFINE_TRANSIT_FUNC8(prefix##8, prefix##8##_end, section_prefix "8.text", chain_type, origin_field, max_items) \
    DEFINE_TRANSIT_FUNC12(prefix##12, prefix##12##_end, section_prefix "12.text", chain_type, origin_field, max_items)

#endif /* __HOOK_TRANSIT_OPS_H__ */
