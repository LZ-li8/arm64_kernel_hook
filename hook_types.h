/*
 * hook_types.h - Hook框架通用类型与常量定义
 */

#ifndef __HOOK_TYPES_H__
#define __HOOK_TYPES_H__

#include <linux/compiler.h>
#include <linux/spinlock.h>
#include <linux/stddef.h>
#include <linux/types.h>

//#define __noreturn __attribute__((__noreturn__))
#define __noinline __attribute__((__noinline__))
//#define __always_inline inline __attribute__((__always_inline__))

#define ___section(name) __attribute__((section(name)))

extern __u64 mod_base;
extern __u64 mod_end;

/**
 * Hook错误码定义
 */
typedef enum {
    HOOK_NO_ERR = 0,            /* 操作成功 */
    HOOK_BAD_ARG = 2048,        /* 无效的参数 */
    HOOK_NOT_FOUND = 2047,
    HOOK_BAD_ADDRESS = 4095,    /* 无效的地址 */
    HOOK_DUPLICATED = 4094,     /* 重复的Hook操作 */
    HOOK_NO_MEM = 4093,         /* 内存分配失败 */
    HOOK_BAD_RELO = 4092,       /* 指令重定位失败 */
    HOOK_TRANSIT_NO_MEM = 4091, /* 过渡代码内存不足 */
    HOOK_CHAIN_FULL = 4090,     /* Hook链已满 */
} hook_err_t;

/**
 * Hook类型定义
 */
enum hook_type {
    NONE = 0,               /* 无Hook */
    INLINE,                 /* 内联Hook */
    INLINE_CHAIN,           /* 内联Hook链 */
    FUNCTION_POINTER_CHAIN, /* 函数指针Hook链 */
};

/**
 * 常量定义
 */
#define HOOK_MEM_REGION_NUM 4
#define TRAMPOLINE_NUM 4
#define TRAMPOLINE_MAX_NUM 6
#define RELOCATE_INST_NUM (TRAMPOLINE_MAX_NUM * 8 + 4)
#define HOOK_CHAIN_NUM 0x10
#define TRANSIT_INST_NUM 0x100
#define FP_HOOK_CHAIN_NUM 0x20
#define HOOK_LOCAL_DATA_NUM 8

/**
 * ARM64指令常量
 */
#define ARM64_NOP 0xd503201f
#define ARM64_BTI_C 0xd503245f
#define ARM64_BTI_J 0xd503249f
#define ARM64_BTI_JC 0xd50324df
#define ARM64_PACIASP 0xd503233f
#define ARM64_PACIBSP 0xd503237f
#define ARM64_RET 0xd65f03c0

/**
 * 辅助宏定义
 */
#define bits32(n, high, low) ((uint32_t)((n) << (31u - (high))) >> (31u - (high) + (low)))
#define bit(n, st) (((n) >> (st)) & 1)
#define sign64_extend(n, len) \
    (((uint64_t)((n) << (63u - (len - 1))) >> 63u) ? ((n) | (0xFFFFFFFFFFFFFFFFull << (len))) : (uint64_t)(n))
#define align_ceil(x, align) (((u64)(x) + (u64)(align) - 1) & ~((u64)(align) - 1))

#define local_offsetof(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)
#define local_container_of(ptr, type, member) ({ (type *)((char *)(ptr) - local_offsetof(type, member)); })

/**
 * Hook链状态定义
 */
typedef int8_t chain_item_state;
#define CHAIN_ITEM_STATE_EMPTY 0
#define CHAIN_ITEM_STATE_READY 1
#define CHAIN_ITEM_STATE_BUSY 2

/**
 * 基本Hook结构
 */
typedef struct {
    uint64_t func_addr;
    uint64_t origin_addr;
    uint64_t replace_addr;
    uint64_t relo_addr;
    int32_t tramp_insts_num;
    int32_t relo_insts_num;
    uint32_t origin_insts[TRAMPOLINE_MAX_NUM] __attribute__((aligned(8)));
    uint32_t tramp_insts[TRAMPOLINE_MAX_NUM] __attribute__((aligned(8)));
    uint32_t relo_insts[RELOCATE_INST_NUM] __attribute__((aligned(8)));
} hook_t __attribute__((aligned(8)));

typedef struct {
    union {
        struct {
            uint64_t data0;
            uint64_t data1;
            uint64_t data2;
            uint64_t data3;
            uint64_t data4;
            uint64_t data5;
            uint64_t data6;
            uint64_t data7;
        };
        uint64_t data[HOOK_LOCAL_DATA_NUM];
    };
} hook_local_t;

typedef struct {
    void *chain;
    int skip_origin;
    hook_local_t local;
    uint64_t ret;
    union {
        struct {
        };
        uint64_t args[0];
    };
} hook_fargs0_t __attribute__((aligned(8)));

typedef struct {
    void *chain;
    int skip_origin;
    hook_local_t local;
    uint64_t ret;
    union {
        struct {
            uint64_t arg0;
            uint64_t arg1;
            uint64_t arg2;
            uint64_t arg3;
        };
        uint64_t args[4];
    };
} hook_fargs4_t __attribute__((aligned(8)));

typedef hook_fargs4_t hook_fargs1_t;
typedef hook_fargs4_t hook_fargs2_t;
typedef hook_fargs4_t hook_fargs3_t;

typedef struct {
    void *chain;
    int skip_origin;
    hook_local_t local;
    uint64_t ret;
    union {
        struct {
            uint64_t arg0;
            uint64_t arg1;
            uint64_t arg2;
            uint64_t arg3;
            uint64_t arg4;
            uint64_t arg5;
            uint64_t arg6;
            uint64_t arg7;
        };
        uint64_t args[8];
    };
} hook_fargs8_t __attribute__((aligned(8)));

typedef hook_fargs8_t hook_fargs5_t;
typedef hook_fargs8_t hook_fargs6_t;
typedef hook_fargs8_t hook_fargs7_t;

typedef struct {
    void *chain;
    int skip_origin;
    hook_local_t local;
    uint64_t ret;
    union {
        struct {
            uint64_t arg0;
            uint64_t arg1;
            uint64_t arg2;
            uint64_t arg3;
            uint64_t arg4;
            uint64_t arg5;
            uint64_t arg6;
            uint64_t arg7;
            uint64_t arg8;
            uint64_t arg9;
            uint64_t arg10;
            uint64_t arg11;
        };
        uint64_t args[12];
    };
} hook_fargs12_t __attribute__((aligned(8)));

typedef hook_fargs12_t hook_fargs9_t;
typedef hook_fargs12_t hook_fargs10_t;
typedef hook_fargs12_t hook_fargs11_t;

typedef void (*hook_chain0_callback)(hook_fargs0_t *fargs, void *udata);
typedef void (*hook_chain1_callback)(hook_fargs1_t *fargs, void *udata);
typedef void (*hook_chain2_callback)(hook_fargs2_t *fargs, void *udata);
typedef void (*hook_chain3_callback)(hook_fargs3_t *fargs, void *udata);
typedef void (*hook_chain4_callback)(hook_fargs4_t *fargs, void *udata);
typedef void (*hook_chain5_callback)(hook_fargs5_t *fargs, void *udata);
typedef void (*hook_chain6_callback)(hook_fargs6_t *fargs, void *udata);
typedef void (*hook_chain7_callback)(hook_fargs7_t *fargs, void *udata);
typedef void (*hook_chain8_callback)(hook_fargs8_t *fargs, void *udata);
typedef void (*hook_chain9_callback)(hook_fargs9_t *fargs, void *udata);
typedef void (*hook_chain10_callback)(hook_fargs10_t *fargs, void *udata);
typedef void (*hook_chain11_callback)(hook_fargs11_t *fargs, void *udata);
typedef void (*hook_chain12_callback)(hook_fargs12_t *fargs, void *udata);

typedef struct _hook_chain {
    hook_t hook;
    int32_t chain_items_max;
    chain_item_state states[HOOK_CHAIN_NUM];
    void *udata[HOOK_CHAIN_NUM];
    void *befores[HOOK_CHAIN_NUM];
    void *afters[HOOK_CHAIN_NUM];
    uint32_t transit[TRANSIT_INST_NUM];
    spinlock_t lock;
} hook_chain_t __attribute__((aligned(8)));

typedef struct {
    uintptr_t fp_addr;
    uint64_t replace_addr;
    uint64_t origin_fp;
} fp_hook_t __attribute__((aligned(8)));

typedef struct _fphook_chain {
    fp_hook_t hook;
    int32_t chain_items_max;
    chain_item_state states[FP_HOOK_CHAIN_NUM];
    void *udata[FP_HOOK_CHAIN_NUM];
    void *befores[FP_HOOK_CHAIN_NUM];
    void *afters[FP_HOOK_CHAIN_NUM];
    uint32_t transit[TRANSIT_INST_NUM];
    spinlock_t lock;
} fp_hook_chain_t __attribute__((aligned(8)));

#endif /* __HOOK_TYPES_H__ */
