/*
 * hook_utils.h - Hook框架工具函数和宏定义
 */

#ifndef _HOOK_UTILS_H
#define _HOOK_UTILS_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <asm/cacheflush.h>
#include <linux/uaccess.h>

#include "log.h"

// // 内存对齐宏
// #define ALIGN_UP(x, align) (((x) + (align) - 1) & ~((align) - 1))
// #define ALIGN_DOWN(x, align) ((x) & ~((align) - 1))

// 内存保护宏
#define PAGE_ROUND_DOWN(x) ((x) & PAGE_MASK)
#define PAGE_ROUND_UP(x) (((x) + PAGE_SIZE - 1) & PAGE_MASK)

// 缓存操作宏
#define CACHE_LINE_SIZE 64
#define CACHE_LINE_ROUND_UP(x) ALIGN_UP(x, CACHE_LINE_SIZE)
#define CACHE_LINE_ROUND_DOWN(x) ALIGN_DOWN(x, CACHE_LINE_SIZE)

// 内存屏障宏
#define MEMORY_BARRIER() asm volatile("dmb ish" ::: "memory")
#define INSTRUCTION_BARRIER() asm volatile("isb" ::: "memory")

// 指令缓存操作
// static inline void flush_icache_range(unsigned long start, unsigned long end)
// {
//     __flush_icache_range(start, end);
//     MEMORY_BARRIER();
//     INSTRUCTION_BARRIER();
// }


// 地址验证函数
// static inline int is_valid_address(void *addr)
// {
//     if (!addr) {
//         return 0;
//     }
    
//     // 检查地址是否在内核空间
//     if ((unsigned long)addr < PAGE_OFFSET) {
//         return 0;
//     }
    
//     // 检查地址是否可访问
//     if (access_ok(VERIFY_READ, addr, 1)) {
//         return 1;
//     }
    
//     return 0;
// }



#define INST_B 0x14000000      /* B指令 */
#define INST_BC 0x54000000     /* B.cond指令 */
#define INST_BL 0x94000000     /* BL指令 */
#define INST_ADR 0x10000000    /* ADR指令 */
#define INST_ADRP 0x90000000   /* ADRP指令 */
#define INST_LDR_32 0x18000000 /* LDR (32位)指令 */
#define INST_LDR_64 0x58000000 /* LDR (64位)指令 */
#define INST_LDRSW_LIT 0x98000000 /* LDRSW指令 */
#define INST_PRFM_LIT 0xD8000000  /* PRFM指令 */
#define INST_LDR_SIMD_32 0x1C000000  /* LDR SIMD (32位)指令 */
#define INST_LDR_SIMD_64 0x5C000000  /* LDR SIMD (64位)指令 */
#define INST_LDR_SIMD_128 0x9C000000 /* LDR SIMD (128位)指令 */
#define INST_CBZ 0x34000000   /* CBZ指令 */
#define INST_CBNZ 0x35000000  /* CBNZ指令 */
#define INST_TBZ 0x36000000   /* TBZ指令 */
#define INST_TBNZ 0x37000000  /* TBNZ指令 */
#define INST_HINT 0xD503201F  /* HINT指令 */
#define INST_IGNORE 0x0       /* 忽略的指令 */

/* 指令掩码 */
#define MASK_B 0xFC000000
#define MASK_BC 0xFF000010
#define MASK_BL 0xFC000000
#define MASK_ADR 0x9F000000
#define MASK_ADRP 0x9F000000
#define MASK_LDR_32 0xFF000000
#define MASK_LDR_64 0xFF000000
#define MASK_LDRSW_LIT 0xFF000000
#define MASK_PRFM_LIT 0xFF000000
#define MASK_LDR_SIMD_32 0xFF000000
#define MASK_LDR_SIMD_64 0xFF000000
#define MASK_LDR_SIMD_128 0xFF000000
#define MASK_CBZ 0x7F000000u
#define MASK_CBNZ 0x7F000000u
#define MASK_TBZ 0x7F000000u
#define MASK_TBNZ 0x7F000000u
#define MASK_HINT 0xFFFFF01F
#define MASK_IGNORE 0x0


// 指令对齐检查
static inline int is_instruction_aligned(void *addr)
{
    return ((unsigned long)addr & 0x3) == 0;
}

// 指令类型检查
static inline int is_branch_instruction(uint32_t inst)
{
    return (inst & MASK_B) == INST_B;
}

static inline int is_conditional_branch_instruction(uint32_t inst)
{
    return (inst & MASK_BC) == INST_BC;
}

static inline int is_register_branch_instruction(uint32_t inst)
{
    return (inst & 0xFE000000) == 0xD6000000;
}


#endif /* _HOOK_UTILS_H */
