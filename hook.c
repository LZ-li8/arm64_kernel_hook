/*
 * hook.c - 内联Hook核心实现
 * 
 * 实现ARM64架构下的内联函数Hook基本操作
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <asm/cacheflush.h>
#include "hook.h"
#include "hmem.h"
#include <asm/pgtable.h>

// // 内存权限操作相关函数
// static void make_kernel_text_rw(unsigned long addr)
// {
//     // unsigned long start = addr & PAGE_MASK;
//     // unsigned long size = PAGE_SIZE;
    
//     // pte_t *pte = pte_from_kva(start);
//     // if (pte) {
//     //     // 去掉写保护标志
//     //     //pte->pte &= ~_PAGE_RO;
//     //     // 刷新TLB
//     //     //__flush_tlb_all();
//     // }
// }

// static void make_kernel_text_ro(unsigned long addr)
// {
//     // unsigned long start = addr & PAGE_MASK;
//     // unsigned long size = PAGE_SIZE;
    
//     // pte_t *pte = pte_from_kva(start);
//     // if (pte) {
//     //     // 恢复写保护标志
//     //    // pte->pte |= _PAGE_RO;
//     //     // 刷新TLB
//     //    // __flush_tlb_all();
//     // }
// }

