/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include "hook.h"
#include "log.h"
#include <linux/spinlock.h>


static uint64_t mem_region_start = 0;
static uint64_t mem_region_end = 0;


typedef struct
{
    int using;
    atomic_t refcount;
    enum hook_type type;
    uintptr_t addr;
    // must align 8
    union
    {
        hook_t inl;
        hook_chain_t inl_chain;
        fp_hook_chain_t fp_chain;
    } chain __attribute__((aligned(8)));
} hook_mem_warp_t __attribute__((aligned(16)));

DEFINE_SPINLOCK(hook_mem_lock);//分配锁



// 添加位图索引
#define MAX_HOOK_SLOTS 256
static unsigned long hook_slots_bitmap[(MAX_HOOK_SLOTS + 63) / 64];

void *hook_mem_zalloc_optimized(uintptr_t origin_addr, enum hook_type type)
{
    unsigned long flags;
    hook_mem_warp_t *wrap = NULL;
    void *result = NULL;
    int slot;
    
    spin_lock_irqsave(&hook_mem_lock, flags);
    
    // 使用位图快速查找空闲槽位
    slot = find_first_zero_bit(hook_slots_bitmap, MAX_HOOK_SLOTS);
    if (slot >= MAX_HOOK_SLOTS) {
        hook_err("No free hook slots\n");
        goto out;
    }
    
    // 标记为已使用
    set_bit(slot, hook_slots_bitmap);
    
    // 计算地址
    wrap = (hook_mem_warp_t *)(mem_region_start + slot * sizeof(hook_mem_warp_t));
    
    wrap->using = 1;
    atomic_set(&wrap->refcount, 1);
    wrap->addr = origin_addr;
    wrap->type = type;
    
    // 清零 chain
    memset(&wrap->chain, 0, sizeof(wrap->chain));
    
    result = &wrap->chain;
    hook_debug("Allocated hook slot %d: origin=0x%lx\n", slot, origin_addr);
    
out:
    spin_unlock_irqrestore(&hook_mem_lock, flags);
    return result;
}






int hook_mem_add(uint64_t start, int32_t size)
{
    // 参数验证
    if (!start || size <= 0) {
        hook_err("Invalid parameters: start=0x%llx size=%d\n", start, size);
        return -EINVAL;
    }
    
    // hook allocator可能返回module/vmalloc区域地址，这些地址也应视作合法内核地址
    if (!(is_kernel(start) || is_vmalloc_or_module_addr((void *)start))) {
        hook_err("Address not in supported kernel space: 0x%llx\n", start);
        return -EINVAL;
    }
    
    // 检查大小是否合理
    if (size < (int32_t)sizeof(hook_mem_warp_t)) {
        hook_err("Size too small: %d < %lu\n", size, sizeof(hook_mem_warp_t));
        return -EINVAL;
    }
    
    // 初始化内存区域
    // for (uint64_t i = start; i < start + size; i += 8) {
    //     *(uint64_t *)i = 0;
    // }

    memset((void *)start, 0, size);
    
    mem_region_start = start;
    mem_region_end = start + size;
    
    hook_info("Hook memory region initialized: 0x%llx - 0x%llx (%d bytes, max %lu hooks)\n",
          start, start + size, size, size / sizeof(hook_mem_warp_t));
    
    return 0;
}

void *hook_mem_zalloc(uintptr_t origin_addr, enum hook_type type)
{
    unsigned long flags;
    hook_mem_warp_t *wrap = NULL;
    void *result = NULL;
    
    // 检查内存区域是否已初始化
    if (mem_region_start == 0 || mem_region_end == 0) {
        hook_err("Hook memory region not initialized\n");
        return NULL;
    }
    
    // 使用自旋锁保护分配过程
    spin_lock_irqsave(&hook_mem_lock, flags);
    
    // 查找空闲槽位
    for (uint64_t addr = mem_region_start; addr < mem_region_end; addr += sizeof(hook_mem_warp_t)) {
        wrap = (hook_mem_warp_t *)addr;
        
        // 原子性检查和设置（在锁保护下）
        if (!wrap->using) {
            // 找到空闲槽位
            wrap->using = 1;
            atomic_set(&wrap->refcount, 1);
            wrap->addr = origin_addr;
            wrap->type = type;
            
            // 清零 chain 区域
            memset(&wrap->chain, 0, sizeof(wrap->chain));
            
            // 验证对齐
            if (((uintptr_t)&wrap->chain) & 0b111) {
                hook_err("Chain alignment error: %p\n", &wrap->chain);
                wrap->using = 0;
                result = NULL;
                goto out;
            }
            
            result = &wrap->chain;

            
            hook_debug("Allocated hook: origin=0x%lx type=%d\n", 
                  origin_addr, type);
            
            goto out;
        }
    }
    
    // 没有找到空闲槽位
    hook_err("No free hook slots available\n");
    
out:
    spin_unlock_irqrestore(&hook_mem_lock, flags);
    return result;
}

// 增加引用计数
void hook_mem_get(void *hook_mem)
{
    hook_mem_warp_t *warp;
    
    if (!hook_mem) {
        hook_err("hook_mem_get: NULL pointer\n");
        return;
    }
    
    warp = local_container_of(hook_mem, hook_mem_warp_t, chain);
    
    if (!warp->using) {
        hook_warn("hook_mem_get: hook not in use\n");
        return;
    }
    
    atomic_inc(&warp->refcount);
    hook_debug("hook_mem_get: origin=0x%lx refcount=%d\n", 
          warp->addr, atomic_read(&warp->refcount));
}

// 减少引用计数并在必要时释放
void hook_mem_put(void *hook_mem)
{
    hook_mem_warp_t *warp;
    unsigned long flags;
    int refcount;
    
    if (!hook_mem) {
        hook_err("hook_mem_put: NULL pointer\n");
        return;
    }
    
    warp = local_container_of(hook_mem, hook_mem_warp_t, chain);
    
    if (!warp->using) {
        hook_warn("hook_mem_put: hook not in use\n");
        return;
    }
    
    refcount = atomic_dec_return(&warp->refcount);
    
    hook_debug("hook_mem_put: origin=0x%lx refcount=%d\n", warp->addr, refcount);
    
    if (refcount == 0) {
        // 引用计数为 0，可以释放
        spin_lock_irqsave(&hook_mem_lock, flags);
        
        if (warp->using) {
            warp->using = 0;
            
            hook_info("Hook freed: origin=0x%lx\n", warp->addr);
        }
        
        spin_unlock_irqrestore(&hook_mem_lock, flags);
    } else if (refcount < 0) {
        // 异常：引用计数变负了
        hook_err("hook_mem_put: refcount underflow! origin=0x%lx refcount=%d\n",
              warp->addr, refcount);
        atomic_set(&warp->refcount, 0);
    }
}

// 旧的释放函数（保持兼容性，但建议使用 hook_mem_put）
void hook_mem_free(void *hook_mem)
{
    hook_mem_warp_t *warp;
    unsigned long flags;
    int refcount;
    uintptr_t origin;
    
    if (!hook_mem) {
        return;
    }
    
    warp = local_container_of(hook_mem, hook_mem_warp_t, chain);
    
    refcount = atomic_read(&warp->refcount);
    if (refcount > 0) {
        hook_warn("hook_mem_free: freeing hook with refcount=%d, use hook_mem_put instead\n", refcount);
    }
    
    spin_lock_irqsave(&hook_mem_lock, flags);
    
    if (warp->using) {
        origin = warp->addr;
        warp->using = 0;
        warp->addr = 0;
        warp->type = NONE;
        atomic_set(&warp->refcount, 0);
        hook_info("Hook force freed: origin=0x%lx\n", origin);
    }
    
    spin_unlock_irqrestore(&hook_mem_lock, flags);
}

void hook_mem_retire(void *hook_mem)
{
    hook_mem_warp_t *warp;
    unsigned long flags;
    uintptr_t origin;

    if (!hook_mem) {
        return;
    }

    warp = local_container_of(hook_mem, hook_mem_warp_t, chain);

    spin_lock_irqsave(&hook_mem_lock, flags);

    if (!warp->using) {
        spin_unlock_irqrestore(&hook_mem_lock, flags);
        return;
    }

    origin = warp->addr;
    warp->addr = 0;
    warp->type = NONE;
    atomic_set(&warp->refcount, 0);

    /*
     * Keep the retired slot occupied until module teardown so any stale
     * backup/transit pointer won't jump into re-used memory.
     */
    hook_info("Hook retired: origin=0x%lx\n", origin);

    spin_unlock_irqrestore(&hook_mem_lock, flags);
}

void *hook_get_mem_from_origin(uint64_t origin_addr)
{
    uint64_t start = mem_region_start;
    unsigned long flags;
    void *result = NULL;

    spin_lock_irqsave(&hook_mem_lock, flags);
    
    for (uint64_t addr = start; addr < mem_region_end; addr += sizeof(hook_mem_warp_t)) {
        hook_mem_warp_t *wrap = (hook_mem_warp_t *)addr;
        if (wrap->using && wrap->addr && wrap->addr == origin_addr) {
            result = &wrap->chain;
            break;
        }
    }
    
    spin_unlock_irqrestore(&hook_mem_lock, flags);
    
    return result;
}


// 检查内存泄漏
void hook_mem_check_leaks(void)
{
    unsigned long flags;
    int leak_count = 0;
    
    hook_info("=== Hook Memory Leak Check ===\n");
    
    spin_lock_irqsave(&hook_mem_lock, flags);
    
    for (uint64_t addr = mem_region_start; addr < mem_region_end; addr += sizeof(hook_mem_warp_t)) {
        hook_mem_warp_t *wrap = (hook_mem_warp_t *)addr;
        
        if (wrap->using) {
            if (!wrap->addr)
                continue;
            int refcount = atomic_read(&wrap->refcount);
            
            if (refcount > 1) {
                hook_warn("Potential leak: origin=0x%lx type=%d refcount=%d\n",
                      wrap->addr, wrap->type, refcount);
                leak_count++;
            }
        }
    }
    
    spin_unlock_irqrestore(&hook_mem_lock, flags);
    
    if (leak_count > 0) {
        hook_warn("Found %d potential leaks\n", leak_count);
    } else {
        hook_info("No memory leaks detected\n");
    }
    
    hook_info("=============================\n");
}

// 清理所有 hooks（用于模块卸载）
void hook_mem_cleanup_all(void)
{
    unsigned long flags;
    int count = 0;
    
    hook_info("Cleaning up all hook memory...\n");
    
    spin_lock_irqsave(&hook_mem_lock, flags);
    
    for (uint64_t addr = mem_region_start; addr < mem_region_end; addr += sizeof(hook_mem_warp_t)) {
        hook_mem_warp_t *wrap = (hook_mem_warp_t *)addr;
        
        if (wrap->using) {
            int refcount = atomic_read(&wrap->refcount);
            
            if (refcount > 0) {
                hook_warn("Force freeing hook with refcount=%d: origin=0x%lx\n",
                      refcount, wrap->addr);
            }
            
            wrap->using = 0;
            wrap->addr = 0;
            wrap->type = NONE;
            atomic_set(&wrap->refcount, 0);
            count++;
        }
    }
    
    spin_unlock_irqrestore(&hook_mem_lock, flags);
    
    hook_info("Cleaned up %d hooks\n", count);
}
