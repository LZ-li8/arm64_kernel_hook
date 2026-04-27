#ifndef _KP_CACHE_H_
#define _KP_CACHE_H_

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/mm.h>
#include "asm/cacheflush.h"

// /*
//  * Utility macro to choose an instruction according to the exception
//  * level (EL) passed, which number is concatenated between insa and insb parts
//  */
// #define SWITCH_EL(insa, insb, el)    \
//     if (el == 1)                     \
//         asm volatile(insa "1" insb); \
//     else if (el == 2)                \
//         asm volatile(insa "2" insb); \
//     else                             \
//         asm volatile(insa "3" insb)
// /* get current exception level (EL1-EL3) */
// static inline uint32_t current_el(void)
// {
//     uint32_t el;
//     asm volatile("mrs %w0, CurrentEL" : "=r"(el));
//     return el >> 2;
// }

// /* write translation table base register 0 (TTBR0_ELx) */
// static inline void write_ttbr0(uint64_t val, uint32_t el)
// {
//     SWITCH_EL("msr ttbr0_el", ", %0" : : "r"(val) : "memory", el);
// }
// /* read translation control register (TCR_ELx) */
// static inline uint64_t read_tcr(uint32_t el)
// {
//     uint64_t val = 0;
//     SWITCH_EL("mrs %0, tcr_el", : "=r"(val), el);
//     return val;
// }
// /* write translation control register (TCR_ELx) */
// static inline void write_tcr(uint64_t val, uint32_t el)
// {
//     SWITCH_EL("msr tcr_el", ", %0" : : "r"(val) : "memory", el);
// }

// /* data cache clean and invalidate by VA to PoC */
// static inline void dccivac(uint64_t va)
// {
//     asm volatile("dc civac, %0" : : "r"(va) : "memory");
// }
// /* data cache clean and invalidate by set/way */
// static inline void dccisw(uint64_t val)
// {
//     asm volatile("dc cisw, %0" : : "r"(val) : "memory");
// }
// /* data cache clean by VA to PoC */
// static inline void dccvac(uint64_t va)
// {
//     asm volatile("dc cvac, %0" : : "r"(va) : "memory");
// }
// /* data cache clean by set/way */
// static inline void dccsw(uint64_t val)
// {
//     asm volatile("dc csw, %0" : : "r"(val) : "memory");
// }
// /* data cache invalidate by VA to PoC */
// static inline void dcivac(uint64_t va)
// {
//     asm volatile("dc ivac, %0" : : "r"(va) : "memory");
// }
// /* data cache invalidate by set/way */
// static inline void dcisw(uint64_t val)
// {
//     asm volatile("dc isw, %0" : : "r"(val) : "memory");
// }
// /* instruction cache invalidate all */
// static inline void iciallu(void)
// {
//     asm volatile("ic iallu" : : : "memory");
// }


#define mask_ul(h, l) (((~0ul) << (l)) & (~0ul >> (63 - (h))))

#define sev() asm volatile("sev" : : : "memory")
#define wfe() asm volatile("wfe" : : : "memory")
#define wfi() asm volatile("wfi" : : : "memory")

#define isb() asm volatile("isb" : : : "memory")
#define dmb(opt) asm volatile("dmb " #opt : : : "memory")
#define dsb(opt) asm volatile("dsb " #opt : : : "memory")

#define tlbi_0(op)       \
    asm("tlbi " #op "\n" \
        "dsb ish\n"      \
        "tlbi " #op "\n")

#define tlbi_1(op, arg)      \
    asm("tlbi " #op ", %0\n" \
        "dsb ish\n"          \
        "tlbi " #op ", %0\n" \
        :                    \
        : "r"(arg))


static inline void local_flush_icache_all(void)
{
    asm volatile("ic iallu");
    asm volatile("dsb nsh" : : : "memory");
    asm volatile("isb" : : : "memory");
}

static inline void flush_icache_all(void)
{
    asm volatile("dsb ish" : : : "memory");
    asm volatile("ic ialluis");
    asm volatile("dsb ish" : : : "memory");
    asm volatile("isb" : : : "memory");
}

// __TLBI_VADDR
static inline uint64_t tlbi_vaddr(uint64_t addr, uint64_t asid)
{
    uint64_t x = addr >> 12;
    x &= mask_ul(43, 0);
    x |= asid << 48;
    return x;
}

static inline void k_flush_tlb_kernel_range(uint64_t start, uint64_t end)
{
    start = tlbi_vaddr(start, 0);
    end = tlbi_vaddr(end, 0);
    dsb(ishst);
    for(uint64_t addr = start; addr < end; addr += 1 << (PAGE_SHIFT - 12))
        tlbi_1(vaale1is, addr);
    dsb(ish);
    isb();
}

static inline void k_flush_tlb_kernel_page(uint64_t addr)
{
    addr = tlbi_vaddr(addr, 0);
    dsb(ishst);
    tlbi_1(vaale1is, addr);
    dsb(ish);
    isb();
}


// 在关键路径使用轻量级屏障
static inline void ensure_write_order(void)
{
    smp_wmb();  // Write Memory Barrier，比 dsb(ish) 轻量
}

static inline void ensure_read_order(void)
{
    smp_rmb();  // Read Memory Barrier
}

static inline void ensure_full_order(void)
{
    smp_mb();   // Full Memory Barrier
}

// This function appears in 5.14:
// https://github.com/torvalds/linux/commit/fade9c2c6ee2baea7df8e6059b3f143c681e5ce4#diff-fc9ef24572e183c6c049b5ae8029762159787f8669d909452bdf40db748f94a7L52
// https://github.com/torvalds/linux/commit/814b186079cd54d3fe3b6b8ab539cbd44705ef9d#diff-fc9ef24572e183c6c049b5ae8029762159787f8669d909452bdf40db748f94a7R53
// However, it's backport to android13-5.10 but not to android12-5.10.
// https://cs.android.com/android/_/android/kernel/common/+/6d9f07d8f1ffc310a6877153fe882f35ae380799
// So we need to grep kernel source code to detect which one to use.
//#ifndef __flush_dcache_area
#define ksu_flush_dcache(start, sz)                                                                                    \
    ({                                                                                                                 \
        unsigned long __start = (start);                                                                               \
        unsigned long __end = __start + (sz);                                                                          \
        dcache_clean_inval_poc(__start, __end);                                                                        \
    })
#define ksu_flush_icache(start, end) caches_clean_inval_pou
// #else
// #define ksu_flush_dcache(start, sz) __flush_dcache_area((void *)start, sz)
// #define ksu_flush_icache(start, end) __flush_icache_range
// #endif

#endif