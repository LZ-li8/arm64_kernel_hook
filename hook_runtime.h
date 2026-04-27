/*
 * hook_runtime.h - Hook框架运行时辅助函数
 */

#ifndef __HOOK_RUNTIME_H__
#define __HOOK_RUNTIME_H__

#include <asm/pgtable-types.h>
#include <linux/mm.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include "kallsyms_name.h"
#include "hook_utils.h"
#include "log.h"

typedef void *(*vmalloc_exec_p)(unsigned long size);

extern pte_t *pte_from_kva(unsigned long kaddr);
pte_t *pte_from_virt(struct mm_struct *mm, unsigned long addr);

__nocfi
static void *hook_alloc(size_t size)
{
    static vmalloc_exec_p vmalloc_x = NULL;
    void *ptr = NULL;

    if (!vmalloc_x) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
        vmalloc_x = (vmalloc_exec_p)m_kallsyms_lookup_name("vmalloc_exec");
#else
        vmalloc_x = (vmalloc_exec_p)m_kallsyms_lookup_name("module_alloc");
#endif
        if (!vmalloc_x)
            return NULL;
        hook_info("vmalloc_exec:%llx", (uint64_t)vmalloc_x);
    }

    ptr = vmalloc_x(size);
    if (ptr) {
        memset(ptr, 0, size);
    }

    return ptr;
}

static inline void hook_free(void *ptr)
{
    if (ptr) {
        vfree(ptr);
    }
}

static inline int is_bad_address(void *addr)
{
    unsigned long kaddr = (unsigned long)addr;

    if (kaddr & 0x3)
        return 1;

    return !(is_kernel(kaddr) || is_vmalloc_or_module_addr((void *)kaddr));
}

#endif /* __HOOK_RUNTIME_H__ */
