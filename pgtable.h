
#ifndef HOOK__PGTABLE__H
#define HOOK__PGTABLE__H
#include <asm/pgtable-types.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <linux/kernel.h>
#include <linux/mm.h>

// arch/arm64/include/asm/pgtable.h

pte_t *pte_from_virt(struct mm_struct *mm, unsigned long addr);

pte_t *pte_from_kva(unsigned long kvaddr);

int va_to_kpa(struct mm_struct *mm, unsigned long va, phys_addr_t *pa);

uint64_t *pgtable_entry(uint64_t pgd, uint64_t va);

int protect_rodata_memory(unsigned long kvaddr);

int unprotect_rodata_memory(unsigned long kvaddr);



#endif
