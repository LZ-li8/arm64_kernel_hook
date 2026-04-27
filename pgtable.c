#include "pgtable.h"
#include "asm/pgtable.h"
#include "kallsyms_name.h"
#include <linux/kallsyms.h>

#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <linux/moduleloader.h>

static struct mm_struct *init_mm_ptr = NULL;

pte_t *pte_from_virt(struct mm_struct *mm, unsigned long addr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    if (!mm)
        return NULL;

    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return NULL;

    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return NULL;

    pud = pud_offset(p4d, addr);
    if (pud_none(*pud))
        return NULL;

#if defined(pud_leaf)
    if (pud_leaf(*pud))
        return (pte_t *)pud;
#endif

    if (pud_bad(*pud))
        return NULL;

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd))
        return NULL;

#if defined (pmd_leaf)
    if (pmd_leaf(*pmd))
        return (pte_t *)pmd;
#endif

    if (pmd_bad(*pmd))
        return NULL;

    pte = pte_offset_kernel(pmd, addr);
    if (pte_none(*pte))
        return NULL;

    return pte;
}

pte_t* pte_from_kva(unsigned long addr)
{

    if (!init_mm_ptr)
    {
        init_mm_ptr = (struct mm_struct *)m_kallsyms_lookup_name("init_mm");
        if (!init_mm_ptr) {
            return NULL;
        }
    }

   return pte_from_virt(init_mm_ptr, addr);
}



static int set_rodata_memory_writable(unsigned long addr, bool writable)
{
    pte_t pte;
    pte_t *ptep;

    ptep = pte_from_kva(addr);
    if (!ptep)
        return -ENOENT;

    if (!pte_valid(READ_ONCE(*ptep)))
        return -ENOENT;

    pte = READ_ONCE(*ptep);
    if (writable) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
        pte = pte_mkwrite(pte);
#else
        pte = pte_mkwrite_novma(pte);
#endif
    } else {
        pte = pte_wrprotect(pte);
    }

    set_pte(ptep, pte);
    __flush_tlb_kernel_pgtable(addr);

    return 0;
}

int protect_rodata_memory(unsigned long addr)
{
    return set_rodata_memory_writable(addr, false);
}

int unprotect_rodata_memory(unsigned long addr)
{
    return set_rodata_memory_writable(addr, true);
}

int va_to_kpa(struct mm_struct *mm, unsigned long va, phys_addr_t *pa) {
  pgd_t *pgd;
  p4d_t *p4d;
  pud_t *pud;
  pmd_t *pmd;
  pte_t *pte;

  *pa = 0;

  pgd = pgd_offset(mm, va); // pgd 目前还没大页
  if (pgd_none(*pgd) || pgd_bad(*pgd)) {
    return -EFAULT;
  }

  p4d = p4d_offset(pgd, va); // p4d = pgd
  if (p4d_none(*p4d) || p4d_bad(*p4d))
    return -EFAULT;

  pud = pud_offset(p4d, va);
  if (pud_none(*pud))
    return -EFAULT;

  if (pud_leaf(*pud)) {
    *pa = (pud_pfn(*pud) << PAGE_SHIFT) | (va & ~PUD_MASK);
    return 0;
  }
  if (WARN_ON_ONCE(pud_bad(*pud)))
    return NULL;

  pmd = pmd_offset(pud, va);
  if (pmd_none(*pmd))
    return -EFAULT;

  if (pmd_leaf(*pmd)) {
    *pa = (pmd_pfn(*pmd) << PAGE_SHIFT) | (va & ~PMD_MASK);
    return 0;
  }
  if (WARN_ON_ONCE(pmd_bad(*pmd)))
    return NULL;

  pte = pte_offset_map(pmd, va);
  if (pte_none(*pte))
    return -EFAULT;

  *pa = (pte_pfn(*pte) << PAGE_SHIFT) | (va & ~PAGE_MASK);
  pte_unmap(pte);

  return 0;
}

uint64_t *pgtable_entry(uint64_t pgd, uint64_t va)
{
    uint64_t pxd_bits = PAGE_SHIFT - 3;
    uint64_t pxd_ptrs = 1u << pxd_bits;
    uint64_t pxd_va = pgd;
    uint64_t pxd_pa = virt_to_phys(pxd_va);
    uint64_t pxd_entry_va = 0;
    uint64_t block_lv = 0;

    for (int64_t lv = 4 - CONFIG_PGTABLE_LEVELS; lv < 4; lv++) {
        uint64_t pxd_shift = (PAGE_SHIFT - 3) * (4 - lv) + 3;
        uint64_t pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);
        pxd_entry_va = pxd_va + pxd_index * 8;
        if (!pxd_entry_va) return 0;
        uint64_t pxd_desc = *((uint64_t *)pxd_entry_va);
        //LOG_INFO("pxd_desc %lx ",pxd_desc);
        if ((pxd_desc & 0b11) == 0b11) { // table
            pxd_pa = pxd_desc & (((1ul << (48 - PAGE_SHIFT)) - 1) << PAGE_SHIFT);
        } else if ((pxd_desc & 0b11) == 0b01) { // block
            // 4k page: lv1, lv2. 16k and 64k page: only lv2.
            uint64_t block_bits = (3 - lv) * pxd_bits + PAGE_SHIFT;
            pxd_pa = pxd_desc & (((1ul << (48 - block_bits)) - 1) << block_bits);
            block_lv = lv;
        } else { // invalid
            return 0;
        }
        //
        pxd_va = phys_to_virt(pxd_pa);
        
        if (block_lv) {
            break;
        }
    }
#if 0
    uint64_t left_bit = PAGE_SHIFT + (block_lv ? (3 - block_lv) * pxd_bits : 0);
    uint64_t tpa = pxd_pa + (va & ((1u << left_bit) - 1));
    //uint64_t tlva = phys_to_virt(tpa);
    //LOG_INFO("tpa %lx tlva %lx",tpa,tlva);
#endif

    return (uint64_t *)pxd_entry_va;
}


/*
 * Walk a vmap address to the struct page it maps. Huge vmap mappings will
 * return the tail page that corresponds to the base page address, which
 * matches small vmap mappings.
 */
struct page *vm_to_page(const void *vmalloc_addr)
{
	unsigned long addr = (unsigned long) vmalloc_addr;
	struct page *page = NULL;
	pgd_t *pgd = pgd_offset_k(addr);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;

	/*
	 * XXX we might need to change this if we add VIRTUAL_BUG_ON for
	 * architectures that do not vmalloc module space
	 */
	VIRTUAL_BUG_ON(!is_vmalloc_or_module_addr(vmalloc_addr));

	if (pgd_none(*pgd))
		return NULL;
	if (WARN_ON_ONCE(pgd_leaf(*pgd)))
		return NULL; /* XXX: no allowance for huge pgd */
	if (WARN_ON_ONCE(pgd_bad(*pgd)))
		return NULL;

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d))
		return NULL;
	if (p4d_leaf(*p4d))
		return p4d_page(*p4d) + ((addr & ~P4D_MASK) >> PAGE_SHIFT);
	if (WARN_ON_ONCE(p4d_bad(*p4d)))
		return NULL;

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud))
		return NULL;
	if (pud_leaf(*pud))
		return pud_page(*pud) + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
	if (WARN_ON_ONCE(pud_bad(*pud)))
		return NULL;

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return NULL;
	if (pmd_leaf(*pmd))
		return pmd_page(*pmd) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
	if (WARN_ON_ONCE(pmd_bad(*pmd)))
		return NULL;

	ptep = pte_offset_map(pmd, addr);
	pte = *ptep;
	if (pte_present(pte))
		page = pte_page(pte);
	pte_unmap(ptep);

	return page;
}
