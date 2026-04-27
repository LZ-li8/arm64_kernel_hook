#include "hotpatch.h"

#include <asm/memory.h>
#include <asm/cacheflush.h>
#include <asm/fixmap.h>
#include <linux/cpumask.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/stop_machine.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "cache.h"
#include "hook_types.h"
#include "kallsyms_name.h"
#include "log.h"
#include "pgtable.h"

int hotpatch_init_flag = 0;

static DEFINE_MUTEX(hotpatch_mutex);
static DEFINE_RAW_SPINLOCK(hotpatch_lock);

#define HOOK_PATCH_MAX_PAGES 8

struct hook_patch_page_state {
    pte_t *pte;
    pte_t old;
};

struct hotpatch_write_info {
    void *dst;
    const void *src;
    size_t len;
    unsigned int flags;
    atomic_t cpu_count;
};

struct hotpatch_batch_info {
    void **addrs;
    uint32_t *values;
    int cnt;
    atomic_t cpu_count;
};

static bool hotpatch_is_image_text(unsigned long addr)
{
    return core_kernel_text(addr);
}

static void *hotpatch_map(void *addr, int fixmap)
{
    unsigned long uintaddr = (uintptr_t)addr;
    struct page *page;

    if (hotpatch_is_image_text(uintaddr)) {
        page = phys_to_page(__pa_symbol(addr));
    } else if (is_vmalloc_or_module_addr(addr)) {
        page = vmalloc_to_page(addr);
    } else if (virt_addr_valid(addr)) {
        page = virt_to_page(addr);
    } else {
        return NULL;
    }

    if (!page) {
        return NULL;
    }

    return (void *)set_fixmap_offset(fixmap, page_to_phys(page) + (uintaddr & ~PAGE_MASK));
}

static void hotpatch_unmap(int fixmap)
{
    clear_fixmap(fixmap);
}

// void caches_clean_inval_pou(unsigned long start, unsigned long end);
static void (*kf_caches_clean_inval_pou)(unsigned long, unsigned long);
// void __flush_icache_range(unsigned long start, unsigned long end);
static void (*kf_flush_icache_range)(unsigned long, unsigned long);

__nocfi static void hotpatch_sync_icache_range(unsigned long start,
                                               unsigned long end) {
  if (!kf_caches_clean_inval_pou) {

    kf_flush_icache_range(start, end);

    return;
  }
  kf_caches_clean_inval_pou(start, end);
}

static int hook_patch_prepare_pages(uintptr_t addr, size_t len, struct hook_patch_page_state *pages, size_t *page_count)
{
    uintptr_t start = addr & PAGE_MASK;
    uintptr_t end = PAGE_ALIGN(addr + len);
    size_t count = 0;

    if (!len || !pages || !page_count) {
        return -EINVAL;
    }

    for (uintptr_t cur = start; cur < end; cur += PAGE_SIZE) {
        pte_t *pte = pte_from_kva(cur);
        if (!pte) {
            hook_err("hook_patch: pte_from_kva failed for 0x%lx\n", cur);
            goto err;
        }
        if (count >= HOOK_PATCH_MAX_PAGES) {
            hook_err("hook_patch: range 0x%lx len=%zu exceeds page budget\n", (unsigned long)addr, len);
            goto err;
        }
        pages[count].pte = pte;
        pages[count].old = *pte;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
        set_pte(pte, pte_mkwrite(*pte));
#else
        set_pte(pte, pte_mkwrite_novma(*pte));
#endif
        k_flush_tlb_kernel_page(cur);
        count++;
    }

    *page_count = count;
    return 0;

err:
    while (count > 0) {
        uintptr_t cur = start + (count - 1) * PAGE_SIZE;
        set_pte(pages[count - 1].pte, pages[count - 1].old);
        k_flush_tlb_kernel_page(cur);
        count--;
    }
    return -HOOK_BAD_ADDRESS;
}

static void hook_patch_restore_pages(uintptr_t addr, struct hook_patch_page_state *pages, size_t page_count)
{
    uintptr_t start = addr & PAGE_MASK;

    while (page_count > 0) {
        uintptr_t cur = start + (page_count - 1) * PAGE_SIZE;
        set_pte(pages[page_count - 1].pte, pages[page_count - 1].old);
        k_flush_tlb_kernel_page(cur);
        page_count--;
    }
}

static int hotpatch_copy_internal(void *dst, const void *src, size_t len)
{
    const unsigned char *src_bytes = src;
    size_t copied = 0;
    int rc = 0;
    unsigned long flags;

    if (!dst || !src || !len) {
        return -EINVAL;
    }

    while (copied < len) {
        unsigned long cur = (unsigned long)dst + copied;
        size_t page_off = cur & (PAGE_SIZE - 1);
        size_t chunk = min_t(size_t, len - copied, PAGE_SIZE - page_off);
        void *map;

        raw_spin_lock_irqsave(&hotpatch_lock, flags);
        map = hotpatch_map((void *)cur, FIX_TEXT_POKE0);
        if (!map) {
            raw_spin_unlock_irqrestore(&hotpatch_lock, flags);
            hook_err("hotpatch: failed to map 0x%lx\n", cur);
            return -HOOK_BAD_ADDRESS;
        }
        rc = (int)copy_to_kernel_nofault(map, src_bytes + copied, chunk);
        hotpatch_unmap(FIX_TEXT_POKE0);
        raw_spin_unlock_irqrestore(&hotpatch_lock, flags);
        if (rc) {
            hook_err("hotpatch: copy_to_kernel_nofault failed at 0x%lx len=%zu rc=%d\n",
                     cur, chunk, rc);
            return rc;
        }

        copied += chunk;
    }

    return 0;
}

static int hotpatch_write_nosync_internal(void *dst, const void *src, size_t len, unsigned int flags)
{
    unsigned long dst_addr = (unsigned long)dst;
    int rc;

    rc = hotpatch_copy_internal(dst, src, len);
    if (rc) {
        return rc;
    }

    dsb(ish);

    if (flags & HOTPATCH_FLAG_FLUSH_ICACHE) {
        hotpatch_sync_icache_range(dst_addr, dst_addr + len);
    }

    return 0;
}

static int hotpatch_write_cb(void *arg)
{
    struct hotpatch_write_info *info = arg;
    int ret = 0;

    /* The last CPU becomes master and performs the actual write. */
    if (atomic_inc_return(&info->cpu_count) == num_online_cpus()) {
        ret = hotpatch_write_nosync_internal(info->dst, info->src, info->len, info->flags);
        isb();
        atomic_inc(&info->cpu_count);
    } else {
        while (atomic_read(&info->cpu_count) <= num_online_cpus()) {
            cpu_relax();
        }
        isb();
    }

    return ret;
}

static int hotpatch_batch_nosync_internal(void *addrs[], uint32_t values[], int cnt)
{
    int i;
    int rc;

    if (!addrs || !values || cnt <= 0) {
        return -EINVAL;
    }

    for (i = 0; i < cnt; i++) {
        if (((uintptr_t)addrs[i]) & 0x3) {
            hook_err("hotpatch: instruction addr not aligned at [%d] addr=%llx\n",
                     i, (uint64_t)addrs[i]);
            return -EINVAL;
        }
    }

    for (i = 0; i < cnt; i++) {
        rc = hotpatch_copy_internal(addrs[i], &values[i], sizeof(values[i]));
        if (rc) {
            hook_err("hotpatch: write failed at [%d] addr=%llx, len=%zu rc=%d\n",
                     i, (uint64_t)addrs[i], sizeof(values[i]), rc);
            return rc;
        }
    }

    dsb(ish);

    for (i = 0; i < cnt; i++) {
        unsigned long start = (unsigned long)addrs[i];

        hotpatch_sync_icache_range(start, start + sizeof(values[i]));
    }

    return 0;
}

static int hotpatch_batch_cb(void *arg)
{
    struct hotpatch_batch_info *info = arg;
    int ret = 0;

    if (atomic_inc_return(&info->cpu_count) == num_online_cpus()) {
        ret = hotpatch_batch_nosync_internal(info->addrs, info->values, info->cnt);
        isb();
        atomic_inc(&info->cpu_count);
    } else {
        while (atomic_read(&info->cpu_count) <= num_online_cpus()) {
            cpu_relax();
        }
        isb();
    }

    return ret;
}

int hotpatch_write(void *dst, const void *src, size_t len, unsigned int flags)
{
    struct hotpatch_write_info info = {
        .dst = dst,
        .src = src,
        .len = len,
        .flags = flags,
        .cpu_count = ATOMIC_INIT(0),
    };
    int rc;

    if (!hotpatch_init_flag) {
        return -EINVAL;
    }

    mutex_lock(&hotpatch_mutex);
    rc = stop_machine(hotpatch_write_cb, &info, cpu_online_mask);
    mutex_unlock(&hotpatch_mutex);

    return rc;
}

int hook_patch_text(uintptr_t addr, const uint32_t *words, int cnt, int head_last)
{
    struct hook_patch_page_state pages[HOOK_PATCH_MAX_PAGES];
    void *addrs[TRAMPOLINE_MAX_NUM];
    size_t page_count = 0;
    size_t len;
    int rc;

    if (!words || cnt <= 0) {
        return -EINVAL;
    }

    if (hotpatch_init_flag) {
        uint32_t values[TRAMPOLINE_MAX_NUM];

        if (cnt > TRAMPOLINE_MAX_NUM) {
            return -EINVAL;
        }

        if (head_last && cnt > 1) {
            int out = 0;

            for (int i = cnt - 1; i >= 1; i--) {
                addrs[out] = (uint32_t *)addr + i;
                values[out] = words[i];
                out++;
            }
            addrs[out] = (uint32_t *)addr;
            values[out] = words[0];
        } else {
            for (int i = 0; i < cnt; i++) {
                addrs[i] = (uint32_t *)addr + i;
                values[i] = words[i];
            }
        }

        return hotpatch(addrs, values, cnt);
    }

    len = (size_t)cnt * sizeof(*words);
    rc = hook_patch_prepare_pages(addr, len, pages, &page_count);
    if (rc) {
        return rc;
    }

    if (head_last && cnt > 1) {
        for (int i = cnt - 1; i >= 1; i--) {
            *((uint32_t *)addr + i) = words[i];
        }
        smp_wmb();
        *((uint32_t *)addr) = words[0];
    } else {
        for (int i = 0; i < cnt; i++) {
            *((uint32_t *)addr + i) = words[i];
        }
    }

    flush_icache_range(addr, addr + len);
    hook_patch_restore_pages(addr, pages, page_count);
    return 0;
}

int hook_patch_data(uintptr_t addr, const void *src, size_t len)
{
    struct hook_patch_page_state pages[HOOK_PATCH_MAX_PAGES];
    size_t page_count = 0;
    int rc;

    if (!src || !len) {
        return -EINVAL;
    }

    if (hotpatch_init_flag) {
        return hotpatch_write((void *)addr, src, len, 0);
    }

    rc = hook_patch_prepare_pages(addr, len, pages, &page_count);
    if (rc) {
        return rc;
    }

    memcpy((void *)addr, src, len);
    dsb(ish);
    hook_patch_restore_pages(addr, pages, page_count);
    return 0;
}

int hotpatch_nosync(void *addr, uint32_t value)
{
    if ((uintptr_t)addr & 0x3) {
        return -EINVAL;
    }

    return hotpatch_write_nosync_internal(addr, &value, sizeof(value), HOTPATCH_FLAG_FLUSH_ICACHE);
}

int hotpatch(void *addrs[], uint32_t values[], int cnt)
{
    struct hotpatch_batch_info info = {
        .addrs = addrs,
        .values = values,
        .cnt = cnt,
        .cpu_count = ATOMIC_INIT(0),
    };
    int rc;

    if (!hotpatch_init_flag) {
        return -EINVAL;
    }

    if (!addrs || !values || cnt <= 0) {
        return -EINVAL;
    }

    mutex_lock(&hotpatch_mutex);
    rc = stop_machine(hotpatch_batch_cb, &info, cpu_online_mask);
    mutex_unlock(&hotpatch_mutex);

    return rc;
}

int hotpatch_init(void)
{
    if (hotpatch_init_flag) {
        return 0;
    }


    kf_caches_clean_inval_pou = (void *)m_kallsyms_lookup_name("caches_clean_inval_pou");
    if (!kf_caches_clean_inval_pou) {

        kf_flush_icache_range = (void *)m_kallsyms_lookup_name("__flush_icache_range");
        if (!kf_flush_icache_range) {
            hook_err("hotpatch: failed to find cache sync function\n");
            return -ENOENT;
        }
    }

    hook_info("hotpatch: using fixmap + stop_machine for instruction/data patching\n");
    hotpatch_init_flag = 1;
    return 0;
}
