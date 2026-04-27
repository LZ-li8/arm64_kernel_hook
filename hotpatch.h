#ifndef _KP_HOTPATCH_H_
#define _KP_HOTPATCH_H_

#include <linux/kernel.h>

extern int hotpatch_init_flag;

#define HOTPATCH_FLAG_FLUSH_ICACHE (1U << 0)

int hotpatch_init(void);
int hotpatch(void *addrs[], uint32_t values[], int cnt);
int hotpatch_nosync(void *addr, uint32_t value);
int hotpatch_write(void *dst, const void *src, size_t len, unsigned int flags);
int hook_patch_text(uintptr_t addr, const uint32_t *words, int cnt, int head_last);
int hook_patch_data(uintptr_t addr, const void *src, size_t len);

#endif
