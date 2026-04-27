/*
 * hook_chain_ops.h - hook/fp_hook共享的链项与transit辅助逻辑
 */

#ifndef __HOOK_CHAIN_OPS_H__
#define __HOOK_CHAIN_OPS_H__

#include <linux/string.h>
#include "hook_types.h"

#define HOOK_TRANSIT_OWNER_MAGIC 0xfedcba9876543210ull

static inline hook_err_t hook_copy_transit_code(uint32_t *transit, uint64_t transit_start, uint64_t transit_end,
                                                uintptr_t owner)
{
    int32_t transit_num = (transit_end - transit_start) / 4;
    bool owner_patched = false;

    /*
     * transit[0] 和 transit[1] 预留给 BTI/NOP 标记，
     * 真实模板从 transit[2] 开始复制。
     */
    if (transit_num + 2 > TRANSIT_INST_NUM) {
        return -HOOK_TRANSIT_NO_MEM;
    }

    transit[0] = ARM64_BTI_JC;
    transit[1] = ARM64_NOP;
    for (int i = 0; i < transit_num; i++) {
        transit[i + 2] = ((uint32_t *)transit_start)[i];
    }

    for (int i = 0; i + 1 < transit_num; i++) {
        u64 *slot = (u64 *)&transit[i + 2];
        if (*slot == HOOK_TRANSIT_OWNER_MAGIC) {
            *slot = owner;
            owner_patched = true;
            break;
        }
    }

    if (!owner_patched) {
        return -HOOK_BAD_RELO;
    }

    return HOOK_NO_ERR;
}

static inline hook_err_t hook_chain_slots_add_common(int max_items, int32_t *chain_items_max,
                                                     chain_item_state *states, void **befores, void **afters,
                                                     void **udata, void *before, void *after, void *item_udata)
{
    for (int i = 0; i < max_items; i++) {
        if ((before && befores[i] == before) || (after && afters[i] == after)) {
            return -HOOK_DUPLICATED;
        }

        if (states[i] == CHAIN_ITEM_STATE_EMPTY) {
            WRITE_ONCE(states[i], CHAIN_ITEM_STATE_BUSY);
            smp_wmb();
            WRITE_ONCE(udata[i], item_udata);
            WRITE_ONCE(befores[i], before);
            WRITE_ONCE(afters[i], after);
            if (i + 1 > *chain_items_max) {
                WRITE_ONCE(*chain_items_max, i + 1);
            }
            smp_wmb();
            WRITE_ONCE(states[i], CHAIN_ITEM_STATE_READY);
            return HOOK_NO_ERR;
        }
    }

    return -HOOK_CHAIN_FULL;
}

static inline int hook_chain_slots_remove_common(int max_items, chain_item_state *states, void **befores,
                                                 void **afters, void **udata, void *before, void *after)
{
    for (int i = 0; i < max_items; i++) {
        if (states[i] != CHAIN_ITEM_STATE_READY) {
            continue;
        }
        if ((before && befores[i] == before) || (after && afters[i] == after)) {
            WRITE_ONCE(states[i], CHAIN_ITEM_STATE_BUSY);
            smp_wmb();
            WRITE_ONCE(udata[i], NULL);
            WRITE_ONCE(befores[i], NULL);
            WRITE_ONCE(afters[i], NULL);
            smp_wmb();
            WRITE_ONCE(states[i], CHAIN_ITEM_STATE_EMPTY);
            return 1;
        }
    }

    return 0;
}

static inline int hook_chain_slots_all_empty_common(int max_items, chain_item_state *states)
{
    for (int i = 0; i < max_items; i++) {
        if (states[i] != CHAIN_ITEM_STATE_EMPTY) {
            return 0;
        }
    }
    return 1;
}

static inline int hook_chain_snapshot_common(int max_items, spinlock_t *lock, int32_t *chain_items_max,
                                             chain_item_state *states, void **befores, void **afters, void **udata,
                                             void **before_snapshot, void **after_snapshot, void **udata_snapshot)
{
    unsigned long flags;
    int limit;

    spin_lock_irqsave(lock, flags);
    limit = READ_ONCE(*chain_items_max);
    if (limit < 0) {
        limit = 0;
    } else if (limit > max_items) {
        limit = max_items;
    }

    for (int i = 0; i < limit; i++) {
        if (READ_ONCE(states[i]) != CHAIN_ITEM_STATE_READY) {
            before_snapshot[i] = NULL;
            after_snapshot[i] = NULL;
            udata_snapshot[i] = NULL;
            continue;
        }
        before_snapshot[i] = READ_ONCE(befores[i]);
        after_snapshot[i] = READ_ONCE(afters[i]);
        udata_snapshot[i] = READ_ONCE(udata[i]);
    }
    spin_unlock_irqrestore(lock, flags);

    return limit;
}

#endif /* __HOOK_CHAIN_OPS_H__ */
