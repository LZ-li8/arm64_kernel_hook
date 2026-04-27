/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include "secpass.h"

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/types.h>

#include "hotpatch.h"
#include "kallsyms_name.h"
#include "log.h"

#define ARM64_RET_INST 0xd65f03c0
#define ARM64_MOV_X0_1 0xd2800020

#define KCFI_PATCH_MAX_WORDS 2

struct kcfi_patch_site {
    const char *name;
    unsigned long addr;
    uint32_t original[KCFI_PATCH_MAX_WORDS];
    uint32_t patch[KCFI_PATCH_MAX_WORDS];
    int words;
    bool installed;
};

static struct kcfi_patch_site kcfi_patch_sites[] = {
    {
        .name = "report_cfi_failure",
        .patch = { ARM64_MOV_X0_1, ARM64_RET_INST },
        .words = 2,
    },
    {
        .name = "__cfi_slowpath_diag",
        .patch = { ARM64_RET_INST },
        .words = 1,
    },
    {
        .name = "__cfi_slowpath",
        .patch = { ARM64_RET_INST },
        .words = 1,
    },
    {
        .name = "__cfi_check",
        .patch = { ARM64_RET_INST },
        .words = 1,
    },
    {
        .name = "__cfi_check_fail",
        .patch = { ARM64_RET_INST },
        .words = 1,
    },
    {
        .name = "__ubsan_handle_cfi_check_fail_abort",
        .patch = { ARM64_RET_INST },
        .words = 1,
    },
    {
        .name = "__ubsan_handle_cfi_check_fail",
        .patch = { ARM64_RET_INST },
        .words = 1,
    },
};

static int kcfi_patch_one(struct kcfi_patch_site *site)
{
    int rc;

    site->addr = m_kallsyms_lookup_name(site->name);
    if (!site->addr) {
        hook_info("kcfi patch: no symbol %s\n", site->name);
        return 0;
    }

    if (site->addr & 0x3) {
        hook_err("kcfi patch: %s addr is not aligned: 0x%lx\n", site->name, site->addr);
        return -EINVAL;
    }

    memcpy(site->original, (void *)site->addr, sizeof(uint32_t) * site->words);

    rc = hook_patch_text(site->addr, site->patch, site->words, 0);
    if (rc) {
        hook_err("kcfi patch: patch %s at 0x%lx failed: %d\n", site->name, site->addr, rc);
        return rc;
    }

    site->installed = true;
    hook_info("kcfi patch: patched %s at 0x%lx\n", site->name, site->addr);
    return 0;
}

int bypass_kcfi(void)
{
    int rc = 0;
    int patched = 0;

    for (size_t i = 0; i < ARRAY_SIZE(kcfi_patch_sites); i++) {
        struct kcfi_patch_site *site = &kcfi_patch_sites[i];

        if (site->installed) {
            patched++;
            continue;
        }

        rc = kcfi_patch_one(site);
        if (rc)
            return rc;

        if (site->installed)
            patched++;
    }

    if (!patched)
        hook_info("kcfi patch: no symbol for pass kcfi\n");

    return 0;
}

void restore_kcfi(void)
{
    for (size_t i = ARRAY_SIZE(kcfi_patch_sites); i > 0; i--) {
        struct kcfi_patch_site *site = &kcfi_patch_sites[i - 1];
        int rc;

        if (!site->installed)
            continue;

        rc = hook_patch_text(site->addr, site->original, site->words, 0);
        if (rc) {
            hook_err("kcfi patch: restore %s at 0x%lx failed: %d\n", site->name, site->addr, rc);
            continue;
        }

        site->installed = false;
        hook_info("kcfi patch: restored %s at 0x%lx\n", site->name, site->addr);
    }
}
