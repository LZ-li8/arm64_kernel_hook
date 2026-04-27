/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_HMEM_H_
#define _KP_HMEM_H_

#include <linux/kernel.h>
#include "hook_types.h"

/*
 * Hook 内存管理模块
 * 
 * 功能：
 * - 管理 Hook 内存分配和释放
 * - 引用计数机制防止内存泄漏
 * - 资源限制防止耗尽
 * - 统计和泄漏检测
 */

// 初始化 Hook 内存区域
int hook_mem_add(uint64_t start, int32_t size);

// 分配 Hook 内存（带资源限制和并发保护）
void *hook_mem_zalloc(uintptr_t origin_addr, enum hook_type type);

// 引用计数管理（推荐使用）
void hook_mem_get(void *hook_mem);     // 增加引用计数
void hook_mem_put(void *hook_mem);     // 减少引用计数，为 0 时自动释放

// 强制释放（兼容旧代码，不推荐使用）
void hook_mem_free(void *hook_mem);
void hook_mem_retire(void *hook_mem);

// 根据原始地址查找 Hook 内存
void *hook_get_mem_from_origin(uint64_t origin_addr);


void hook_mem_check_leaks(void);
void hook_mem_cleanup_all(void);

#endif
