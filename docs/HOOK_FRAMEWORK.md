# 当前内核 Hook 框架解读

本文档基于当前目录源码整理，面向后续维护、调试和扩展。项目是一个面向 Android ARM64/GKI 内核的 LKM Hook 实验框架，核心能力包括：

- inline hook：改写目标函数入口，跳转到替换函数。
- inline wrap：改写目标函数入口，进入 before/origin/after 回调链。
- function pointer hook：改写函数指针槽位，例如 syscall table、ops table。
- function pointer wrap：函数指针槽位进入 before/origin/after 回调链。
- hotpatch、页表权限修改、指令重定位、KCFI 绕过、kallsyms 查询等底层支撑。

## 1. 代码分层

### 1.1 对外 API 层

主要入口在 `hook.h`：

- `hook(func, replace, backup)`：安装 inline hook。
- `unhook(func)`：卸载 inline hook。
- `hook_wrap(func, argno, before, after, udata)`：安装 inline wrap。
- `hook_unwrap(func, before, after)`：移除 inline wrap 回调，最后一个回调移除后卸载 hook。
- `fp_hook(fp_addr, replace, backup)`：直接替换函数指针槽位。
- `fp_unhook(fp_addr, backup)`：恢复函数指针槽位。
- `fp_hook_wrap(fp_addr, argno, before, after, udata)`：函数指针 wrap。
- `fp_hook_unwrap(fp_addr, before, after)`：移除函数指针 wrap 回调。

`hook.h` 还生成了 `hook_wrap0` 到 `hook_wrap12`、`fp_hook_wrap0` 到 `fp_hook_wrap12` 这组类型化辅助函数。

### 1.2 核心实现层

- `hook_chain.c`
  实现 inline hook、inline wrap、回调链分发逻辑。

- `fp_hook.c`
  实现函数指针 hook、函数指针 wrap、函数指针回调链分发逻辑。

- `hook_reloc.c`
  实现 ARM64 指令重定位。inline hook 需要把被覆盖的原始入口指令搬到 trampoline 中执行，因此所有 PC-relative 指令都必须修正。

- `hook_chain_ops.h`
  inline wrap 与 fp wrap 共享的链表槽位管理和快照逻辑。

- `hmem.c`
  管理 hook 元数据和可执行跳板内存。

- `hotpatch.c`
  text/data 写入后端。优先使用 fixmap + `stop_machine()` 的热补丁路径，并按 patch 范围同步 I-cache。

### 1.3 运行环境支撑层

- `pgtable.c`
  根据虚拟地址遍历页表，返回 PTE，并提供 rodata/text 临时可写能力。

- `cache.h`
  ARM64 cache/TLB flush、barrier、TLBI 辅助函数。

- `secpass.c`
  Hook `report_cfi_failure` / `__cfi_slowpath`，让落在本模块 hook 内存区域内的间接调用目标通过 KCFI 检查。

- `kallsyms_name.c`
  在高版本内核中通过 kprobe 获取未导出的 `kallsyms_lookup_name` 地址。

- `syscall.c`
  syscall hook 的辅助封装。若能拿到 syscall table，走 fp wrap；否则通过 syscall 符号名走 inline wrap。

- `pgfault.c`
  一个基于 page fault 和 single-step 的实验性用户态指令命中方案，不是当前主 hook 框架的主路径。

- `lkm.c`
  模块入口、自测、hook 内存初始化、KCFI 绕过、`vfs_open` demo。

## 2. 核心数据结构

定义集中在 `hook_types.h`。

### 2.1 `hook_t`

`hook_t` 表示一个 inline hook：

```c
typedef struct {
    uint64_t func_addr;
    uint64_t origin_addr;
    uint64_t replace_addr;
    uint64_t relo_addr;
    int32_t tramp_insts_num;
    int32_t relo_insts_num;
    uint32_t origin_insts[TRAMPOLINE_MAX_NUM];
    uint32_t tramp_insts[TRAMPOLINE_MAX_NUM];
    uint32_t relo_insts[RELOCATE_INST_NUM];
} hook_t;
```

关键字段含义：

- `func_addr`：调用方传入的函数地址，可能是 BTI 或 branch 跳板地址。
- `origin_addr`：经过 `branch_func_addr()` 解析后的真实入口。
- `replace_addr`：替换函数地址，或者 wrap 场景下的 transit 地址。
- `origin_insts`：被覆盖的原始入口指令备份。
- `tramp_insts`：写回目标函数入口的跳转指令。
- `relo_insts`：搬迁后的原始入口指令，加上跳回原函数后续位置的跳转。
- `relo_addr`：`relo_insts` 的执行地址，也就是 backup 函数入口。

### 2.2 `hook_chain_t`

`hook_chain_t` 在 `hook_t` 基础上增加回调链：

- `states[]`：每个槽位状态，`EMPTY` / `BUSY` / `READY`。
- `befores[]`：前置回调。
- `afters[]`：后置回调。
- `udata[]`：用户数据。
- `transit[]`：目标函数入口跳到的短跳板。
- `lock`：保护回调槽位。

inline wrap 的目标函数入口最终跳到 `chain->transit`，`transit` 再把当前 `chain` 放入 `x9`，并跳入 `hook_dispatch0/4/8/12`。

### 2.3 `fp_hook_chain_t`

`fp_hook_chain_t` 是函数指针 wrap 的链对象。它不包含 `hook_t`，而是包含：

```c
typedef struct {
    uintptr_t fp_addr;
    uint64_t replace_addr;
    uint64_t origin_fp;
} fp_hook_t;
```

- `fp_addr`：函数指针槽位地址。
- `origin_fp`：槽位原始函数地址。
- `replace_addr`：`chain->transit`，用于写入函数指针槽位。

### 2.4 `hook_fargs*_t`

回调收到的是 `hook_fargs0_t`、`hook_fargs4_t`、`hook_fargs8_t`、`hook_fargs12_t` 之一。

当前实现按参数数量分组：

- 0 参数走 `hook_fargs0_t`。
- 1 到 4 参数走 `hook_fargs4_t`。
- 5 到 8 参数走 `hook_fargs8_t`。
- 9 到 12 参数走 `hook_fargs12_t`。

回调可以：

- 修改 `arg0` 到 `arg11`，影响 origin 调用参数。
- 设置 `skip_origin = 1` 跳过原函数。
- 修改 `ret`，影响最终返回值。
- 使用 `local.data[]` 在 before/after 之间传递少量局部数据。
- 读取 `chain` 获取链对象。

## 3. inline hook 工作流

入口：`hook()`，实现主体在 `hook_chain.c`。

### 3.1 安装流程

1. 校验 `func`、`replace`、`backup`。
2. 调用 `branch_func_addr()` 解析真实入口：
   - 如果入口是 `B`，继续追踪跳转目标。
   - 如果入口是 BTI 指令，跳过 BTI。
   - 如果 BTI 后已经是本框架 hook 形态，则保留当前入口地址，避免卸载时把 origin 解析到 `origin + 4`。
3. 用 `hook_get_mem_from_origin(origin)` 检查重复 hook。
4. 从 `hmem.c` 分配 `hook_t`。
5. 填充：
   - `func_addr = func`
   - `origin_addr = origin`
   - `replace_addr = replace`
   - `relo_addr = hook->relo_insts`
   - `*backup = hook->relo_addr`
6. 调用 `hook_prepare()` 生成 trampoline 与 relocated backup。
7. 调用 `hook_install()` 写入目标函数入口。

### 3.2 `hook_prepare()` 做了什么

`hook_prepare()` 是 inline hook 的关键步骤：

1. 备份目标函数入口最多 `TRAMPOLINE_MAX_NUM` 条指令到 `origin_insts`。
2. 生成 `tramp_insts`：
   - 当前 `branch_from_to()` 使用 `ret_absolute()`。
   - 指令形态为 `LDR X17, #8; RET X17; addr64`。
   - 如果原函数入口是 PACIASP/PACIBSP，会额外插入 `BTI JC`。
3. 根据将覆盖的指令数量，对原入口指令逐条调用 `relocate_inst()`，生成 `relo_insts`。
4. 在 `relo_insts` 末尾追加跳回：
   - 跳回 `origin_addr + tramp_insts_num * 4`。
5. 如果检测到目标已经是本框架 hook 形态，则直接复制原 hook 指令到 relocated 区域，用于支持再次链式接入的场景。

### 3.3 安装与卸载

- `hook_install()` 调用 `hook_patch_text(origin_addr, tramp_insts, tramp_insts_num, 1)`。
- `hook_uninstall()` 调用 `hook_patch_text(origin_addr, origin_insts, tramp_insts_num, 0)`。

`head_last = 1` 时，先写入口后面的指令，最后写第 1 条指令，降低其他 CPU 看到半成品入口的概率。

PAC/BTI 场景下，已安装的入口可能是：

```text
BTI JC
LDR X17, #8
RET X17
addr64
```

当前 `branch_func_addr_once()` 会识别这种已 hook 入口并返回原地址，不再跳过 BTI。这样 `unhook(func)` 能用正确 origin 找到 hook 记录并正常恢复，不需要依赖 `vfs_open` demo 的兜底恢复。

## 4. ARM64 指令重定位

实现：`hook_reloc.c`。

inline hook 覆盖目标函数入口若干条指令后，backup 必须能继续执行这些原始指令。问题是 ARM64 很多指令是 PC-relative 的，从新地址执行会计算出错误目标，所以需要重定位。

当前识别并处理的类型包括：

- `B`
- `B.cond`
- `BL`
- `ADR`
- `ADRP`
- `LDR literal`
- `LDRSW literal`
- `PRFM literal`
- SIMD literal load
- `CBZ` / `CBNZ`
- `TBZ` / `TBNZ`
- 其他指令按原样复制并补 NOP

重定位策略总体是：

1. 从原指令中解出目标地址。
2. 如果目标落在被覆盖的 trampoline 区域内，通过 `relo_in_tramp()` 映射到 relocated 后的新地址。
3. 生成“加载绝对地址 + 间接跳转/加载”的等价指令序列。

目前每类指令都有固定的 `relo_len[]`，所以 `hook_prepare()` 可以提前做 buffer 上界检查。

## 5. inline wrap 工作流

入口：`hook_wrap()`。

inline wrap 与 inline hook 的区别是：目标函数入口不是跳到业务替换函数，而是跳到框架生成的 `chain->transit`。

### 5.1 第一次 wrap

1. 根据 `func` 解析 `origin`。
2. 若该 origin 尚未建立 chain，分配 `hook_chain_t`。
3. 设置 `hook->replace_addr = chain->transit`。
4. 调用 `hook_prepare()` 生成 inline hook 所需数据。
5. 调用 `hook_chain_prepare()` 写入 `chain->transit`：

```text
BTI JC
LDR X9, #12       ; X9 = chain
LDR X17, #16      ; X17 = hook_dispatch0/4/8/12
BR X17
chain
dispatcher
```

6. 调用 `hook_chain_add()` 添加 before/after。
7. 调用 `hook_chain_install()` 安装入口 patch。

### 5.2 后续 wrap

如果同一个 origin 已经存在 `hook_chain_t`，不再重复 patch 目标函数，只向已有 chain 增加一个回调槽位。

### 5.3 调用时序

以 `hook_dispatch4()` 为例：

1. 从 `x9` 取出 `hook_chain_t`。
2. 在自旋锁保护下复制当前 READY 回调到栈上 snapshot。
3. 按注册顺序执行 before。
4. 如果 `skip_origin == 0`：
   - 通过 `hook_chain->hook.relo_addr` 调用 relocated origin。
   - 参数使用可能已被 before 修改后的 `fargs.arg*`。
5. 按反向顺序执行 after。
6. 返回 `fargs.ret`。

before 正序、after 逆序的语义类似嵌套包装：

```text
before A
  before B
    origin
  after B
after A
```

### 5.4 unwrap

`hook_unwrap_remove()` 先移除匹配的 before 或 after 槽位。若所有槽位为空：

1. 调用 `hook_chain_uninstall()` 恢复目标函数入口。
2. 调用 `synchronize_rcu()` 等待并发读侧结束。
3. 调用 `hook_mem_retire()` 退休该槽位。

当前 snapshot 使用的是自旋锁复制，不是 RCU 无锁遍历；`synchronize_rcu()` 主要用于保守等待可能仍在执行的旧路径。

## 6. function pointer hook 与 wrap

实现：`fp_hook.c`。

### 6.1 直接函数指针 hook

`fp_hook(fp_addr, replace, backup)`：

1. 读取 `*(uintptr_t *)fp_addr` 保存到 `backup`。
2. 调用 `hook_patch_data(fp_addr, &replace, sizeof(replace))` 写入新函数地址。

`fp_unhook(fp_addr, backup)` 则把槽位恢复为 `backup`。

这种方式不需要指令重定位，因为不改写代码，只改写数据指针。

### 6.2 函数指针 wrap

`fp_hook_wrap()` 的结构与 inline wrap 基本一致，但入口点是函数指针槽位：

1. 使用 `fp_addr` 作为 origin key 查找或创建 `fp_hook_chain_t`。
2. `chain->hook.replace_addr = chain->transit`。
3. `hook_chain_prepare()` 写入 `transit`，同样通过 `x9` 传递 chain。
4. 首次创建时调用 `fp_hook(fp_addr, chain->transit, &origin_fp)`。
5. 添加 before/after 槽位。

调用时进入 `fp_dispatch0/4/8/12`。与 inline wrap 不同的是，origin 调用目标来自：

```c
READ_ONCE(hook_chain->hook.origin_fp)
```

而不是 `hook.relo_addr`。

### 6.3 fp unwrap

当所有回调槽位为空时：

1. 调用 `fp_unhook(fp_addr, origin_fp)` 恢复槽位。
2. `synchronize_rcu()`。
3. `hook_mem_retire(chain)`。

## 7. 回调链槽位与并发模型

共享逻辑在 `hook_chain_ops.h`。

### 7.1 槽位状态

- `CHAIN_ITEM_STATE_EMPTY`：空闲。
- `CHAIN_ITEM_STATE_BUSY`：正在写入或移除。
- `CHAIN_ITEM_STATE_READY`：可被 dispatch 使用。

添加槽位时顺序是：

1. `EMPTY -> BUSY`
2. 写入 `udata` / `before` / `after`
3. 更新 `chain_items_max`
4. `BUSY -> READY`

移除槽位时顺序是：

1. `READY -> BUSY`
2. 清空 `udata` / `before` / `after`
3. `BUSY -> EMPTY`

中间用 `smp_wmb()` 保证写入顺序。

### 7.2 snapshot

dispatch 时调用 `hook_chain_snapshot_common()`：

1. 获取 chain 自旋锁。
2. 读取 `chain_items_max`。
3. 只复制 READY 槽位到栈上数组。
4. 释放锁。

后续执行 before/after 时不持锁，避免回调内执行慢路径时长时间占用锁。

### 7.3 重复与容量限制

- 同一个 chain 内，如果 before 或 after 任一函数指针重复，会返回 `HOOK_DUPLICATED`。
- inline wrap 最大 `HOOK_CHAIN_NUM = 0x10` 个槽位。
- fp wrap 最大 `FP_HOOK_CHAIN_NUM = 0x20` 个槽位。

## 8. Hook 内存管理

实现：`hmem.c`。

模块加载时，`lkm.c` 调用 `hook_module_prepare_text()`：

1. 通过 `hook_alloc(PAGE_SIZE * 10)` 申请一段可执行模块内存。
2. 设置全局 `mod_base` / `mod_end`，供 KCFI 绕过逻辑判断目标是否落在 hook 区域。
3. 遍历这 10 页 PTE，清掉 `PTE_PXN`、`PTE_RDONLY`、`PTE_GP`，设置可写/共享等属性。
4. flush TLB。
5. 调用 `hook_mem_add()` 把这段内存交给 hook allocator。

`hmem.c` 将这段区域切成 `hook_mem_warp_t` 槽位，每个槽位可存放：

- `hook_t`
- `hook_chain_t`
- `fp_hook_chain_t`

查找使用 `origin_addr` 或 `fp_addr` 作为 key。

### 8.1 retire 而不是立即复用

`hook_mem_retire()` 会清空 `addr` / `type` / `refcount`，但保留 `using = 1`。源码注释说明：

> retired slot occupied until module teardown so any stale backup/transit pointer won't jump into re-used memory.

也就是说，卸载 hook 后不立即复用该槽位，避免外部仍持有旧 backup/transit 指针时跳进已复用的新对象。

## 9. patch 后端

实现：`hotpatch.c`。

### 9.1 hotpatch 路径

`hotpatch_init()` 会设置 `hotpatch_init_flag = 1`。之后：

- `hook_patch_text()` 走 `hotpatch()`。
- `hook_patch_data()` 走 `hotpatch_write()`。

hotpatch 使用：

- `stop_machine()` 让在线 CPU 进入同步回调。
- 最后一个进入的 CPU 作为 master 执行真实写入。
- fixmap 临时映射目标物理页。
- `copy_to_kernel_nofault()` 写入。
- 对 text patch 按 patch 范围执行 cache clean/invalidate。
- 其他 CPU 等待完成后执行 `isb()`。

这种方式避免长期修改目标页 PTE，也减少并发执行期间看到不一致指令的风险。

注意：`flush_icache_range()` 在 ARM64 上会调用 `kick_all_cpus_sync()`，不能直接放在 `stop_machine()` 回调内部，否则容易与停机回调中的 CPU 等待形成死锁。当前 hotpatch master CPU 在 `stop_machine()` 内使用 `caches_clean_inval_pou(start, end)` 做范围级 cache 同步，随后所有 CPU 通过回调末尾的 `isb()` 完成指令同步。

### 9.2 fallback 路径

如果 `hotpatch_init_flag == 0`：

- `hook_patch_prepare_pages()` 通过 `pte_from_kva()` 找到涉及页。
- 临时 `pte_mkwrite()`。
- 写入 text/data。
- text 写入后调用 `flush_icache_range(addr, addr + len)`；data 写入后执行 barrier。
- 恢复原 PTE。
- flush TLB。

当前模块入口会先调用 `hotpatch_init()`，所以正常路径是 fixmap + `stop_machine()`。

## 10. KCFI 绕过

实现：`secpass.c`。

框架生成的 `transit` 和 `relo_insts` 位于运行时申请的模块内存，不一定具备内核 KCFI 期望的类型元数据。直接通过函数指针或间接调用跳入这些地址，可能触发 CFI failure。

当前方案是：

1. `bypass_kcfi()` 查找并 inline hook：
   - `report_cfi_failure`
   - `__cfi_slowpath_diag` 或 `__cfi_slowpath`
2. 替换函数判断目标地址是否位于：

```c
target > mod_base && target < mod_end
```

3. 如果是本模块 hook 内存范围：
   - `report_cfi_failure` 路径返回 `BUG_TRAP_TYPE_WARN`。
   - `__cfi_slowpath` 路径直接 return。
4. 卸载模块时 `restore_kcfi()` 恢复相关 hook。

因此当前模块初始化阶段会直接执行 `bypass_kcfi()`，不再通过模块参数单独开关。

## 11. syscall hook 封装

实现：`syscall.c`。

初始化 `syscall_init()` 会尝试解析：

- `sys_call_table`
- `compat_sys_call_table`
- 是否存在 `__arm64_sys_*` wrapper
- 是否存在 compat syscall

封装策略：

- 如果拿到 syscall table，则 `hook_syscalln()` 使用 `fp_hook_wrap()` 修改表项。
- 如果拿不到 syscall table，则根据 syscall name 找符号，并使用 `hook_wrap()` inline 包装。
- 如果内核使用 syscall wrapper，参数数目会被压缩为 1，即 `struct pt_regs *`。

注意：当前 `lkm.c` 未显式调用 `syscall_init()`，所以 syscall 封装属于框架能力，但不是模块默认自测主路径。

## 12. 模块入口与自测

入口：`hook_module_init()`。

初始化顺序：

1. `hotpatch_init()`
2. `hook_module_prepare_text()`
3. 调用 `bypass_kcfi()`
4. 根据 `enable_selftests` 运行自测
5. 根据 `enable_vfs_demo` 安装 `vfs_open` demo hook

卸载顺序：

1. `unhook_vfs_open()`
2. `hook_mem_check_leaks()`
3. `hook_mem_cleanup_all()`
4. `hook_free(text)`
5. `restore_kcfi()`

当前模块参数默认值偏向真实 `vfs_open` hook 测试：

- `enable_selftests = false`
- `enable_vfs_demo = true`
- `enable_inline_selftests = false`
- `enable_fp_selftests = false`
- `enable_syscall_selftests = false`

### 12.1 自测覆盖

`lkm.c` 当前覆盖：

- inline hook：
  - baseline 为 5。
  - hook 后替换函数调用 backup，再加 1000，期望 1005。
  - unhook 后恢复为 5。

- inline wrap：
  - before 修改两个参数各加 1。
  - after 修改返回值加 10。
  - baseline 3，wrap 后期望 15。

- fp hook：
  - 函数指针从 `x * 2` 改为 `x * 3`。
  - backup 仍可调用原始函数。

- fp wrap：
  - 与 inline wrap 类似，验证 before/after/hits。

KCFI bypass 当前不是模块参数开关，模块初始化阶段会直接执行 `bypass_kcfi()`，自测是否运行只由 `enable_selftests` 及各 selftest 子开关控制。

## 13. vfs_open demo

`hook_vfs_open()` 通过 `m_kallsyms_lookup_name("vfs_open")` 找到目标函数，调用：

```c
hook(target_func, new_vfs_open, (void **)&back_vfs_open);
```

`new_vfs_open()` 打印 `d_path()` 得到的文件路径，然后调用 `back_vfs_open(path, file)` 继续原逻辑。

这是普通 inline hook 的示例，不使用 chain wrap。

卸载时 `unhook_vfs_open()` 会：

1. 设置 `vfs_hook_unloading = true`，让已进入替换函数的路径只调用原函数，不再打印路径。
2. 等待 `vfs_open_active` 归零。
3. 调用通用 `unhook(target_func)`。
4. 校验 `vfs_open` 入口是否恢复为安装前保存的原始指令。
5. 如果入口仍是 hook 指令或不匹配，则调用 `hook_patch_text()` 强制恢复，并 retire 对应 hook 内存。

最新测试中，修复 `branch_func_addr()` 对 BTI + hook 入口的解析后，卸载走正常 `unhook -> Hook retired` 路径，`force restore` 兜底没有再触发。

## 14. 当前实现特点与限制

### 14.1 特点

- inline hook 与 wrap 复用同一套 `hook_prepare()` / `hook_install()`。
- fp hook 不依赖指令重定位，适合 ops table / syscall table。
- wrap 支持多个 before/after，并允许修改参数、跳过原函数、修改返回值。
- patch 后端已有 `stop_machine()` + fixmap 路径。
- text patch 的 I-cache 同步已收敛到 patch 范围，避免全量 `flush_icache_all()`。
- retired hook 槽位不复用，降低旧 backup/transit 指针误跳风险。
- KCFI 绕过仅放行 `mod_base` 到 `mod_end` 的 hook 内存区域。

### 14.2 限制与风险点

- 仅面向 ARM64/AArch64。
- inline hook 能否成功依赖入口前几条指令能被 `hook_reloc.c` 正确重定位。
- `ADRP` 目标落在被覆盖区域时会返回 `HOOK_BAD_RELO`。
- 当前 `branch_from_to()` 总是生成绝对跳转形态，没有使用近距离 `B` 优化。
- `TRAMPOLINE_MAX_NUM`、`RELOCATE_INST_NUM` 是固定容量，复杂入口可能失败。
- wrap 只建模最多 12 个整数/指针参数；浮点/SIMD 参数没有专门建模。
- 回调签名统一按 `uint64_t` 参数处理，需要调用者自行理解真实 ABI。
- KCFI bypass 本身通过 inline hook 实现，初始化顺序和目标内核符号可用性很关键。
- `syscall.c` 能力依赖 `syscall_init()` 初始化 syscall table/wrapper 状态，当前模块入口未默认调用。
- `pgfault.c` 更像实验代码，未接入主模块生命周期。

## 15. 推荐阅读顺序

如果要继续维护这套框架，建议按以下顺序读代码：

1. `hook_types.h`：先理解数据结构和容量限制。
2. `lkm.c`：看初始化、自测和 demo。
3. `hook_chain.c`：理解 inline hook 与 inline wrap 主流程。
4. `fp_hook.c`：理解函数指针 hook 与 wrap。
5. `hook_reloc.c`：理解为什么 backup 能执行原函数入口。
6. `hotpatch.c`、`pgtable.c`、`cache.h`：理解写 text/data 的底层机制。
7. `secpass.c`：理解 KCFI 绕过边界。
8. `syscall.c`、`pgfault.c`：理解扩展能力与实验分支。
