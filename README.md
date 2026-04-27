# kernel_hook

Android arm64 内核 Hook 实验项目，包含：

- 内核模块 `hook_module.ko`
- 自定义 text/data patch 后端
- inline hook / inline wrap
- function pointer hook / function pointer wrap
- 设备端 Rust loader，用于解析 ELF、补未定义符号并调用 `init_module`

## 目录说明

- `lkm.c`
  模块主入口、自测逻辑、`vfs_open` demo hook
- `hook_chain.c`
  inline hook / inline wrap 主实现
- `fp_hook.c`
  function pointer hook / wrap 主实现
- `hotpatch.c`
  text/data patch 后端
- `hmem.c`
  hook 内存池与生命周期管理
- `loader/`
  Rust 编写的模块加载器

## 构建

### 内核模块

默认使用仓库内的 `build_module.sh`：

```bash
bash build_module.sh
```

输出：

- `hook_module.ko`

### Rust loader

主机侧检查：

```bash
cd loader
cargo check
```

构建 Android arm64 版本：

```bash
cd loader
cargo build --target aarch64-linux-android --release
```

当前仓库默认使用的 NDK 路径写在：

- [loader/.cargo/config.toml](/home/qiu/Android/kernel_hook/loader/.cargo/config.toml)

## 设备端加载

### 方式一：主机侧一键 adb 运行

```bash
cd loader
cargo run -- --adb-run \
  --device-loader target/aarch64-linux-android/release/hook-loader \
  --name hook_module \
  ../hook_module.ko \
  enable_selftests=1 enable_kcfi_bypass=0 enable_vfs_demo=0
```

说明：

- 主机只负责 `adb push` 和远程执行
- 设备端 `hook-loader` 负责：
  - 读取 `.ko`
  - 解析 ELF
  - 从 `/proc/kallsyms` 补未定义符号
  - 调用 `init_module`
  - 失败时抓相关 `dmesg`

### 方式二：手动 adb 执行设备端 loader

```bash
adb push loader/target/aarch64-linux-android/release/hook-loader /data/local/tmp/hook_loader/hook-loader
adb push hook_module.ko /data/local/tmp/hook_loader/hook_module.ko
adb shell "su -c 'chmod 755 /data/local/tmp/hook_loader/hook-loader && \
  /data/local/tmp/hook_loader/hook-loader \
  --name hook_module \
  /data/local/tmp/hook_loader/hook_module.ko \
  enable_selftests=1 enable_kcfi_bypass=0 enable_vfs_demo=0'"
```

## 模块参数

`lkm.c` 目前支持以下参数：

- `enable_selftests`
  加载时运行本地自测
- `enable_kcfi_bypass`
  安装 KCFI bypass hook
- `enable_inline_selftests`
  是否运行 inline hook / inline wrap 自测
- `enable_fp_selftests`
  是否运行 fp hook / fp wrap 自测
- `enable_vfs_demo`
  是否安装 `vfs_open` demo hook

## 已验证场景

在当前测试设备上已验证通过：

- 设备端 Rust loader 可正常加载模块
- 参数传递正常
- `fp_hook`
- `fp_hook_wrap`
- `inline hook`
- `inline wrap`
- `enable_vfs_demo=1` 时真实 `vfs_open` hook
- `rmmod hook_module` 可正常卸载

## 推荐测试组合

### 仅验证 fp hook

```text
enable_selftests=1 enable_kcfi_bypass=0 enable_inline_selftests=0 enable_fp_selftests=1 enable_vfs_demo=0
```

### 验证全部自测

```text
enable_selftests=1 enable_kcfi_bypass=1 enable_inline_selftests=1 enable_fp_selftests=1 enable_vfs_demo=0
```

### 验证真实 vfs hook

```text
enable_selftests=0 enable_kcfi_bypass=1 enable_inline_selftests=0 enable_fp_selftests=0 enable_vfs_demo=1
```

## 当前限制

- 当前模块仍依赖设备端 loader 的“补符号后 `init_module`”方式加载
- 还没有收敛到“标准 `insmod` 无补符号直接加载”的状态
- 构建输出中仍有不少 modpost unresolved symbol 警告，需要后续继续处理
