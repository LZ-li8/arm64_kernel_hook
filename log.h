#ifndef __HOOK_LOG_H
#define __HOOK_LOG_H

#include <linux/printk.h>

#define DEBUG

#ifdef DEBUG
#define hook_debug(fmt, ...) pr_debug("hookmod: " fmt, ##__VA_ARGS__)
#else
#define hook_debug(fmt, ...)
#endif

#define hook_info(fmt, ...) pr_info("hookmod: " fmt, ##__VA_ARGS__)
#define hook_warn(fmt, ...) pr_warn("hookmod: " fmt, ##__VA_ARGS__)
#define hook_err(fmt, ...) pr_err("hookmod: " fmt, ##__VA_ARGS__)

#define hook_debug_func(fmt, ...) hook_debug("%s: " fmt, __func__, ##__VA_ARGS__)
#define hook_info_func(fmt, ...) hook_info("%s: " fmt, __func__, ##__VA_ARGS__)
#define hook_warn_func(fmt, ...) hook_warn("%s: " fmt, __func__, ##__VA_ARGS__)
#define hook_err_func(fmt, ...) hook_err("%s: " fmt, __func__, ##__VA_ARGS__)

/* Legacy aliases kept here so log.h remains the single logging API source. */
#define logkd(fmt, ...) hook_debug(fmt, ##__VA_ARGS__)
#define logkfd(fmt, ...) hook_debug_func(fmt, ##__VA_ARGS__)

#define logki(fmt, ...) hook_info(fmt, ##__VA_ARGS__)
#define logkfi(fmt, ...) hook_info_func(fmt, ##__VA_ARGS__)

#define logkw(fmt, ...) hook_warn(fmt, ##__VA_ARGS__)
#define logkfw(fmt, ...) hook_warn_func(fmt, ##__VA_ARGS__)

#define logke(fmt, ...) hook_err(fmt, ##__VA_ARGS__)
#define logkfe(fmt, ...) hook_err_func(fmt, ##__VA_ARGS__)

#define logkv(fmt, ...) hook_debug(fmt, ##__VA_ARGS__)
#define logkfv(fmt, ...) hook_debug_func(fmt, ##__VA_ARGS__)

#endif
