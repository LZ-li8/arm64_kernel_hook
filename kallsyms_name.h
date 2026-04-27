#ifndef __HOOK_LOOKUP_NAME_H
#define __HOOK_LOOKUP_NAME_H
#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>


u64 m_kallsyms_lookup_name(const char *symbol_name); 

u64 * find_syscall_table(void);



#endif