obj-m := hook_module.o

hook_module-objs := lkm.o \
                   hook.o \
                   hook_chain.o \
                   fp_hook.o \
                   hook_reloc.o \
                   hmem.o \
				   kallsyms_name.o \
                   secpass.o \
                   syscall.o \
                   sysname.o pgtable.o hotpatch.o

# EXTRA_CFLAGS += -fno-sanitize=kcfi
ccflags-y += -std=gnu11 -Wno-strict-prototypes -Wno-gcc-compat -Wno-unused-function -Wno-format -Wno-int-conversion -Wno-unused-variable
ccflags-y += -fno-builtin -nostdinc -Wno-declaration-after-statement
ccflags-y += -fno-stack-protector -g -O2 -Wno-missing-prototypes 



