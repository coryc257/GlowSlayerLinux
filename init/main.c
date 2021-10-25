// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/init/main.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  GK 2/5/95  -  Changed to support mounting root fs via NFS
 *  Added initrd & change_root: Werner Almesberger & Hans Lermen, Feb '96
 *  Moan early if gcc is old, avoiding bogus kernels - Paul Gortmaker, May '96
 *  Simplified starting of init:  Michael A. Griffith <grif@acm.org>
 */

#define DEBUG		/* Enable initcall_debug */

#include <linux/types.h>
#include <linux/extable.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/binfmts.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/stackprotector.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/memblock.h>
#include <linux/acpi.h>
#include <linux/bootconfig.h>
#include <linux/console.h>
#include <linux/nmi.h>
#include <linux/percpu.h>
#include <linux/kmod.h>
#include <linux/kprobes.h>
#include <linux/vmalloc.h>
#include <linux/kernel_stat.h>
#include <linux/start_kernel.h>
#include <linux/security.h>
#include <linux/smp.h>
#include <linux/profile.h>
#include <linux/kfence.h>
#include <linux/rcupdate.h>
#include <linux/srcu.h>
#include <linux/moduleparam.h>
#include <linux/kallsyms.h>
#include <linux/buildid.h>
#include <linux/writeback.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/cgroup.h>
#include <linux/efi.h>
#include <linux/tick.h>
#include <linux/sched/isolation.h>
#include <linux/interrupt.h>
#include <linux/taskstats_kern.h>
#include <linux/delayacct.h>
#include <linux/unistd.h>
#include <linux/utsname.h>
#include <linux/rmap.h>
#include <linux/mempolicy.h>
#include <linux/key.h>
#include <linux/page_ext.h>
#include <linux/debug_locks.h>
#include <linux/debugobjects.h>
#include <linux/lockdep.h>
#include <linux/kmemleak.h>
#include <linux/padata.h>
#include <linux/pid_namespace.h>
#include <linux/device/driver.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/sched/init.h>
#include <linux/signal.h>
#include <linux/idr.h>
#include <linux/kgdb.h>
#include <linux/ftrace.h>
#include <linux/async.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/perf_event.h>
#include <linux/ptrace.h>
#include <linux/pti.h>
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/sched/clock.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/context_tracking.h>
#include <linux/random.h>
#include <linux/list.h>
#include <linux/integrity.h>
#include <linux/proc_ns.h>
#include <linux/io.h>
#include <linux/cache.h>
#include <linux/rodata_test.h>
#include <linux/jump_label.h>
#include <linux/mem_encrypt.h>
#include <linux/kcsan.h>
#include <linux/init_syscalls.h>
#include <linux/stackdepot.h>

#include <asm/io.h>
#include <asm/bugs.h>
#include <asm/setup.h>
#include <asm/sections.h>
#include <asm/cacheflush.h>

#define CREATE_TRACE_POINTS
#include <trace/events/initcall.h>

#include <kunit/test.h>

static int kernel_init(void *);

extern void init_IRQ(void);
extern void radix_tree_init(void);

/*
 * Debug helper: via this flag we know that we are in 'early bootup code'
 * where only the boot processor is running with IRQ disabled.  This means
 * two things - IRQ must not be enabled before the flag is cleared and some
 * operations which are not allowed with IRQ disabled are allowed while the
 * flag is set.
 */
bool early_boot_irqs_disabled __read_mostly;

enum system_states system_state __read_mostly;
EXPORT_SYMBOL(system_state);

/*
 * Boot command-line arguments
 */
#define MAX_INIT_ARGS CONFIG_INIT_ENV_ARG_LIMIT
#define MAX_INIT_ENVS CONFIG_INIT_ENV_ARG_LIMIT

extern void time_init(void);
/* Default late time init is NULL. archs can override this later. */
void (*__initdata late_time_init)(void);

/* Untouched command line saved by arch-specific code. */
char __initdata boot_command_line[COMMAND_LINE_SIZE];
/* Untouched saved command line (eg. for /proc) */
char *saved_command_line;
/* Command line for parameter parsing */
static char *static_command_line;
/* Untouched extra command line */
static char *extra_command_line;
/* Extra init arguments */
static char *extra_init_args;

#ifdef CONFIG_BOOT_CONFIG
/* Is bootconfig on command line? */
static bool bootconfig_found;
static bool initargs_found;
#else
# define bootconfig_found false
# define initargs_found false
#endif

static char *execute_command;
static char *ramdisk_execute_command = "/init";

/*
 * Used to generate warnings if static_key manipulation functions are used
 * before jump_label_init is called.
 */
bool static_key_initialized __read_mostly;
EXPORT_SYMBOL_GPL(static_key_initialized);

/*
 * If set, this is an indication to the drivers that reset the underlying
 * device before going ahead with the initialization otherwise driver might
 * rely on the BIOS and skip the reset operation.
 *
 * This is useful if kernel is booting in an unreliable environment.
 * For ex. kdump situation where previous kernel has crashed, BIOS has been
 * skipped and devices will be in unknown state.
 */
unsigned int reset_devices;
EXPORT_SYMBOL(reset_devices);

static int __init set_reset_devices(char *str)
{
	reset_devices = 1;
	return 1;
}

__setup("reset_devices", set_reset_devices);

static const char *argv_init[MAX_INIT_ARGS+2] = { "init", NULL, };
const char *envp_init[MAX_INIT_ENVS+2] = { "HOME=/", "TERM=linux", NULL, };
static const char *panic_later, *panic_param;

extern const struct obs_kernel_param __setup_start[], __setup_end[];

static bool __init obsolete_checksetup(char *line)
{
	const struct obs_kernel_param *p;
	bool had_early_param = false;

	p = __setup_start;
	do {
		int n = strlen(p->str);
		if (parameqn(line, p->str, n)) {
			if (p->early) {
				/* Already done in parse_early_param?
				 * (Needs exact match on param part).
				 * Keep iterating, as we can have early
				 * params and __setups of same names 8( */
				if (line[n] == '\0' || line[n] == '=')
					had_early_param = true;
			} else if (!p->setup_func) {
				pr_warn("Parameter %s is obsolete, ignored\n",
					p->str);
				return true;
			} else if (p->setup_func(line + n))
				return true;
		}
		p++;
	} while (p < __setup_end);

	return had_early_param;
}

/*
 * This should be approx 2 Bo*oMips to start (note initial shift), and will
 * still work even if initially too large, it will just take slightly longer
 */
unsigned long loops_per_jiffy = (1<<12);
EXPORT_SYMBOL(loops_per_jiffy);

static int __init debug_kernel(char *str)
{
	console_loglevel = CONSOLE_LOGLEVEL_DEBUG;
	return 0;
}

static int __init quiet_kernel(char *str)
{
	console_loglevel = CONSOLE_LOGLEVEL_QUIET;
	return 0;
}

early_param("debug", debug_kernel);
early_param("quiet", quiet_kernel);

static int __init loglevel(char *str)
{
	int newlevel;

	/*
	 * Only update loglevel value when a correct setting was passed,
	 * to prevent blind crashes (when loglevel being set to 0) that
	 * are quite hard to debug
	 */
	if (get_option(&str, &newlevel)) {
		console_loglevel = newlevel;
		return 0;
	}

	return -EINVAL;
}

early_param("loglevel", loglevel);

#ifdef CONFIG_BLK_DEV_INITRD
static void * __init get_boot_config_from_initrd(u32 *_size, u32 *_csum)
{
	u32 size, csum;
	char *data;
	u32 *hdr;
	int i;

	if (!initrd_end)
		return NULL;

	data = (char *)initrd_end - BOOTCONFIG_MAGIC_LEN;
	/*
	 * Since Grub may align the size of initrd to 4, we must
	 * check the preceding 3 bytes as well.
	 */
	for (i = 0; i < 4; i++) {
		if (!memcmp(data, BOOTCONFIG_MAGIC, BOOTCONFIG_MAGIC_LEN))
			goto found;
		data--;
	}
	return NULL;

found:
	hdr = (u32 *)(data - 8);
	size = le32_to_cpu(hdr[0]);
	csum = le32_to_cpu(hdr[1]);

	data = ((void *)hdr) - size;
	if ((unsigned long)data < initrd_start) {
		pr_err("bootconfig size %d is greater than initrd size %ld\n",
			size, initrd_end - initrd_start);
		return NULL;
	}

	/* Remove bootconfig from initramfs/initrd */
	initrd_end = (unsigned long)data;
	if (_size)
		*_size = size;
	if (_csum)
		*_csum = csum;

	return data;
}
#else
static void * __init get_boot_config_from_initrd(u32 *_size, u32 *_csum)
{
	return NULL;
}
#endif

#ifdef CONFIG_BOOT_CONFIG

static char xbc_namebuf[XBC_KEYLEN_MAX] __initdata;

#define rest(dst, end) ((end) > (dst) ? (end) - (dst) : 0)

static int __init xbc_snprint_cmdline(char *buf, size_t size,
				      struct xbc_node *root)
{
	struct xbc_node *knode, *vnode;
	char *end = buf + size;
	const char *val;
	int ret;

	xbc_node_for_each_key_value(root, knode, val) {
		ret = xbc_node_compose_key_after(root, knode,
					xbc_namebuf, XBC_KEYLEN_MAX);
		if (ret < 0)
			return ret;

		vnode = xbc_node_get_child(knode);
		if (!vnode) {
			ret = snprintf(buf, rest(buf, end), "%s ", xbc_namebuf);
			if (ret < 0)
				return ret;
			buf += ret;
			continue;
		}
		xbc_array_for_each_value(vnode, val) {
			ret = snprintf(buf, rest(buf, end), "%s=\"%s\" ",
				       xbc_namebuf, val);
			if (ret < 0)
				return ret;
			buf += ret;
		}
	}

	return buf - (end - size);
}
#undef rest

/* Make an extra command line under given key word */
static char * __init xbc_make_cmdline(const char *key)
{
	struct xbc_node *root;
	char *new_cmdline;
	int ret, len = 0;

	root = xbc_find_node(key);
	if (!root)
		return NULL;

	/* Count required buffer size */
	len = xbc_snprint_cmdline(NULL, 0, root);
	if (len <= 0)
		return NULL;

	new_cmdline = memblock_alloc(len + 1, SMP_CACHE_BYTES);
	if (!new_cmdline) {
		pr_err("Failed to allocate memory for extra kernel cmdline.\n");
		return NULL;
	}

	ret = xbc_snprint_cmdline(new_cmdline, len + 1, root);
	if (ret < 0 || ret > len) {
		pr_err("Failed to print extra kernel cmdline.\n");
		return NULL;
	}

	return new_cmdline;
}

static int __init bootconfig_params(char *param, char *val,
				    const char *unused, void *arg)
{
	if (strcmp(param, "bootconfig") == 0) {
		bootconfig_found = true;
	}
	return 0;
}

static int __init warn_bootconfig(char *str)
{
	/* The 'bootconfig' has been handled by bootconfig_params(). */
	return 0;
}

static void __init setup_boot_config(void)
{
	static char tmp_cmdline[COMMAND_LINE_SIZE] __initdata;
	const char *msg;
	int pos;
	u32 size, csum;
	char *data, *copy, *err;
	int ret;

	/* Cut out the bootconfig data even if we have no bootconfig option */
	data = get_boot_config_from_initrd(&size, &csum);

	strlcpy(tmp_cmdline, boot_command_line, COMMAND_LINE_SIZE);
	err = parse_args("bootconfig", tmp_cmdline, NULL, 0, 0, 0, NULL,
			 bootconfig_params);

	if (IS_ERR(err) || !bootconfig_found)
		return;

	/* parse_args() stops at '--' and returns an address */
	if (err)
		initargs_found = true;

	if (!data) {
		pr_err("'bootconfig' found on command line, but no bootconfig found\n");
		return;
	}

	if (size >= XBC_DATA_MAX) {
		pr_err("bootconfig size %d greater than max size %d\n",
			size, XBC_DATA_MAX);
		return;
	}

	if (xbc_calc_checksum(data, size) != csum) {
		pr_err("bootconfig checksum failed\n");
		return;
	}

	copy = memblock_alloc(size + 1, SMP_CACHE_BYTES);
	if (!copy) {
		pr_err("Failed to allocate memory for bootconfig\n");
		return;
	}

	memcpy(copy, data, size);
	copy[size] = '\0';

	ret = xbc_init(copy, &msg, &pos);
	if (ret < 0) {
		if (pos < 0)
			pr_err("Failed to init bootconfig: %s.\n", msg);
		else
			pr_err("Failed to parse bootconfig: %s at %d.\n",
				msg, pos);
	} else {
		pr_info("Load bootconfig: %d bytes %d nodes\n", size, ret);
		/* keys starting with "kernel." are passed via cmdline */
		extra_command_line = xbc_make_cmdline("kernel");
		/* Also, "init." keys are init arguments */
		extra_init_args = xbc_make_cmdline("init");
	}
	return;
}

#else

static void __init setup_boot_config(void)
{
	/* Remove bootconfig data from initrd */
	get_boot_config_from_initrd(NULL, NULL);
}

static int __init warn_bootconfig(char *str)
{
	pr_warn("WARNING: 'bootconfig' found on the kernel command line but CONFIG_BOOT_CONFIG is not set.\n");
	return 0;
}
#endif
early_param("bootconfig", warn_bootconfig);

/* Change NUL term back to "=", to make "param" the whole string. */
static void __init repair_env_string(char *param, char *val)
{
	if (val) {
		/* param=val or param="val"? */
		if (val == param+strlen(param)+1)
			val[-1] = '=';
		else if (val == param+strlen(param)+2) {
			val[-2] = '=';
			memmove(val-1, val, strlen(val)+1);
		} else
			BUG();
	}
}

/* Anything after -- gets handed straight to init. */
static int __init set_init_arg(char *param, char *val,
			       const char *unused, void *arg)
{
	unsigned int i;

	if (panic_later)
		return 0;

	repair_env_string(param, val);

	for (i = 0; argv_init[i]; i++) {
		if (i == MAX_INIT_ARGS) {
			panic_later = "init";
			panic_param = param;
			return 0;
		}
	}
	argv_init[i] = param;
	return 0;
}

/*
 * Unknown boot options get handed to init, unless they look like
 * unused parameters (modprobe will find them in /proc/cmdline).
 */
static int __init unknown_bootoption(char *param, char *val,
				     const char *unused, void *arg)
{
	size_t len = strlen(param);

	repair_env_string(param, val);

	/* Handle obsolete-style parameters */
	if (obsolete_checksetup(param))
		return 0;

	/* Unused module parameter. */
	if (strnchr(param, len, '.'))
		return 0;

	if (panic_later)
		return 0;

	if (val) {
		/* Environment option */
		unsigned int i;
		for (i = 0; envp_init[i]; i++) {
			if (i == MAX_INIT_ENVS) {
				panic_later = "env";
				panic_param = param;
			}
			if (!strncmp(param, envp_init[i], len+1))
				break;
		}
		envp_init[i] = param;
	} else {
		/* Command line option */
		unsigned int i;
		for (i = 0; argv_init[i]; i++) {
			if (i == MAX_INIT_ARGS) {
				panic_later = "init";
				panic_param = param;
			}
		}
		argv_init[i] = param;
	}
	return 0;
}

static int __init init_setup(char *str)
{
	unsigned int i;

	execute_command = str;
	/*
	 * In case LILO is going to boot us with default command line,
	 * it prepends "auto" before the whole cmdline which makes
	 * the shell think it should execute a script with such name.
	 * So we ignore all arguments entered _before_ init=... [MJ]
	 */
	for (i = 1; i < MAX_INIT_ARGS; i++)
		argv_init[i] = NULL;
	return 1;
}
__setup("init=", init_setup);

static int __init rdinit_setup(char *str)
{
	unsigned int i;

	ramdisk_execute_command = str;
	/* See "auto" comment in init_setup */
	for (i = 1; i < MAX_INIT_ARGS; i++)
		argv_init[i] = NULL;
	return 1;
}
__setup("rdinit=", rdinit_setup);

#ifndef CONFIG_SMP
static const unsigned int setup_max_cpus = NR_CPUS;
static inline void setup_nr_cpu_ids(void) { }
static inline void smp_prepare_cpus(unsigned int maxcpus) { }
#endif

/*
 * We need to store the untouched command line for future reference.
 * We also need to store the touched command line since the parameter
 * parsing is performed in place, and we should allow a component to
 * store reference of name/value for future reference.
 */
static void __init setup_command_line(char *command_line)
{
	size_t len, xlen = 0, ilen = 0;

	if (extra_command_line)
		xlen = strlen(extra_command_line);
	if (extra_init_args)
		ilen = strlen(extra_init_args) + 4; /* for " -- " */

	len = xlen + strlen(boot_command_line) + 1;

	saved_command_line = memblock_alloc(len + ilen, SMP_CACHE_BYTES);
	if (!saved_command_line)
		panic("%s: Failed to allocate %zu bytes\n", __func__, len + ilen);

	static_command_line = memblock_alloc(len, SMP_CACHE_BYTES);
	if (!static_command_line)
		panic("%s: Failed to allocate %zu bytes\n", __func__, len);

	if (xlen) {
		/*
		 * We have to put extra_command_line before boot command
		 * lines because there could be dashes (separator of init
		 * command line) in the command lines.
		 */
		strcpy(saved_command_line, extra_command_line);
		strcpy(static_command_line, extra_command_line);
	}
	strcpy(saved_command_line + xlen, boot_command_line);
	strcpy(static_command_line + xlen, command_line);

	if (ilen) {
		/*
		 * Append supplemental init boot args to saved_command_line
		 * so that user can check what command line options passed
		 * to init.
		 */
		len = strlen(saved_command_line);
		if (initargs_found) {
			saved_command_line[len++] = ' ';
		} else {
			strcpy(saved_command_line + len, " -- ");
			len += 4;
		}

		strcpy(saved_command_line + len, extra_init_args);
	}
}

/*
 * We need to finalize in a non-__init function or else race conditions
 * between the root thread and the init thread may cause start_kernel to
 * be reaped by free_initmem before the root thread has proceeded to
 * cpu_idle.
 *
 * gcc-3.4 accidentally inlines this function, so use noinline.
 */

static __initdata DECLARE_COMPLETION(kthreadd_done);

noinline void __ref rest_init(void)
{
	struct task_struct *tsk;
	int pid;

	rcu_scheduler_starting();
	/*
	 * We need to spawn init first so that it obtains pid 1, however
	 * the init task will end up wanting to create kthreads, which, if
	 * we schedule it before we create kthreadd, will OOPS.
	 */
	pid = kernel_thread(kernel_init, NULL, CLONE_FS);
	/*
	 * Pin init on the boot CPU. Task migration is not properly working
	 * until sched_init_smp() has been run. It will set the allowed
	 * CPUs for init to the non isolated CPUs.
	 */
	rcu_read_lock();
	tsk = find_task_by_pid_ns(pid, &init_pid_ns);
	tsk->flags |= PF_NO_SETAFFINITY;
	set_cpus_allowed_ptr(tsk, cpumask_of(smp_processor_id()));
	rcu_read_unlock();

	numa_default_policy();
	pid = kernel_thread(kthreadd, NULL, CLONE_FS | CLONE_FILES);
	rcu_read_lock();
	kthreadd_task = find_task_by_pid_ns(pid, &init_pid_ns);
	rcu_read_unlock();

	/*
	 * Enable might_sleep() and smp_processor_id() checks.
	 * They cannot be enabled earlier because with CONFIG_PREEMPTION=y
	 * kernel_thread() would trigger might_sleep() splats. With
	 * CONFIG_PREEMPT_VOLUNTARY=y the init task might have scheduled
	 * already, but it's stuck on the kthreadd_done completion.
	 */
	system_state = SYSTEM_SCHEDULING;

	complete(&kthreadd_done);

	/*
	 * The boot idle thread must execute schedule()
	 * at least once to get things moving:
	 */
	schedule_preempt_disabled();
	/* Call into cpu_idle with preempt disabled */
	cpu_startup_entry(CPUHP_ONLINE);
}

/* Check for early params. */
static int __init do_early_param(char *param, char *val,
				 const char *unused, void *arg)
{
	const struct obs_kernel_param *p;

	for (p = __setup_start; p < __setup_end; p++) {
		if ((p->early && parameq(param, p->str)) ||
		    (strcmp(param, "console") == 0 &&
		     strcmp(p->str, "earlycon") == 0)
		) {
			if (p->setup_func(val) != 0)
				pr_warn("Malformed early option '%s'\n", param);
		}
	}
	/* We accept everything at this stage. */
	return 0;
}

void __init parse_early_options(char *cmdline)
{
	parse_args("early options", cmdline, NULL, 0, 0, 0, NULL,
		   do_early_param);
}

/* Arch code calls this early on, or if not, just before other parsing. */
void __init parse_early_param(void)
{
	static int done __initdata;
	static char tmp_cmdline[COMMAND_LINE_SIZE] __initdata;

	if (done)
		return;

	/* All fall through to do_early_param. */
	strlcpy(tmp_cmdline, boot_command_line, COMMAND_LINE_SIZE);
	parse_early_options(tmp_cmdline);
	done = 1;
}

void __init __weak arch_post_acpi_subsys_init(void) { }

void __init __weak smp_setup_processor_id(void)
{
}

# if THREAD_SIZE >= PAGE_SIZE
void __init __weak thread_stack_cache_init(void)
{
}
#endif

void __init __weak mem_encrypt_init(void) { }

void __init __weak poking_init(void) { }

void __init __weak pgtable_cache_init(void) { }

bool initcall_debug;
core_param(initcall_debug, initcall_debug, bool, 0644);

#ifdef TRACEPOINTS_ENABLED
static void __init initcall_debug_enable(void);
#else
static inline void initcall_debug_enable(void)
{
}
#endif

/* Report memory auto-initialization states for this boot. */
static void __init report_meminit(void)
{
	const char *stack;

	if (IS_ENABLED(CONFIG_INIT_STACK_ALL_PATTERN))
		stack = "all(pattern)";
	else if (IS_ENABLED(CONFIG_INIT_STACK_ALL_ZERO))
		stack = "all(zero)";
	else if (IS_ENABLED(CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL))
		stack = "byref_all(zero)";
	else if (IS_ENABLED(CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF))
		stack = "byref(zero)";
	else if (IS_ENABLED(CONFIG_GCC_PLUGIN_STRUCTLEAK_USER))
		stack = "__user(zero)";
	else
		stack = "off";

	pr_info("mem auto-init: stack:%s, heap alloc:%s, heap free:%s\n",
		stack, want_init_on_alloc(GFP_KERNEL) ? "on" : "off",
		want_init_on_free() ? "on" : "off");
	if (want_init_on_free())
		pr_info("mem auto-init: clearing system memory may take some time...\n");
}

/*
 * Set up kernel memory allocators
 */
static void __init mm_init(void)
{
	/*
	 * page_ext requires contiguous pages,
	 * bigger than MAX_ORDER unless SPARSEMEM.
	 */
	page_ext_init_flatmem();
	init_mem_debugging_and_hardening();
	kfence_alloc_pool();
	report_meminit();
	stack_depot_init();
	mem_init();
	mem_init_print_info();
	/* page_owner must be initialized after buddy is ready */
	page_ext_init_flatmem_late();
	kmem_cache_init();
	kmemleak_init();
	pgtable_init();
	debug_objects_mem_init();
	vmalloc_init();
	/* Should be run before the first non-init thread is created */
	init_espfix_bsp();
	/* Should be run after espfix64 is set up. */
	pti_init();
}

#ifdef CONFIG_HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
DEFINE_STATIC_KEY_MAYBE_RO(CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT,
			   randomize_kstack_offset);
DEFINE_PER_CPU(u32, kstack_offset);

static int __init early_randomize_kstack_offset(char *buf)
{
	int ret;
	bool bool_result;

	ret = kstrtobool(buf, &bool_result);
	if (ret)
		return ret;

	if (bool_result)
		static_branch_enable(&randomize_kstack_offset);
	else
		static_branch_disable(&randomize_kstack_offset);
	return 0;
}
early_param("randomize_kstack_offset", early_randomize_kstack_offset);
#endif

void __init __weak arch_call_rest_init(void)
{
	rest_init();
}

static void __init print_unknown_bootoptions(void)
{
	char *unknown_options;
	char *end;
	const char *const *p;
	size_t len;

	if (panic_later || (!argv_init[1] && !envp_init[2]))
		return;

	/*
	 * Determine how many options we have to print out, plus a space
	 * before each
	 */
	len = 1; /* null terminator */
	for (p = &argv_init[1]; *p; p++) {
		len++;
		len += strlen(*p);
	}
	for (p = &envp_init[2]; *p; p++) {
		len++;
		len += strlen(*p);
	}

	unknown_options = memblock_alloc(len, SMP_CACHE_BYTES);
	if (!unknown_options) {
		pr_err("%s: Failed to allocate %zu bytes\n",
			__func__, len);
		return;
	}
	end = unknown_options;

	for (p = &argv_init[1]; *p; p++)
		end += sprintf(end, " %s", *p);
	for (p = &envp_init[2]; *p; p++)
		end += sprintf(end, " %s", *p);

	pr_notice("Unknown command line parameters:%s\n", unknown_options);
	memblock_free(__pa(unknown_options), len);
}

asmlinkage __visible void __init __no_sanitize_address start_kernel(void)
{
	char *command_line;
	char *after_dashes;

	set_task_stack_end_magic(&init_task);
	smp_setup_processor_id();
	debug_objects_early_init();
	init_vmlinux_build_id();

	cgroup_init_early();

	local_irq_disable();
	early_boot_irqs_disabled = true;

	/*
	 * Interrupts are still disabled. Do necessary setups, then
	 * enable them.
	 */
	boot_cpu_init();
	page_address_init();
	pr_notice("%s", linux_banner);
	early_security_init();
	setup_arch(&command_line);
	setup_boot_config();
	setup_command_line(command_line);
	setup_nr_cpu_ids();
	setup_per_cpu_areas();
	smp_prepare_boot_cpu();	/* arch-specific boot-cpu hooks */
	boot_cpu_hotplug_init();

	build_all_zonelists(NULL);
	page_alloc_init();

	pr_notice("Kernel command line: %s\n", saved_command_line);
	/* parameters may set static keys */
	jump_label_init();
	parse_early_param();
	after_dashes = parse_args("Booting kernel",
				  static_command_line, __start___param,
				  __stop___param - __start___param,
				  -1, -1, NULL, &unknown_bootoption);
	print_unknown_bootoptions();
	if (!IS_ERR_OR_NULL(after_dashes))
		parse_args("Setting init args", after_dashes, NULL, 0, -1, -1,
			   NULL, set_init_arg);
	if (extra_init_args)
		parse_args("Setting extra init args", extra_init_args,
			   NULL, 0, -1, -1, NULL, set_init_arg);

	/*
	 * These use large bootmem allocations and must precede
	 * kmem_cache_init()
	 */
	setup_log_buf(0);
	vfs_caches_init_early();
	sort_main_extable();
	trap_init();
	mm_init();

	ftrace_init();

	/* trace_printk can be enabled here */
	early_trace_init();

	/*
	 * Set up the scheduler prior starting any interrupts (such as the
	 * timer interrupt). Full topology setup happens at smp_init()
	 * time - but meanwhile we still have a functioning scheduler.
	 */
	sched_init();

	if (WARN(!irqs_disabled(),
		 "Interrupts were enabled *very* early, fixing it\n"))
		local_irq_disable();
	radix_tree_init();

	/*
	 * Set up housekeeping before setting up workqueues to allow the unbound
	 * workqueue to take non-housekeeping into account.
	 */
	housekeeping_init();

	/*
	 * Allow workqueue creation and work item queueing/cancelling
	 * early.  Work item execution depends on kthreads and starts after
	 * workqueue_init().
	 */
	workqueue_init_early();

	rcu_init();

	/* Trace events are available after this */
	trace_init();

	if (initcall_debug)
		initcall_debug_enable();

	context_tracking_init();
	/* init some links before init_ISA_irqs() */
	early_irq_init();
	init_IRQ();
	tick_init();
	rcu_init_nohz();
	init_timers();
	srcu_init();
	hrtimers_init();
	softirq_init();
	timekeeping_init();
	kfence_init();

	/*
	 * For best initial stack canary entropy, prepare it after:
	 * - setup_arch() for any UEFI RNG entropy and boot cmdline access
	 * - timekeeping_init() for ktime entropy used in rand_initialize()
	 * - rand_initialize() to get any arch-specific entropy like RDRAND
	 * - add_latent_entropy() to get any latent entropy
	 * - adding command line entropy
	 */
	rand_initialize();
	add_latent_entropy();
	add_device_randomness(command_line, strlen(command_line));
	boot_init_stack_canary();

	time_init();
	perf_event_init();
	profile_init();
	call_function_init();
	WARN(!irqs_disabled(), "Interrupts were enabled early\n");

	early_boot_irqs_disabled = false;
	local_irq_enable();

	kmem_cache_init_late();

	/*
	 * HACK ALERT! This is early. We're enabling the console before
	 * we've done PCI setups etc, and console_init() must be aware of
	 * this. But we do want output early, in case something goes wrong.
	 */
	console_init();
	if (panic_later)
		panic("Too many boot %s vars at `%s'", panic_later,
		      panic_param);

	lockdep_init();

	/*
	 * Need to run this when irqs are enabled, because it wants
	 * to self-test [hard/soft]-irqs on/off lock inversion bugs
	 * too:
	 */
	locking_selftest();

	/*
	 * This needs to be called before any devices perform DMA
	 * operations that might use the SWIOTLB bounce buffers. It will
	 * mark the bounce buffers as decrypted so that their usage will
	 * not cause "plain-text" data to be decrypted when accessed.
	 */
	mem_encrypt_init();

#ifdef CONFIG_BLK_DEV_INITRD
	if (initrd_start && !initrd_below_start_ok &&
	    page_to_pfn(virt_to_page((void *)initrd_start)) < min_low_pfn) {
		pr_crit("initrd overwritten (0x%08lx < 0x%08lx) - disabling it.\n",
		    page_to_pfn(virt_to_page((void *)initrd_start)),
		    min_low_pfn);
		initrd_start = 0;
	}
#endif
	setup_per_cpu_pageset();
	numa_policy_init();
	acpi_early_init();
	if (late_time_init)
		late_time_init();
	sched_clock_init();
	calibrate_delay();
	pid_idr_init();
	anon_vma_init();
#ifdef CONFIG_X86
	if (efi_enabled(EFI_RUNTIME_SERVICES))
		efi_enter_virtual_mode();
#endif
	thread_stack_cache_init();
	cred_init();
	fork_init();
	proc_caches_init();
	uts_ns_init();
	key_init();
	security_init();
	dbg_late_init();
	vfs_caches_init();
	pagecache_init();
	signals_init();
	seq_file_init();
	proc_root_init();
	nsfs_init();
	cpuset_init();
	cgroup_init();
	taskstats_init_early();
	delayacct_init();

	poking_init();
	check_bugs();

	acpi_subsystem_init();
	arch_post_acpi_subsys_init();
	kcsan_init();

	/* Do the rest non-__init'ed, we're now alive */
	arch_call_rest_init();

	prevent_tail_call_optimization();
}

/* Call all constructor functions linked into the kernel. */
static void __init do_ctors(void)
{
/*
 * For UML, the constructors have already been called by the
 * normal setup code as it's just a normal ELF binary, so we
 * cannot do it again - but we do need CONFIG_CONSTRUCTORS
 * even on UML for modules.
 */
#if defined(CONFIG_CONSTRUCTORS) && !defined(CONFIG_UML)
	ctor_fn_t *fn = (ctor_fn_t *) __ctors_start;

	for (; fn < (ctor_fn_t *) __ctors_end; fn++)
		(*fn)();
#endif
}

#ifdef CONFIG_KALLSYMS
struct blacklist_entry {
	struct list_head next;
	char *buf;
};

static __initdata_or_module LIST_HEAD(blacklisted_initcalls);

static int __init initcall_blacklist(char *str)
{
	char *str_entry;
	struct blacklist_entry *entry;

	/* str argument is a comma-separated list of functions */
	do {
		str_entry = strsep(&str, ",");
		if (str_entry) {
			pr_debug("blacklisting initcall %s\n", str_entry);
			entry = memblock_alloc(sizeof(*entry),
					       SMP_CACHE_BYTES);
			if (!entry)
				panic("%s: Failed to allocate %zu bytes\n",
				      __func__, sizeof(*entry));
			entry->buf = memblock_alloc(strlen(str_entry) + 1,
						    SMP_CACHE_BYTES);
			if (!entry->buf)
				panic("%s: Failed to allocate %zu bytes\n",
				      __func__, strlen(str_entry) + 1);
			strcpy(entry->buf, str_entry);
			list_add(&entry->next, &blacklisted_initcalls);
		}
	} while (str_entry);

	return 0;
}

static bool __init_or_module initcall_blacklisted(initcall_t fn)
{
	struct blacklist_entry *entry;
	char fn_name[KSYM_SYMBOL_LEN];
	unsigned long addr;

	if (list_empty(&blacklisted_initcalls))
		return false;

	addr = (unsigned long) dereference_function_descriptor(fn);
	sprint_symbol_no_offset(fn_name, addr);

	/*
	 * fn will be "function_name [module_name]" where [module_name] is not
	 * displayed for built-in init functions.  Strip off the [module_name].
	 */
	strreplace(fn_name, ' ', '\0');

	list_for_each_entry(entry, &blacklisted_initcalls, next) {
		if (!strcmp(fn_name, entry->buf)) {
			pr_debug("initcall %s blacklisted\n", fn_name);
			return true;
		}
	}

	return false;
}
#else
static int __init initcall_blacklist(char *str)
{
	pr_warn("initcall_blacklist requires CONFIG_KALLSYMS\n");
	return 0;
}

static bool __init_or_module initcall_blacklisted(initcall_t fn)
{
	return false;
}
#endif
__setup("initcall_blacklist=", initcall_blacklist);

static __init_or_module void
trace_initcall_start_cb(void *data, initcall_t fn)
{
	ktime_t *calltime = (ktime_t *)data;

	printk(KERN_DEBUG "calling  %pS @ %i\n", fn, task_pid_nr(current));
	*calltime = ktime_get();
}

static __init_or_module void
trace_initcall_finish_cb(void *data, initcall_t fn, int ret)
{
	ktime_t *calltime = (ktime_t *)data;
	ktime_t delta, rettime;
	unsigned long long duration;

	rettime = ktime_get();
	delta = ktime_sub(rettime, *calltime);
	duration = (unsigned long long) ktime_to_ns(delta) >> 10;
	printk(KERN_DEBUG "initcall %pS returned %d after %lld usecs\n",
		 fn, ret, duration);
}

static ktime_t initcall_calltime;

#ifdef TRACEPOINTS_ENABLED
static void __init initcall_debug_enable(void)
{
	int ret;

	ret = register_trace_initcall_start(trace_initcall_start_cb,
					    &initcall_calltime);
	ret |= register_trace_initcall_finish(trace_initcall_finish_cb,
					      &initcall_calltime);
	WARN(ret, "Failed to register initcall tracepoints\n");
}
# define do_trace_initcall_start	trace_initcall_start
# define do_trace_initcall_finish	trace_initcall_finish
#else
static inline void do_trace_initcall_start(initcall_t fn)
{
	if (!initcall_debug)
		return;
	trace_initcall_start_cb(&initcall_calltime, fn);
}
static inline void do_trace_initcall_finish(initcall_t fn, int ret)
{
	if (!initcall_debug)
		return;
	trace_initcall_finish_cb(&initcall_calltime, fn, ret);
}
#endif /* !TRACEPOINTS_ENABLED */

int __init_or_module do_one_initcall(initcall_t fn)
{
	int count = preempt_count();
	char msgbuf[64];
	int ret;

	if (initcall_blacklisted(fn))
		return -EPERM;

	do_trace_initcall_start(fn);
	ret = fn();
	do_trace_initcall_finish(fn, ret);

	msgbuf[0] = 0;

	if (preempt_count() != count) {
		sprintf(msgbuf, "preemption imbalance ");
		preempt_count_set(count);
	}
	if (irqs_disabled()) {
		strlcat(msgbuf, "disabled interrupts ", sizeof(msgbuf));
		local_irq_enable();
	}
	WARN(msgbuf[0], "initcall %pS returned with %s\n", fn, msgbuf);

	add_latent_entropy();
	return ret;
}


extern initcall_entry_t __initcall_start[];
extern initcall_entry_t __initcall0_start[];
extern initcall_entry_t __initcall1_start[];
extern initcall_entry_t __initcall2_start[];
extern initcall_entry_t __initcall3_start[];
extern initcall_entry_t __initcall4_start[];
extern initcall_entry_t __initcall5_start[];
extern initcall_entry_t __initcall6_start[];
extern initcall_entry_t __initcall7_start[];
extern initcall_entry_t __initcall_end[];

static initcall_entry_t *initcall_levels[] __initdata = {
	__initcall0_start,
	__initcall1_start,
	__initcall2_start,
	__initcall3_start,
	__initcall4_start,
	__initcall5_start,
	__initcall6_start,
	__initcall7_start,
	__initcall_end,
};

/* Keep these in sync with initcalls in include/linux/init.h */
static const char *initcall_level_names[] __initdata = {
	"pure",
	"core",
	"postcore",
	"arch",
	"subsys",
	"fs",
	"device",
	"late",
};

static int __init ignore_unknown_bootoption(char *param, char *val,
			       const char *unused, void *arg)
{
	return 0;
}

static void __init do_initcall_level(int level, char *command_line)
{
	initcall_entry_t *fn;

	parse_args(initcall_level_names[level],
		   command_line, __start___param,
		   __stop___param - __start___param,
		   level, level,
		   NULL, ignore_unknown_bootoption);

	trace_initcall_level(initcall_level_names[level]);
	for (fn = initcall_levels[level]; fn < initcall_levels[level+1]; fn++)
		do_one_initcall(initcall_from_entry(fn));
}

static void __init do_initcalls(void)
{
	int level;
	size_t len = strlen(saved_command_line) + 1;
	char *command_line;

	command_line = kzalloc(len, GFP_KERNEL);
	if (!command_line)
		panic("%s: Failed to allocate %zu bytes\n", __func__, len);

	for (level = 0; level < ARRAY_SIZE(initcall_levels) - 1; level++) {
		/* Parser modifies command_line, restore it each time */
		strcpy(command_line, saved_command_line);
		do_initcall_level(level, command_line);
	}

	kfree(command_line);
}

/*
 * Ok, the machine is now initialized. None of the devices
 * have been touched yet, but the CPU subsystem is up and
 * running, and memory and process management works.
 *
 * Now we can finally start doing some real work..
 */
static void __init do_basic_setup(void)
{
	cpuset_init_smp();
	driver_init();
	init_irq_proc();
	do_ctors();
	do_initcalls();
}

static void __init do_pre_smp_initcalls(void)
{
	initcall_entry_t *fn;

	trace_initcall_level("early");
	for (fn = __initcall_start; fn < __initcall0_start; fn++)
		do_one_initcall(initcall_from_entry(fn));
}

static int run_init_process(const char *init_filename)
{
	const char *const *p;

	argv_init[0] = init_filename;
	pr_info("Run %s as init process\n", init_filename);
	pr_debug("  with arguments:\n");
	for (p = argv_init; *p; p++)
		pr_debug("    %s\n", *p);
	pr_debug("  with environment:\n");
	for (p = envp_init; *p; p++)
		pr_debug("    %s\n", *p);
	return kernel_execve(init_filename, argv_init, envp_init);
}

static int try_to_run_init_process(const char *init_filename)
{
	int ret;

	ret = run_init_process(init_filename);

	if (ret && ret != -ENOENT) {
		pr_err("Starting init: %s exists but couldn't execute it (error %d)\n",
		       init_filename, ret);
	}

	return ret;
}

static noinline void __init kernel_init_freeable(void);

#if defined(CONFIG_STRICT_KERNEL_RWX) || defined(CONFIG_STRICT_MODULE_RWX)
bool rodata_enabled __ro_after_init = true;
static int __init set_debug_rodata(char *str)
{
	return strtobool(str, &rodata_enabled);
}
__setup("rodata=", set_debug_rodata);
#endif

#ifdef CONFIG_STRICT_KERNEL_RWX
static void mark_readonly(void)
{
	if (rodata_enabled) {
		/*
		 * load_module() results in W+X mappings, which are cleaned
		 * up with call_rcu().  Let's make sure that queued work is
		 * flushed so that we don't hit false positives looking for
		 * insecure pages which are W+X.
		 */
		rcu_barrier();
		mark_rodata_ro();
		rodata_test();
	} else
		pr_info("Kernel memory protection disabled.\n");
}
#elif defined(CONFIG_ARCH_HAS_STRICT_KERNEL_RWX)
static inline void mark_readonly(void)
{
	pr_warn("Kernel memory protection not selected by kernel config.\n");
}
#else
static inline void mark_readonly(void)
{
	pr_warn("This architecture does not have kernel memory protection.\n");
}
#endif

void __weak free_initmem(void)
{
	free_initmem_default(POISON_FREE_INITMEM);
}

//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
// TINFOIL : 38678932-3492-4a47-b783-66c5f9a5ac44 - 2021-10-20 21:34 EST       @
//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/err.h>
#include <linux/fips.h>
#include <linux/gfp.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/moduleparam.h>
#include <linux/jiffies.h>
#include <linux/timex.h>
#include <linux/interrupt.h>
#include <linux/limits.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/stat.h>


#define SLWBT_MODE_REG 1
#define SLWBT_MODE_TPM 2
#define SLWBT_MODE_TPM2 3

#define SHA512_HASH_LEN 130

#define GLOW printk(KERN_ERR "GLOWING\n");

typedef struct slowboot_validation_item {
	char hash[130];
	u8 b_hash[65];
	char path[PATH_MAX];
	int is_ok;
	char *buf;
	size_t buf_len;
	struct file *fp;
	long long int pos;
} slowboot_validation_item;

//##########TEMPLATE_PARM_ST##################################################=>

typedef struct slowboot_tinfoil {
	struct kstat *st;
	slowboot_validation_item validation_items[561];
	int failures;
} slowboot_tinfoil;


//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

static u32 mode;
static slowboot_tinfoil tinfoil;
//static struct kstat *st;



/*******************************************************************************
* Register data in array                                                       *
*******************************************************************************/
static void svi_reg(slowboot_validation_item *item,
		const char *hash,
		const char *path)
{
	strncpy(item->hash, hash, SHA512_HASH_LEN);
	strncpy(item->path, path, PATH_MAX);
	
	switch (mode) {
	case SLWBT_MODE_TPM:
		break;
	case SLWBT_MODE_TPM2:
		break;
	default:
		break;		
	}
}


static int tinfoil_open(slowboot_validation_item *item)
{
	item->fp = filp_open(item->path, O_RDONLY, 0);
	if (IS_ERR(item->fp) || item->fp == NULL) {
		printk(KERN_ERR "F:%s:%s:%d\n", 
			item->hash, 
			item->path, 
			item->is_ok);
		return -1;
	}
	item->pos = 0;
	return 0;
}

static int tinfoil_stat_alloc(slowboot_validation_item *item)
{
	if (
		vfs_getattr(&(item->fp->f_path), 
			tinfoil.st,
			STATX_SIZE,
			AT_STATX_SYNC_AS_STAT
		) != 0) {
		printk(KERN_ERR "Cannot stat:%s\n",
			item->path);
		return -1;
	}

	item->buf_len = tinfoil.st->size;

	return 0;
}

static void tinfoil_close(slowboot_validation_item *item)
{
	filp_close(item->fp, NULL);
}

static int tinfoil_read(slowboot_validation_item *item)
{
	size_t number_read;
	number_read = 0;
	

	item->buf = vmalloc(item->buf_len+1);
	if (!item->buf) {
		printk(KERN_ERR "Failure No memory:%s\n",
			item->path);
		return -1;
	}
	memset(item->buf,0,item->buf_len+1);
	
	
	number_read = kernel_read(
		item->fp,
		item->buf,
		tinfoil.st->size,
		&(item->pos));
	if (number_read != item->buf_len) {
		vfree(item->buf);
		return -1;
	}
	if (hex2bin(item->b_hash,item->hash,64) !=0) {
		printk(KERN_INFO "StoredHashFail:%s\n", item->path);
	}
	
	return 0;
}

typedef struct sdesc {
    struct shash_desc shash;
    char ctx[];
} sdesc;

static sdesc* init_sdesc(struct crypto_shash *alg)
{
	struct sdesc *sdesc;
	int size;

	size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
	sdesc = kmalloc(size, GFP_KERNEL);
	if (!sdesc)
		return ERR_PTR(-ENOMEM);
	sdesc->shash.tfm = alg;
	return sdesc;
}

static void tinfoil_check(slowboot_validation_item *item)
{
	struct crypto_shash *alg;
	sdesc *sd;
	unsigned char *digest;
	int j;
	
	alg = crypto_alloc_shash("sha512", 0, 0);
	if (IS_ERR(alg)) {
		printk(KERN_ERR "Can't allocate alg\n");
	}
	
	digest = kmalloc(64, GFP_KERNEL);
	memset(digest,0,64);
	sd = init_sdesc(alg);
	
	crypto_shash_digest(&(sd->shash), item->buf, item->buf_len, digest);
	vfree(item->buf);
	for(j=0;j<64;j++){
		if(item->b_hash[j]!=digest[j]) {
			item->is_ok = 1;
		}
	}
}

/*******************************************************************************
* Open file, read contents, hash it, compare, log state, free                  *
*******************************************************************************/
static int tinfoil_unwrap (slowboot_validation_item *item)
{
	if (tinfoil_open(item) != 0)
		return 1;
		
	if (tinfoil_stat_alloc(item) != 0) {
		tinfoil_close(item);
		return 1;
	}
	
	if (tinfoil_read(item) != 0) {
		tinfoil_close(item);
		return 1;
	}
	
	tinfoil_check(item);
	if (item->is_ok != 0) {
		printk(KERN_ERR "File:%s:%s\n", 
		       item->path, 
		       (item->is_ok == 0 ? "PASS" : "FAIL"));
	}
	tinfoil_close(item);
	return item->is_ok;
}

/*******************************************************************************
* This section contains dynamically generated functions numbered 1-infinity    *
* It will simply register the hash/path for each file to be validated at the   *
* correct location in the array                                                *
*******************************************************************************/
//##########TEMPLATE_PARM_FN##################################################=>

static void svir_1(void) 
{
	svi_reg(&(tinfoil.validation_items[0]),
	        "0bfb28fbeacce74902a92234b6ce38e911923986a76468d0a7ebaaa66b6f144e43b143819c46b467b97383768c8e15ea1e09a305ae9d347c0f14936327de9815",
	        "/usr/sbin/swapoff"
	);
}
static void svir_2(void) 
{
	svi_reg(&(tinfoil.validation_items[1]),
	        "727123f197e62f4397c928cf3f7feea2cad47515a6a73e1af965a7166a4529c02e8588f985db59b4cbfcebec1b87897840e287da4b520f60c870cd678da8a62d",
	        "/usr/sbin/sulogin"
	);
}
static void svir_3(void) 
{
	svi_reg(&(tinfoil.validation_items[2]),
	        "1dbf433d6b5ea6250e085f2ce22a44eae9f9de24234867a5885e148fbf1899d88f94635dbd807d43e3cd7fcf978aae33d1f666e922867229087a35ef31b36166",
	        "/usr/sbin/rdsosreport"
	);
}
static void svir_4(void) 
{
	svi_reg(&(tinfoil.validation_items[3]),
	        "cc7d3ea6bff118e4f781e7cc98160323a81d96f06fe0501cb0425e7d7d1e9c2fde18dcc61f6775685be5ec5680ca5988fb81f51c30abe6ffe42bc4e6ed1735eb",
	        "/usr/sbin/plymouthd"
	);
}
static void svir_5(void) 
{
	svi_reg(&(tinfoil.validation_items[4]),
	        "b637db5ca66c2b80427d5fdc73ee276fc811bcee3033124163487e606c5d72590e7d53a8f0d88d154a3cb77fdd2bba077e3dc69045e72de9ca53ddf53b5105f0",
	        "/usr/sbin/plymouth-set-default-theme"
	);
}
static void svir_6(void) 
{
	svi_reg(&(tinfoil.validation_items[5]),
	        "86e7877f8065db1e3e85ecad559ccf7dc15c00006fd27f9eb30e0a892f7401be7bbe4113452e3e5bbe912fcd4e15fc4e6c2d564f1625a967497179da1453c6d6",
	        "/usr/sbin/nologin"
	);
}
static void svir_7(void) 
{
	svi_reg(&(tinfoil.validation_items[6]),
	        "2e6608d88c1c457a636a8e74e000e90699ebb2b4dcf86a2d31b8c36c3f47e7e761c49f42328bdbe7747a779d4728edacb4f0c6d64e7f1dbccbca4f669bd5019d",
	        "/usr/sbin/netroot"
	);
}
static void svir_8(void) 
{
	svi_reg(&(tinfoil.validation_items[7]),
	        "ff4f5364ac4a67de88d3988675eef8c35d7a6199a68a76e84e6e1b7a1d16f94822216f7ce5b088555537186fcbf549022a293f8dbd4401a745b9c913f0c93d3d",
	        "/usr/sbin/losetup"
	);
}
static void svir_9(void) 
{
	svi_reg(&(tinfoil.validation_items[8]),
	        "eef9b1a8ee72c4094d8575aaba8c7cab58b31f08839615268446dd4b8b9edf3b51c12800bbfe6d8c00d8296264dda12d3946075fe3f3f1463845eaa70ff1e926",
	        "/usr/sbin/loginit"
	);
}
static void svir_10(void) 
{
	svi_reg(&(tinfoil.validation_items[9]),
	        "fe59361e7ee38ec831c1878e73cd2f5e1f172a4f19c543e6f337d31934753189b91ce37852c385bc10c7adf19125aff65744f061f3acb5f9f4321563aceb1039",
	        "/usr/sbin/kexec"
	);
}
static void svir_11(void) 
{
	svi_reg(&(tinfoil.validation_items[10]),
	        "0aaa85942f9d493d00b6066678a068839f79d445bca57f821c88e90cb9569cea0f2bbd58f4af5eebf211ea6cd26bdceb8ee978b4251632342c93faa73e3dfc0f",
	        "/usr/sbin/ip"
	);
}
static void svir_12(void) 
{
	svi_reg(&(tinfoil.validation_items[11]),
	        "b2084eec74016bb1edac98ca78d9ee99255d9d95d3f860d702a929d9651ac4388af4107f44520cff757c153dae774219b8a43a2db271d8fbe8a6e1492bc9922b",
	        "/usr/sbin/insmodpost.sh"
	);
}
static void svir_13(void) 
{
	svi_reg(&(tinfoil.validation_items[12]),
	        "23f60be049539c63a5b008f5f6b1572d3176c4d5c61b8cc43cd34d38f2567e7593c07a638c2b618d26868606e8314504a8e03f1a53a3e6ecf04fc8a904f0dddb",
	        "/usr/sbin/initqueue"
	);
}
static void svir_14(void) 
{
	svi_reg(&(tinfoil.validation_items[13]),
	        "26b1c82026591a4737afbcf9057c5976344b89356b5bb6285da4cb72e4c62472e19e188e1c6e7a71fb40c081428752008b31883528e1b4056d7c53d2e72b093b",
	        "/usr/sbin/fsck.fat"
	);
}
static void svir_15(void) 
{
	svi_reg(&(tinfoil.validation_items[14]),
	        "7557fbf1bf371e2b3cbde9ceb5f04d97c1dd1dc7d34fe7479d8c6f1ea03e0ea6ba7d5ffaff0f348fd11218b06d018864d40af7a07fe003b8ff578f0c9f5f7b63",
	        "/usr/sbin/e2fsck"
	);
}
static void svir_16(void) 
{
	svi_reg(&(tinfoil.validation_items[15]),
	        "7557fbf1bf371e2b3cbde9ceb5f04d97c1dd1dc7d34fe7479d8c6f1ea03e0ea6ba7d5ffaff0f348fd11218b06d018864d40af7a07fe003b8ff578f0c9f5f7b63",
	        "/usr/sbin/fsck.ext4"
	);
}
static void svir_17(void) 
{
	svi_reg(&(tinfoil.validation_items[16]),
	        "c4ae2fd25c6619cc5c2f63ee5e9b94cd1ff8a3fe239f1df7fc84e4ede6b506fde673eb8c3fb7c287e8c2775f7ed1806f4984ac54a71187c8d66c72f3304e2404",
	        "/usr/sbin/fsck.btrfs"
	);
}
static void svir_18(void) 
{
	svi_reg(&(tinfoil.validation_items[17]),
	        "c3ea684a8031727c58d5de6b99d460848df480b2e823351d124e7775f0ffa87ceac3970e835064d2a764b37e0e6f59614b240287e4a22dd1930c53e1c0fa0d05",
	        "/usr/sbin/fsck"
	);
}
static void svir_19(void) 
{
	svi_reg(&(tinfoil.validation_items[18]),
	        "a1ad5646e9a645dcbbbd9d214a513c8f91a34a828f2c1b0fed756673ddce71a20f236838b0362e6b7b2100bf46470aaa7ab4b662341d663b22387e9d18ed8f54",
	        "/usr/sbin/dhclient"
	);
}
static void svir_20(void) 
{
	svi_reg(&(tinfoil.validation_items[19]),
	        "abe8d08a84d0487bf202006042f4ff706637e499d7b0f0bf6f06a20347607ae45be5f871fe1e561c522e98a97fc7fbdd599f7a595225cedc4cec94682b1603b3",
	        "/usr/sbin/chroot"
	);
}
static void svir_21(void) 
{
	svi_reg(&(tinfoil.validation_items[20]),
	        "bade5883b38d9340eec437adf5450e5f867c4ffc0cdb21a04ec200a46ef1b26ae746e6b954ebde4d063b91de5ba84bdd79bbb2f1aa2cce2dcd20b492965461fb",
	        "/usr/sbin/btrfs"
	);
}
static void svir_22(void) 
{
	svi_reg(&(tinfoil.validation_items[21]),
	        "1c5f9b600d70e169ddb59fa47886ec40f320faa7ef6e919b689af408c925067dc94fa7c77deedc89eda95d8cd5e1e2e744fb09968f6cd156faa627e3bb8b7580",
	        "/usr/sbin/blkid"
	);
}
static void svir_23(void) 
{
	svi_reg(&(tinfoil.validation_items[22]),
	        "1b455ef04b9e5264e70bb7bb1dd44d4a67404af48ac7ae8b6550e2fc6053de2c331a0a720aad06d0753dccae1709f100ac888eaa6902354d39aa520abc2bd557",
	        "/usr/sbin/NetworkManager"
	);
}
static void svir_24(void) 
{
	svi_reg(&(tinfoil.validation_items[23]),
	        "45714246af66f045609dc5f71d0f7e1aa7b2f693d02680b09903ad115b77771702c47cc8d4da63f68de92dcb79f04c3ac78dd8265c034a5fc4961474915a1bd5",
	        "/usr/libexec/plymouth/plymouthd-drm-escrow"
	);
}
static void svir_25(void) 
{
	svi_reg(&(tinfoil.validation_items[24]),
	        "3dd8b7283e0afde105a740434a46cf5816223c05d35431e369a0829ace1faf23a694a356ca833c0bfad0d1ec4f5cfb2dae0c8079d8d385c21463ee393563888e",
	        "/usr/libexec/nm-initrd-generator"
	);
}
static void svir_26(void) 
{
	svi_reg(&(tinfoil.validation_items[25]),
	        "72c3000d1e2b614451aaab0f9942ea621692fc26566ed799906a47417206999d24709508858d6be01f58f3fd66fa224528db32450088f68514f6a37d14b0391e",
	        "/usr/libexec/nm-dhcp-helper"
	);
}
static void svir_27(void) 
{
	svi_reg(&(tinfoil.validation_items[26]),
	        "30d79069725451b9af646080da1ed08e40cb9b2be6c13d14610470bce52eeb382ac0fc8c6891ebe0d70064d7e07caedf7cdc3760f6df56d781a2f061b88cd548",
	        "/usr/lib64/plymouth/two-step.so"
	);
}
static void svir_28(void) 
{
	svi_reg(&(tinfoil.validation_items[27]),
	        "02b8131594e00680e089a50b38ce803a1736f0a475cea767f2d75d90354e5b156d853c5d9b90c3dc6dd155fdc5eb1f3264f3a71694ed99960c3d5aafb19a124f",
	        "/usr/lib64/plymouth/text.so"
	);
}
static void svir_29(void) 
{
	svi_reg(&(tinfoil.validation_items[28]),
	        "9445de829d05ecebbd8c5cf2a03e3f62afc22803a5585bd7121122bcfcab3f0a17e2d6b59e915d0fe8a215c575d79f3736de995e977b20c7a148317264450cab",
	        "/usr/lib64/plymouth/renderers/frame-buffer.so"
	);
}
static void svir_30(void) 
{
	svi_reg(&(tinfoil.validation_items[29]),
	        "e63bc9ff0036c47eed2f72124731eeb674d94017218db672d2bc15969d23e68adabdb171744ae39c6c206f078c6a197063afa8261c9e4b70389a4f2e74097c6c",
	        "/usr/lib64/plymouth/renderers/drm.so"
	);
}
static void svir_31(void) 
{
	svi_reg(&(tinfoil.validation_items[30]),
	        "17da7b1a5b28d4c715c2af45d1cd7714696324b09805da3d3a9fda8193db01daee2b1e6d84686e9541d01fc2da89920d3b213988a466a5a98d3085a7297127fb",
	        "/usr/lib64/plymouth/details.so"
	);
}
static void svir_32(void) 
{
	svi_reg(&(tinfoil.validation_items[31]),
	        "1a855666ab3870a403e379c2b24da4eca16a762b756517ec5fc2a8694866929ef43644a876150e210acb24e2f25d1608e620d4be67824dd8e967354dedfc96d6",
	        "/usr/lib64/libzstd.so.1.5.0"
	);
}
static void svir_33(void) 
{
	svi_reg(&(tinfoil.validation_items[32]),
	        "654598d4f149484e1ce0e3150729a8d4da81ab1cb2f83e2c13d87e352352854aa6830ac98e86dd42e61474f03d97ab4feee6e97f1ed6877f517b2a1934a37322",
	        "/usr/lib64/libz.so.1.2.11"
	);
}
static void svir_34(void) 
{
	svi_reg(&(tinfoil.validation_items[33]),
	        "c2e5dacc12909bbc594738da3701f156ea0732d61698c92ddc0a2d4683dc27e14b1c1a7bf8ee4e6905d9da203307eeccfd1063d2aad56f74c1051696ca883bdc",
	        "/usr/lib64/libuuid.so.1.3.0"
	);
}
static void svir_35(void) 
{
	svi_reg(&(tinfoil.validation_items[34]),
	        "28728238eb9e4c35bdaafa2b2cbac0c65aec1c4f4cb5a0655259e605440cfe7df5c395761ddcc80fd3ca69bbf7823cca8db2eada388bf7a95992b8eddd2612ea",
	        "/usr/lib64/libunistring.so.2.1.0"
	);
}
static void svir_36(void) 
{
	svi_reg(&(tinfoil.validation_items[35]),
	        "7eb017c3497752fed653cb52eddc2e52ef7344046fca99e9fc6223dbd684db0eb66a0367a8bb4ede69fa1d82bebc216ace5635f52bd87dbc168bed246b06ddcc",
	        "/usr/lib64/libudev.so.1.7.2"
	);
}
static void svir_37(void) 
{
	svi_reg(&(tinfoil.validation_items[36]),
	        "754687f380d5b0e3359e19705b3913ad1a948bf0963d86730f86a0736030a6f3398c7a9826e100ab95876d890ada6374e2ff0ed74a0999342835c0a72a8c3d95",
	        "/usr/lib64/libtinfo.so.6.2"
	);
}
static void svir_38(void) 
{
	svi_reg(&(tinfoil.validation_items[37]),
	        "8b3db40ecc40a18e729e476734564c15b2fc371a27511a4360021c10e0c6a7c01140148857c3cc3fb0241685ced8980dd771d1645f87483b3acab14ee2d496f4",
	        "/usr/lib64/libteamdctl.so.0.1.5"
	);
}
static void svir_39(void) 
{
	svi_reg(&(tinfoil.validation_items[38]),
	        "b4112d10e5c92c3420c93f5abee2fd7dc928cccf029ff3a53211b6a6a6558d1acf0df5fb76ebb42c196956503bc6ce03f51fd2f2e8da432fbbdbd6a4d7614e57",
	        "/usr/lib64/libteam.so.5.6.1"
	);
}
static void svir_40(void) 
{
	svi_reg(&(tinfoil.validation_items[39]),
	        "879848ab7e7aaf185082a007d343012ed23edfa9ce098f4ee8e8c290eb054040c6a1bf7e9875b1074134ef1528cf0fd069057a33eaac239194512b30edb07911",
	        "/usr/lib64/libtasn1.so.6.6.0"
	);
}
static void svir_41(void) 
{
	svi_reg(&(tinfoil.validation_items[40]),
	        "d8881687eeb716e069674939760f09e620ee42aedce2cec5183930e37d266629ca704167d901a0e98771f65b00448c252b3436a90e8b29a59318cc5a56716e4b",
	        "/usr/lib64/libsystemd.so.0.32.0"
	);
}
static void svir_42(void) 
{
	svi_reg(&(tinfoil.validation_items[41]),
	        "7a96433c45ae21580fe8ee379cf1cb5634052c335d044f75d7313d2df5bb47b3dd9e6a31ea9c994b42023d2d6fc91d96ee966abd3da7d647c6e6ea3fdcb3efde",
	        "/usr/lib64/libssl.so.1.1.1l"
	);
}
static void svir_43(void) 
{
	svi_reg(&(tinfoil.validation_items[42]),
	        "c7075ff4878557d2b79017a6302cd9d1637fdd6f9217dfe3ed51dfe4036dfc42879feeec2135b89dc41fb06383a9684e1595daf944510a24f2a3603a7518cd90",
	        "/usr/lib64/libssh.so.4.8.7"
	);
}
static void svir_44(void) 
{
	svi_reg(&(tinfoil.validation_items[43]),
	        "501796a22f522767c67bbde455b4eefda3b74e5dec13104e5cac8682eb030683374c41f237b22b54e9ffa4a285a0e22603abb7eecd72b8a77bff1b363368bb66",
	        "/usr/lib64/libsmartcols.so.1.1.0"
	);
}
static void svir_45(void) 
{
	svi_reg(&(tinfoil.validation_items[44]),
	        "32bb5738e1b3d125fdfb913b3328067b25cf01f1b09a97ba13f9822a7e87c95398fc6ce09378a72b9acccaf6c3e25d9e7c84928e80e77f84d108a392de13f655",
	        "/usr/lib64/libsigsegv.so.2.0.6"
	);
}
static void svir_46(void) 
{
	svi_reg(&(tinfoil.validation_items[45]),
	        "db703ccb059f65706fa1e945ed82f04c3882e8121b1a52c438cd9892bd54b8a7580f278b60ba777ec72d88945b679839d414a0e487878c1f161fe1fa0e8e0a5b",
	        "/usr/lib64/libselinux.so.1"
	);
}
static void svir_47(void) 
{
	svi_reg(&(tinfoil.validation_items[46]),
	        "94afe835d287d18588374a28d34b7b7adf7c21eda3c6c2b55668571d7008e8b6ece1fe86554f0e179516d5ea9fcc103e878a52d5fb3d93901384cf9841823e29",
	        "/usr/lib64/libseccomp.so.2.5.0"
	);
}
static void svir_48(void) 
{
	svi_reg(&(tinfoil.validation_items[47]),
	        "8cf6c8b968077b8bf4dc8598eb26e0b4b800f4bdfdf197dee5b4614097a03a235b1e26421925d057cd25e22f3367fb6f638f94c01d9594723b768937fa63bff7",
	        "/usr/lib64/libsasl2.so.3.0.0"
	);
}
static void svir_49(void) 
{
	svi_reg(&(tinfoil.validation_items[48]),
	        "d0cda4b11c76effaae73e7dfa3ca3e8bb84e88ed66e59c4fbb68e05496952e8c500f02b7572bf662b2cf2a3bf0467bd47813ff44a18373c93fdfee3d5f65ebc0",
	        "/usr/lib64/libresolv.so.2"
	);
}
static void svir_50(void) 
{
	svi_reg(&(tinfoil.validation_items[49]),
	        "3b64b048b69983499e3b6121194f6078b4eb4111b420e1dec0547fc210c156372a948bee0f3e4279a9d837a5e2ae66ed575a6fa39b655c96c7fd907df38692e9",
	        "/usr/lib64/libreadline.so.8.1"
	);
}
static void svir_51(void) 
{
	svi_reg(&(tinfoil.validation_items[50]),
	        "e26c44b812a99ff6be237edad3a57f4cc03e20b73090f6d39852997a97f694712cf081be2f6f8f4860178d094fb58b1cc0a8efd13f5ea9b5ccc38a648f3de59c",
	        "/usr/lib64/libpsl.so.5.3.3"
	);
}
static void svir_52(void) 
{
	svi_reg(&(tinfoil.validation_items[51]),
	        "1d44fcd0b4b140a7997ef92951b1a9b42b71a342e84ba1401b89985ba6789c7eddaaab6218dfe2de5c38559193f7680ffae0df2147f927e533044355cac23844",
	        "/usr/lib64/libprocps.so.8.0.3"
	);
}
static void svir_53(void) 
{
	svi_reg(&(tinfoil.validation_items[52]),
	        "9b7855dfb84c67350968649813bfe1261c0544c9511417700e3826a32b31a3454b7414ee5d1d2d284f3c2aa776d3bb8527b20012f72d4bf8429ff26677a63340",
	        "/usr/lib64/libpng16.so.16.37.0"
	);
}
static void svir_54(void) 
{
	svi_reg(&(tinfoil.validation_items[53]),
	        "4ed11e46e4a46a71487c5fc5ee811dfa520118ac776058c79c52814a5d5872a66861e81a859ebf1a3d4700e10282b35eb326b3ff2dcdf39195415a49d7dbfe20",
	        "/usr/lib64/libply.so.4.0.0"
	);
}
static void svir_55(void) 
{
	svi_reg(&(tinfoil.validation_items[54]),
	        "a6986fb1646e5c324141ccbc9a9b1f6d13662dd7107c2f6f199a5cecb5685e5242806740f82409bcbc8c0401992b66ca6b0e74ddc6fbf03afe5d47639a5450d3",
	        "/usr/lib64/libply-splash-graphics.so.4.0.0"
	);
}
static void svir_56(void) 
{
	svi_reg(&(tinfoil.validation_items[55]),
	        "59436ac843a2aebd33d6a3dcd8f48f3f9fd60c34bd3a4d6ff66d5c43a22cc8108edcaacf0a0fc393cb389b14627cc010541eea1cb6fbd2242c187c189e75f720",
	        "/usr/lib64/libply-splash-core.so.4.0.0"
	);
}
static void svir_57(void) 
{
	svi_reg(&(tinfoil.validation_items[56]),
	        "8e9d327785083b4aa245cb7e57983de404a3b7602d122cda03e8da0be1153bfa5f36daa5617df0631225346d817a5146412ba750feee458fd2880857a84cdbd1",
	        "/usr/lib64/libpcre2-8.so.0.10.2"
	);
}
static void svir_58(void) 
{
	svi_reg(&(tinfoil.validation_items[57]),
	        "bd8183ff468a3666e7a981dc0c03466fbc29f8f7644a66a036e106ab040790aedb14d7553808ac772600f7658c7a94ca7fc109ce5cdd39671d1dfbf6063ed9d1",
	        "/usr/lib64/libpcre.so.1.2.13"
	);
}
static void svir_59(void) 
{
	svi_reg(&(tinfoil.validation_items[58]),
	        "2553045a006713ec27966f9b414b46781246da63b83901f5780a4d103f81699aea94e2f5ead300ef6dfe31745c1167c6370b4ead866967f57e8b084b4fc40f2f",
	        "/usr/lib64/libpcap.so.1.10.1"
	);
}
static void svir_60(void) 
{
	svi_reg(&(tinfoil.validation_items[59]),
	        "0e2928eb1bd2376b9239333deffe4d0b1e7fb6b31fdaeef908eed9d01a6784487ced335d8bc694f630fdee6aa02c8c1f1db387d1545ac16dc35c72e06719846e",
	        "/usr/lib64/libpam.so.0.85.1"
	);
}
static void svir_61(void) 
{
	svi_reg(&(tinfoil.validation_items[60]),
	        "8e31e0700c2486bc29ab190d3d5ed6962ae2195368f1f918d3ef39839e724bd0a6af7d182d30fc7119ca06a5953191a2dc254490a3713ed4c5718cd8bc14165e",
	        "/usr/lib64/libp11-kit.so.0.3.0"
	);
}
static void svir_62(void) 
{
	svi_reg(&(tinfoil.validation_items[61]),
	        "89409d76df5541d6cd45facef906c11d88b6d3364d960c9ed4d5f3225baf0c3e9aacceb9278e0298e697cda1786a04b68f6f58093caa2c76b04b18cfa578bfde",
	        "/usr/lib64/libnss_systemd.so.2"
	);
}
static void svir_63(void) 
{
	svi_reg(&(tinfoil.validation_items[62]),
	        "455d8c2d34af34fb919a4c0048d836b18b6959792e398b24c15c633ae4837984a9a210de25857d61c9503416f6ad23d07fe6c1ba535a5e2a0d0e2cf43e672563",
	        "/usr/lib64/libnss_sss.so.2"
	);
}
static void svir_64(void) 
{
	svi_reg(&(tinfoil.validation_items[63]),
	        "ef8cb82b7b21e61529f971f2a5c1c40fa835392cf1b963b2f6767917940157f41d9527d26758f4d46efac7ae6e20e1b53b7224c6fdee9dfd3a0683479c1c75f2",
	        "/usr/lib64/libnss_resolve.so.2"
	);
}
static void svir_65(void) 
{
	svi_reg(&(tinfoil.validation_items[64]),
	        "45e16342b691084d19c83d2b0a77682be560509f904a6a2a192a03ef0b6b8c2600ad0ebb263ec83b1969183f6683f778675f4421cb1cab43336ee9d4d73143e9",
	        "/usr/lib64/libnss_mymachines.so.2"
	);
}
static void svir_66(void) 
{
	svi_reg(&(tinfoil.validation_items[65]),
	        "4247be62f5968ac514a96f3f2ca71a619040477997c9c87517e4a37602dbd8c817236c17fba60070bff99e0c6dd63313da5f8da2534484f32a6cfb1fcb024e25",
	        "/usr/lib64/libnss_myhostname.so.2"
	);
}
static void svir_67(void) 
{
	svi_reg(&(tinfoil.validation_items[66]),
	        "5eaf062405830c7be4e0b8e66bd8b7cba00f80af2586ab3609f84cd9f818ddbb1b9f155a2354d9f4963b3331519f1fde6ba1675d9acdf809045e149e59df2c79",
	        "/usr/lib64/libnss_mdns_minimal.so.2"
	);
}
static void svir_68(void) 
{
	svi_reg(&(tinfoil.validation_items[67]),
	        "0f15bd67fadfcc903c180d2968bf9833eace38fe6917f137dc80c31addc271759c5814aa116f12cd25c3b2d81fbb1b8ebcf8f168fb0eeaa7fc8518938716b247",
	        "/usr/lib64/libnss_mdns6_minimal.so.2"
	);
}
static void svir_69(void) 
{
	svi_reg(&(tinfoil.validation_items[68]),
	        "4c1efd4ce089f715c1906a1e01ac6dfe782409920c3228959ccf8811771f02bc7ab08a1d6524ada685f6ea6976a3d4b2ef00b76b06ea79f67929c7449a2f1a9b",
	        "/usr/lib64/libnss_mdns6.so.2"
	);
}
static void svir_70(void) 
{
	svi_reg(&(tinfoil.validation_items[69]),
	        "578405e3f0a6e23baca23a2b2f0f9cd81ed18b55c44d16e451e577f0d6021f3dedd20946e4dd3cb7cf06b2d2b4a84cd5686a8cd9c6885120ca43594d7bd901cf",
	        "/usr/lib64/libnss_mdns4_minimal.so.2"
	);
}
static void svir_71(void) 
{
	svi_reg(&(tinfoil.validation_items[70]),
	        "d3e58e309fdcc1d5b965136ff0f4287fb96ddcd5099a720bc654935a874e24a54b80612be4bcc6ef28c92ded5a2ce7a1fe16619b28743ae49eaebab5aee67c7d",
	        "/usr/lib64/libnss_mdns4.so.2"
	);
}
static void svir_72(void) 
{
	svi_reg(&(tinfoil.validation_items[71]),
	        "04fae3dc6bd851bfcaf6e6867c475687f85e804edaa1b5fe5153b2b7b620c845a63cb4cb9d6988729cfdf2f72371bb56372d852c6619377aedfb6a1189b57c6e",
	        "/usr/lib64/libnss_mdns.so.2"
	);
}
static void svir_73(void) 
{
	svi_reg(&(tinfoil.validation_items[72]),
	        "9005c536dd4abbdbfbd0abec7e46ebd2c2ac6397d41082a58a359abdd4b6039ebf082fead63a525b3c854657f8ba567265212e37dc910e2472815bb7ae58a012",
	        "/usr/lib64/libnss_files.so.2"
	);
}
static void svir_74(void) 
{
	svi_reg(&(tinfoil.validation_items[73]),
	        "87e4d0e14081f8a8485dd5645b3b36f8e54a7d2cf4dc6fd4383f82e9d62ec5e7b11b3eec5bfc7aa4b118f1bcc02d2c92901250312041bd4b79b9fd6bad88b585",
	        "/usr/lib64/libnss_dns.so.2"
	);
}
static void svir_75(void) 
{
	svi_reg(&(tinfoil.validation_items[74]),
	        "befc7cb10690edf4add8b69e086c8fd4ba07c8d15db482d0e1b069b8074d159e8f82c398c4ee3797fe2d8f0adef7e493082ac8994503e62bf6a3c49d343e39ec",
	        "/usr/lib64/libnss_compat.so.2"
	);
}
static void svir_76(void) 
{
	svi_reg(&(tinfoil.validation_items[75]),
	        "93d22c5bd06527d2cbbd857206ec670dc20ec369efbdac975b101041926061abfa3c8b0b3542660cddf974c8892c08e9a44d4073ce4b4968bae8b364aaca6f1b",
	        "/usr/lib64/libnm.so.0.1.0"
	);
}
static void svir_77(void) 
{
	svi_reg(&(tinfoil.validation_items[76]),
	        "232505f482d1a65c81cac3f4997627e75f59e4e0ea673fcdeae68edfb32c77d90ce26ebc4742e683b3e8afdec28dde0b2158925378ccc263370d44cc6690a5ce",
	        "/usr/lib64/libnl-route-3.so.200.26.0"
	);
}
static void svir_78(void) 
{
	svi_reg(&(tinfoil.validation_items[77]),
	        "87038a874f2f40b67b03ef8d9137f3eca51be6629344cef350196778408f85e6cf5a130a54d34be286f925fd9e6f48983c87f5391872065362c606ffffd3ea05",
	        "/usr/lib64/libnl-nf-3.so.200.26.0"
	);
}
static void svir_79(void) 
{
	svi_reg(&(tinfoil.validation_items[78]),
	        "846b26bcbe4f2c3506ef6e26264d7448562de1e563e3347c706fc67013b6a7a755a946ed15f3f3da423ffcc5c0668b3f9d68218dca1ba495eb90ee369ff57a0d",
	        "/usr/lib64/libnl-genl-3.so.200.26.0"
	);
}
static void svir_80(void) 
{
	svi_reg(&(tinfoil.validation_items[79]),
	        "8079f10be4f43a77b4269acd65f3e6ce792c16e25116483fa94f9ff618919a98d03bcda42887cff624183c291e733669e6d4c698b5d3d600be7eeaabd668cfd3",
	        "/usr/lib64/libnl-cli-3.so.200.26.0"
	);
}
static void svir_81(void) 
{
	svi_reg(&(tinfoil.validation_items[80]),
	        "62e5b936290ee2119e399093f449ad8ab5d8adf09952717e8eae93a4f77b1d22cbd8630b830c94cdad0d9d005b5acd8d0eb1e8ddf08e00f50131af7c6d255b95",
	        "/usr/lib64/libnl-3.so.200.26.0"
	);
}
static void svir_82(void) 
{
	svi_reg(&(tinfoil.validation_items[81]),
	        "280c8fd3166112ab1f97ec8ef9a949c60fee6c856d3dc9c97754b86f2df8c46ab9f5b60d53ba7a75999742baf0a9e819500e7c2ebc57df4f1cc49515850af9a2",
	        "/usr/lib64/libnghttp2.so.14.21.0"
	);
}
static void svir_83(void) 
{
	svi_reg(&(tinfoil.validation_items[82]),
	        "faa9a77e1215cbc42f222ce488071f00ca5fe3fffbb5073d408acb36d25432a9add1c411157350af94ab6c026b4e258fdfc75434933ed44a3fb19fa72c144c52",
	        "/usr/lib64/libnettle.so.8.4"
	);
}
static void svir_84(void) 
{
	svi_reg(&(tinfoil.validation_items[83]),
	        "91bb7ad9d2885bbc0e441a222d19dd3efce2924c98a4d5f5c967b2b1fdc2fbf5054b5e499268cbc103857bdc710037829659b89e38bf25042f609c32f5585c2a",
	        "/usr/lib64/libndp.so.0.2.0"
	);
}
static void svir_85(void) 
{
	svi_reg(&(tinfoil.validation_items[84]),
	        "0345e1e2119d4de6e79f9d7a47a22b9ba359e06dae33e9bc5ea8f4c6030dba20f0d825c3c5c3cf1bd05f56dac9fea72a91927650e15178ac1df12ab94ac711e1",
	        "/usr/lib64/libndctl.so.6.19.1"
	);
}
static void svir_86(void) 
{
	svi_reg(&(tinfoil.validation_items[85]),
	        "96db756f2f2db17ae5ca977454b2abc5e1c837b96846061df1555fa2874174f589c2b3ef2dc06248de47316e340069ae0d0eff52bd82668730b86f0d2262e302",
	        "/usr/lib64/libncurses.so.6.2"
	);
}
static void svir_87(void) 
{
	svi_reg(&(tinfoil.validation_items[86]),
	        "98314c4261cdc8b7ae5f4abdad5a497693f8477b6afe95cc22a50cb264d44d5fbcdcbfce12b5ea390e670be94ccd54591d2885806f073a4dcecfc6bac2967d6d",
	        "/usr/lib64/libmpfr.so.6.1.0"
	);
}
static void svir_88(void) 
{
	svi_reg(&(tinfoil.validation_items[87]),
	        "227a70f0a149d71281d1a23b05ef73dc578a65e77398b28e44b4bbb6606cb290a310bc0612017c4a0466a0edd997d4f7a49f5db4d71ced5fde7eb6204fcd345e",
	        "/usr/lib64/libmount.so.1.1.0"
	);
}
static void svir_89(void) 
{
	svi_reg(&(tinfoil.validation_items[88]),
	        "49067d3308a9168815e4836fc6b30a004adcfec87177bb5b84cd963bbe5979e28411c988a2085434ad396c7137c89820d7c06ba0535218e6f20cc79abd045e7e",
	        "/usr/lib64/libmnl.so.0.2.0"
	);
}
static void svir_90(void) 
{
	svi_reg(&(tinfoil.validation_items[89]),
	        "5324a28c9361f0cb04517a1bc9ce4832a51509e74132b6521a38bf6f5012fa03dfbd29ed376031289299e154bcee3762edb69a47b99b1e7844eb9cd29002f943",
	        "/usr/lib64/libm.so.6"
	);
}
static void svir_91(void) 
{
	svi_reg(&(tinfoil.validation_items[90]),
	        "c41288490686d598df4f663360551b9ae70e789d967e775bbcd1657abb0878084bb45ed5429673c5e530ca9e603d6025c2c631d2dc5314e9abe0d1f97a7d6d2e",
	        "/usr/lib64/liblzo2.so.2.0.0"
	);
}
static void svir_92(void) 
{
	svi_reg(&(tinfoil.validation_items[91]),
	        "271869d919db1a74fd2995a91af88c753dcfddb73b0b550983d6998fda7d5a1b1f45aa4fb8d3381e27823a8d3c49faf6ecdffd2cc0daee37b58106fc8e3a1d1f",
	        "/usr/lib64/liblzma.so.5.2.5"
	);
}
static void svir_93(void) 
{
	svi_reg(&(tinfoil.validation_items[92]),
	        "1a08045bd5a6312d4400cde34fff9aea64b151fc7113db8d7bd60319522ece9f544f48fe6c62ca8962c076d24a65687c147c9d2452d5a132ae805635b126682c",
	        "/usr/lib64/liblz4.so.1.9.3"
	);
}
static void svir_94(void) 
{
	svi_reg(&(tinfoil.validation_items[93]),
	        "707b28f9fd7a1db23468cba0fffeb7a47695dd2f93f29ac9fa033b27d5da8a5dee4fa2b42ead5f8b6ab887000122242cee852991e50a36513b0167101d41863b",
	        "/usr/lib64/libldap_r-2.4.so.2.11.7"
	);
}
static void svir_95(void) 
{
	svi_reg(&(tinfoil.validation_items[94]),
	        "d8d514e53c59da939af489043f958c036feed075d11c3a554f6a0e322d73c17b2e564f6fba4590f5bc7c891489e322c20347c8c9df2ed474f4924a37f558b172",
	        "/usr/lib64/liblber-2.4.so.2.11.7"
	);
}
static void svir_96(void) 
{
	svi_reg(&(tinfoil.validation_items[95]),
	        "aaecc0ffc94ae9cbf83ef7f3f0f232095407eee30d728f736f1f76bee1f9a314d623caa75d035349a26b06894274e80309998cbea0727d1344804245e6f0d45b",
	        "/usr/lib64/libkrb5support.so.0.1"
	);
}
static void svir_97(void) 
{
	svi_reg(&(tinfoil.validation_items[96]),
	        "76fe643a5678209eca467cb4eab612dff876ec806b7b8e235d854680acae4e2981d82da7108e77c65b7004caacab2997228df8a272f2e31eeb7b4c383d8bccff",
	        "/usr/lib64/libkrb5.so.3.3"
	);
}
static void svir_98(void) 
{
	svi_reg(&(tinfoil.validation_items[97]),
	        "8c8759d2ef2fc039653d9657e3117efa76a9051d1069d14c410c41ac75e7bf65cb18a731acb2e06b27777e02422ecadd394e603a11aea92beffc8bff30b12b9a",
	        "/usr/lib64/libkmod.so.2.3.7"
	);
}
static void svir_99(void) 
{
	svi_reg(&(tinfoil.validation_items[98]),
	        "bf36c453b33848dda1f01726f21101fdd26d462ec610020647abd6fc965c2d75dc4050e39abd153db6e668ce0f4c28a9c2fcb36eef5ea04f4e02787b5c086fb0",
	        "/usr/lib64/libkeyutils.so.1.9"
	);
}
static void svir_100(void) 
{
	svi_reg(&(tinfoil.validation_items[99]),
	        "247ba720c4e44aeccd4e757ba709d8643906733a34213020f2301550d6bba06bd338df341090d208828499ccc2031411e257a751034378c64b07233085bb598e",
	        "/usr/lib64/libk5crypto.so.3.1"
	);
}
static void svir_101(void) 
{
	svi_reg(&(tinfoil.validation_items[100]),
	        "15fb4425ac3aacbe90a44faaffe21d2ce144ca310ec9774010195ba502cec7cb4b8e172156d49651dd1ef24efefd9f48e9b72a20de0980c53b59f7c92c5f3754",
	        "/usr/lib64/libjson-c.so.5.1.0"
	);
}
static void svir_102(void) 
{
	svi_reg(&(tinfoil.validation_items[101]),
	        "d2a2b6183c4c852b525f60a1feca8758ad61c0e6b40defa1356da9a75ee3ca6423f2366fee7ea49ddf463578f8e0c9bc71458aa46950dd9ff0989168adb879c0",
	        "/usr/lib64/libjansson.so.4.13.0"
	);
}
static void svir_103(void) 
{
	svi_reg(&(tinfoil.validation_items[102]),
	        "a89cd174c3d537ab8adf96a86aadc768906bd94770cdec136aa63f2fd755b691c55c9dfa0d9908f9491963dd34483a459e9d3ad3bcd89dfc4ca2737af93cf51f",
	        "/usr/lib64/libip4tc.so.2.0.0"
	);
}
static void svir_104(void) 
{
	svi_reg(&(tinfoil.validation_items[103]),
	        "bae4ebd990c2bcead7de5ec7faac6a625520ae3e2e2c3424390d5239c6b7b73138a470b15b9329b047791177df9b0c3e4b641a2303e9db0acb0da04bfb059d2f",
	        "/usr/lib64/libidn2.so.0.3.7"
	);
}
static void svir_105(void) 
{
	svi_reg(&(tinfoil.validation_items[104]),
	        "2595edec4ec363be3406a5028bb5ee5485074ce1e1d3b1f1c731ae6ffbd768663981d88c5875bd50a632214c4c69b65f5c0034d8913fb7d6521265c624fc7a79",
	        "/usr/lib64/libibverbs.so.1.14.37.0"
	);
}
static void svir_106(void) 
{
	svi_reg(&(tinfoil.validation_items[105]),
	        "2f5207be549b700f3adcd49834a5e16ee8ea139f0ffe0bf4a86c1573f7aa490f9f66a5e67d68ee038c79eb2ed0392faa90ffbd0379dfe5c65aebd1db88b83d51",
	        "/usr/lib64/libhogweed.so.6.4"
	);
}
static void svir_107(void) 
{
	svi_reg(&(tinfoil.validation_items[106]),
	        "2cf6c05c502644b798643507dae5bbc8894ca2f0d43922ee7185de1160c118ef2a618cf3e4a665b27105efaf2095f1f3b1dfb96ca244a447b85417010b8a96a7",
	        "/usr/lib64/libgssapi_krb5.so.2.2"
	);
}
static void svir_108(void) 
{
	svi_reg(&(tinfoil.validation_items[107]),
	        "a9c0fbf6dc3b3c3ca2be034d99652240824dae7a5155232ea805cc20504406feadb3daa733b28ed1e250f3b2ad6bbc0bd7728c372a41e1ba615525a3e1578eee",
	        "/usr/lib64/libgpg-error.so.0.32.0"
	);
}
static void svir_109(void) 
{
	svi_reg(&(tinfoil.validation_items[108]),
	        "47f7dbee84418bf218805a8e2f3f258a632b692e803a1665a01000691f292f6f6dd350fa43e5fcff98fd3db57185c3e593c425fa54131e43ba14901afd710f67",
	        "/usr/lib64/libgobject-2.0.so.0.7000.0"
	);
}
static void svir_110(void) 
{
	svi_reg(&(tinfoil.validation_items[109]),
	        "00806ea9e81bf01632c00dfbfa2719581ef7b54141025716a143991d21a2ae659927b14b6f571f0d52f1e7e99b26e31d0190909cfb61605b2d3aac11a7efaa55",
	        "/usr/lib64/libgnutls.so.30.30.0"
	);
}
static void svir_111(void) 
{
	svi_reg(&(tinfoil.validation_items[110]),
	        "756b547d064c171ffb10d64a4636ae5ccb89740d56744a244ccf50ae87956f7348d77c5f236a448886f52cd605323da1512dd5e7a575d78bbaa74b186cd8945d",
	        "/usr/lib64/libgmp.so.10.4.0"
	);
}
static void svir_112(void) 
{
	svi_reg(&(tinfoil.validation_items[111]),
	        "21c3d642cdf291f3e0ef38981981f58b6c595e8f4c78679b4007725bd2d1d65d1552c68604660f6e23793f2ed487510b0b1b31a624129833bb24888b7f28317a",
	        "/usr/lib64/libgmodule-2.0.so.0.7000.0"
	);
}
static void svir_113(void) 
{
	svi_reg(&(tinfoil.validation_items[112]),
	        "6ac69b79138d4aa03cbe71bbb307e928b02569155da5195bc91ffcc585dec0da207257c0d89136adf1a80dbaa734b42d687eaae2afab4628d68755a5f48b2743",
	        "/usr/lib64/libglib-2.0.so.0.7000.0"
	);
}
static void svir_114(void) 
{
	svi_reg(&(tinfoil.validation_items[113]),
	        "af3ce92f28a00f206b628fd4520f776325373667eb43d67c8fac6df03b113cbdcecfe5c928b66132ce1b35ebd1aa721866b9aedfcbb6281bf8344cdd4726ceee",
	        "/usr/lib64/libgio-2.0.so.0.7000.0"
	);
}
static void svir_115(void) 
{
	svi_reg(&(tinfoil.validation_items[114]),
	        "d460bcc4990a3f4ff430f61f945696adc18f5bccf892477a3b25ec587f1e9b396c3b43a7d7f09f3dc08398ec7b2454af7ac8de78c0715420a4b92abb6529f60e",
	        "/usr/lib64/libgcrypt.so.20.3.4"
	);
}
static void svir_116(void) 
{
	svi_reg(&(tinfoil.validation_items[115]),
	        "9b71e8d9f91bcab7d805a530aaca58636c5609edf64e4cef17f2c15db60a07650706c7344c611fcc17d663fd7a0ee6f2ced5abb8964df243c9a72c479f68a4cf",
	        "/usr/lib64/libgcc_s-11-20210728.so.1"
	);
}
static void svir_117(void) 
{
	svi_reg(&(tinfoil.validation_items[116]),
	        "97ea6ee5e96fe61ef7a99dfe34383d0233ae2a9d542084de3d7f99f0d0cf08cec7bbcf5f2ae835d61bc0764dd42d29517a25f1f67a4dea3d254d90c4fff90819",
	        "/usr/lib64/libfreeblpriv3.so"
	);
}
static void svir_118(void) 
{
	svi_reg(&(tinfoil.validation_items[117]),
	        "682f8ea49648538b78f2c818b1cbe2bef98fdf26a77cbd4581c3b669a4ced7079b432982be7ad07654c8c94d67e45b5085ecbf5714146a0611eee538a136567e",
	        "/usr/lib64/libfreebl3.so"
	);
}
static void svir_119(void) 
{
	svi_reg(&(tinfoil.validation_items[118]),
	        "75817ba2d0306e10ff63fec8e676b14088de65fe5b5e8a48ea883e3478768e1ae119b3f964a2ae56afb6fc8946d5ddac76036b432d39499296e92a44bbbe93a0",
	        "/usr/lib64/libffi.so.6.0.2"
	);
}
static void svir_120(void) 
{
	svi_reg(&(tinfoil.validation_items[119]),
	        "b6393be5eb9ed065a1666d63297a36adcc7d743c108a17caaea67012661b47c7a9a270aa15045ef32c496d096529d301c7dd5571d205f9d4fc671afb8553cc06",
	        "/usr/lib64/libext2fs.so.2.4"
	);
}
static void svir_121(void) 
{
	svi_reg(&(tinfoil.validation_items[120]),
	        "76bb06cb41893090d0711adbdcbfa62f2cc01f5559d3ad0c8d1b803d616c6affa655867d0cdab9d647d59f1c39e182818117407da5ed1f22cc49b42a2be5cdec",
	        "/usr/lib64/libexpat.so.1.8.1"
	);
}
static void svir_122(void) 
{
	svi_reg(&(tinfoil.validation_items[121]),
	        "1ada711750e714f95f55e5e833827811c2adcd0e8014906f990ce838438da2e6195af593f4ef8589aa35666a6e2fe9535548f2bbac6f5d07ff6a1720c0f28176",
	        "/usr/lib64/libelf-0.185.so"
	);
}
static void svir_123(void) 
{
	svi_reg(&(tinfoil.validation_items[122]),
	        "f91a9d5e8cfd48a8a03d8d0b5e48c8693bcc63783028d2eb0f88578412c2bfc0fa5169cb3c9b153f3bff53f1236248fd57e58cc34e2ffb1b6e95e4d05fddb54a",
	        "/usr/lib64/libeconf.so.0.4.0"
	);
}
static void svir_124(void) 
{
	svi_reg(&(tinfoil.validation_items[123]),
	        "af85657241f1bf3e358569403847eda4586e5b47658fc7af6bd82d5d206018c0b3bf19c25c76520ac9e4230e4116d1b9ed3d115e7dcbc0c5d23af00d953317f6",
	        "/usr/lib64/libe2p.so.2.3"
	);
}
static void svir_125(void) 
{
	svi_reg(&(tinfoil.validation_items[124]),
	        "d539858e3d6966babbfbb42809cb4e4ac511764929cbe5a508d0d6ecd0629b35bc2da00760d90106a98cdc03be413015ffef497e19e364274697dea896288566",
	        "/usr/lib64/libdw-0.185.so"
	);
}
static void svir_126(void) 
{
	svi_reg(&(tinfoil.validation_items[125]),
	        "f313629b13f675ddee06acea3af22bbd3623762e5169381c4a06d344e560f9282e8acb10a365ea130f68ed03d61887746abab8d1b31b290d4a81c82c16e00e64",
	        "/usr/lib64/libdrm.so.2.4.0"
	);
}
static void svir_127(void) 
{
	svi_reg(&(tinfoil.validation_items[126]),
	        "a4de6a0db0dcbcc6f896628c6d35e974e314fdbba6dab78ea7ce363af3d6d49d7fe5b1ff54726412aae1d6afd72fd97e4a9e6fc7038da9aeaf2b1353b0eede61",
	        "/usr/lib64/libdbus-1.so.3.19.13"
	);
}
static void svir_128(void) 
{
	svi_reg(&(tinfoil.validation_items[127]),
	        "9a66b0beddd70278eb9052f0e37360292ed42d5143cde8d4b2de41777734a8a644a14b78d46da2a8037d9bb516b23042c5ce6808865703dcff2def82a027c41a",
	        "/usr/lib64/libdaxctl.so.1.5.0"
	);
}
static void svir_129(void) 
{
	svi_reg(&(tinfoil.validation_items[128]),
	        "5e354b633eb08b5c877b326f91eb6e05fbb9da492d38e25bf99c5ddfdd305d7a0761f861ba392938265e0e9952ccce5d8c4ba5abc73e3fe7e7e17925bebc09f4",
	        "/usr/lib64/libdaemon.so.0.5.0"
	);
}
static void svir_130(void) 
{
	svi_reg(&(tinfoil.validation_items[129]),
	        "607b17c757706e82345b8ba4efebe88ed5ef94d944b87caa1703347f5ecd511db1f27998fe09048c852e45cf1073f7bdac496be24439914fa1ba12888ba26b23",
	        "/usr/lib64/libcurl.so.4.7.0"
	);
}
static void svir_131(void) 
{
	svi_reg(&(tinfoil.validation_items[130]),
	        "3e7b11446bc7ff2db8d3179ba976d4e6d98e13ca3f4a60d8bcd1b9dff8d69f6dac2ee85838a20dbb78a6e09d5407cceaa9130b48ed54904140ea1e74edabaa4a",
	        "/usr/lib64/libcrypto.so.1.1.1l"
	);
}
static void svir_132(void) 
{
	svi_reg(&(tinfoil.validation_items[131]),
	        "dbbe916f63a49ea6983f3e02bb28963330885eb49756411e5ee7dc1dafd9f846a71cdc9f07a0e206b553f06acb25d76e817849d0eeb0c13de8baaa4f67226f4b",
	        "/usr/lib64/libcrypt.so.2.0.0"
	);
}
static void svir_133(void) 
{
	svi_reg(&(tinfoil.validation_items[132]),
	        "4335e7ea3c7139cad4840bf6cf9d4557519f76b383c3b68cc537f0be7bb69a041f147f4e8eef8fa63c5b8f67d5b394eeff3a7cfadcc3eb5608eace87a94c6e2b",
	        "/usr/lib64/libcom_err.so.2.1"
	);
}
static void svir_134(void) 
{
	svi_reg(&(tinfoil.validation_items[133]),
	        "5e253856c0b19a2b8629965fb8845b80fdc6c8ff78ed3b95ed12d7819dd43166b8f5de0266d342ae886628924c71919bf5a134cb9d50eeae9cf32c33fa26c508",
	        "/usr/lib64/libcap.so.2.48"
	);
}
static void svir_135(void) 
{
	svi_reg(&(tinfoil.validation_items[134]),
	        "56da592866a38b1f901ed4b60076cb2a12ede05a4eef20a6cfeb2a32263a65645fb9a2e37340ca09ba41308596364ea3826d309711c6f06063be98690aa2686b",
	        "/usr/lib64/libcap-ng.so.0.0.0"
	);
}
static void svir_136(void) 
{
	svi_reg(&(tinfoil.validation_items[135]),
	        "5b4effdba4bfd29bd6cb22ec2dc89e533448b83b565edede005acce93d49e51467eb2a7e21fa840c061f76bbe9a4c45b87317d94e0236c889209c48a4eb1999f",
	        "/usr/lib64/libc.so.6"
	);
}
static void svir_137(void) 
{
	svi_reg(&(tinfoil.validation_items[136]),
	        "4d4cc38dcc631829d9caae30d57e3c02bcce36dcb10afc0bd033b9df2bed992fc9005339770f06174528b5721f9b5d8f14c70b78b0f838db3cf1f1c2c0f2724e",
	        "/usr/lib64/libbz2.so.1.0.8"
	);
}
static void svir_138(void) 
{
	svi_reg(&(tinfoil.validation_items[137]),
	        "e6a46215f5c0a9d1ef45178c4601e242b441fdc9d7821eccea200ae02a43af22d1ebdebd7d00b79e563608b9db1b140247e7bf69e3f8f552274f069a5332a9d1",
	        "/usr/lib64/libbrotlidec.so.1.0.9"
	);
}
static void svir_139(void) 
{
	svi_reg(&(tinfoil.validation_items[138]),
	        "6678b15e924d06ad0deacfbf118f625ec3d84d669635e30d9167dd12ba30ca07c7279899fcce5f55f781906774b23729c4923a4f1b5b9b3cb2b5225c1c56963a",
	        "/usr/lib64/libbrotlicommon.so.1.0.9"
	);
}
static void svir_140(void) 
{
	svi_reg(&(tinfoil.validation_items[139]),
	        "204ac666854364c803adbd083e51eef1e59500770bf07c6d2be38b9a1ca2ab0644dca1a3ad67b23e3fa8a0d7c8f4942a42b3cbe54ca46ee6ef8c40c53f049956",
	        "/usr/lib64/libblkid.so.1.1.0"
	);
}
static void svir_141(void) 
{
	svi_reg(&(tinfoil.validation_items[140]),
	        "ce3e7af9680ca4462f5b4ed4b2e820e30370bc0008a50673ac558208883ee13dad636c3c083a8895486da4e12699255bfcb1ec3e12b2be4c9e91c42d8751be4c",
	        "/usr/lib64/libaudit.so.1.0.0"
	);
}
static void svir_142(void) 
{
	svi_reg(&(tinfoil.validation_items[141]),
	        "f69a1989768d0104474bb7ca825b2b9a7fe14275309263b49b820498ef7b45f8735f809332ccdd7f298cb0bbdc3ec32fd78e7248ebbbd535402f39e1acfc93c8",
	        "/usr/lib64/libattr.so.1.1.2501"
	);
}
static void svir_143(void) 
{
	svi_reg(&(tinfoil.validation_items[142]),
	        "270d7f8629d6efa9f285590f3fa7f2f4c22c781a3452bd874170b0c5e6c5c9fee95cb915efdc6ea561f28681eab77350dce91460e499b69a860b2369bf9348bc",
	        "/usr/lib64/libacl.so.1.1.2301"
	);
}
static void svir_144(void) 
{
	svi_reg(&(tinfoil.validation_items[143]),
	        "b7d7e4b9ca4849dec0565a9902c50293f9c79422a03115dedbd426402db1d772efd3cbd173c6b13a422eeb30d34f35b7a33b57ecf84902888fcc04c28fa0684d",
	        "/usr/lib64/ld-linux-x86-64.so.2"
	);
}
static void svir_145(void) 
{
	svi_reg(&(tinfoil.validation_items[144]),
	        "796e457be98b71e5971fb42a2ad9aaea89c7ff056a6122f1a492db5c26021caa2b99d7e9475ed2d456517f55608fd5492f6c4f4a2dcf9df4c4ed5e702e59be16",
	        "/usr/lib64/NetworkManager/1.32.12-1.fc35/libnm-settings-plugin-ifcfg-rh.so"
	);
}
static void svir_146(void) 
{
	svi_reg(&(tinfoil.validation_items[145]),
	        "cd8259d561a9f267dab3866c0b5cbbc854e082cd04811289e44d411373406b1237ea2c47f6b953c5123bccfeac2587b9b17eba204b4ff5a6f476ddbde78642d2",
	        "/usr/lib64/NetworkManager/1.32.12-1.fc35/libnm-device-plugin-team.so"
	);
}
static void svir_147(void) 
{
	svi_reg(&(tinfoil.validation_items[146]),
	        "1193d70e966151c1255f981f1557889cae4abb94282c2868b032c3a23d360c4d675857d14f0ad3ab61bfc8c76f6b349ddb8336c768612b8afb7e7a814cdeb9e9",
	        "/usr/lib/udev/scsi_id"
	);
}
static void svir_148(void) 
{
	svi_reg(&(tinfoil.validation_items[147]),
	        "b0838ae1932a04c9d4906f7793ba9aa7d3738ee1262308c5c414e0ca098babaacd8ef20b0d9aac25ed286d745122fd23dfb45fe1992a19a1739b9b88ca23881f",
	        "/usr/lib/udev/cdrom_id"
	);
}
static void svir_149(void) 
{
	svi_reg(&(tinfoil.validation_items[148]),
	        "35ef1626a3d310fe169b11cc55194c72f9cfbfd76d89c01e59a4ddf9c7605bb758f2bbe994ccfaddbdfd5fe0fb887f8dff843ed310131d23f0a2d9aaea49f474",
	        "/usr/lib/udev/ata_id"
	);
}
static void svir_150(void) 
{
	svi_reg(&(tinfoil.validation_items[149]),
	        "a4ae0e06989b79d443de78b1797183878aef58184ab6bb411300b3f12fd440b77b08bba7ee9035010664febd31bc6bac6ea6d46fc47a40b4d10cbaa45d33b4b1",
	        "/usr/lib/systemd/systemd-volatile-root"
	);
}
static void svir_151(void) 
{
	svi_reg(&(tinfoil.validation_items[150]),
	        "97c183ab876e1b3fdb534363893789f7919e4ff7bdfa0e27807361e187b7f25b0a0f8ff842534331424ec1c954c09ce4cf665bb5c223687ad3e202cbcad8fb28",
	        "/usr/lib/systemd/systemd-vconsole-setup"
	);
}
static void svir_152(void) 
{
	svi_reg(&(tinfoil.validation_items[151]),
	        "058f5e542ee0c57db34544a61aa31e15abdffcfcd7e2fac788794ad8858aba38ad72555647e6178a9c58e99da0b5b3dc4408c87a251bdcbd6079a0918211433b",
	        "/usr/lib/systemd/systemd-sysctl"
	);
}
static void svir_153(void) 
{
	svi_reg(&(tinfoil.validation_items[152]),
	        "cba3fffe157f1b370b4edab1e674dec9fc5413e471eedf6f12b2b69fd327e5337e2f7a97647e8fd6b37ffb37fedac400e1075a9dd5863cae454efb0aaf036657",
	        "/usr/lib/systemd/systemd-shutdown"
	);
}
static void svir_154(void) 
{
	svi_reg(&(tinfoil.validation_items[153]),
	        "f53660d38790af7701b3fe48c9f771214042a3df822b1446f2d0d6d2c7c21a0c4d145f74ba4e032e91c6738fb49e177777cac31c123117d1de170879d2b56275",
	        "/usr/lib/systemd/systemd-reply-password"
	);
}
static void svir_155(void) 
{
	svi_reg(&(tinfoil.validation_items[154]),
	        "5c0fa5054f06e2641d72d4ac64a56ed7deffa5ba095e1232a14d23f4d29dff801972cba1c71893af326b5983d2948e49181617d941ebe1b15aadaa5cbc3dc6ce",
	        "/usr/lib/systemd/systemd-modules-load"
	);
}
static void svir_156(void) 
{
	svi_reg(&(tinfoil.validation_items[155]),
	        "67076789b802f54ef6be5d9d86a975efd02eb483c25e4dc3385964ee46b9644da85ea3977dc18387b32b6076ab6b1b778fc9c42e60f591e6f83a33ca1209b68b",
	        "/usr/lib/systemd/systemd-journald"
	);
}
static void svir_157(void) 
{
	svi_reg(&(tinfoil.validation_items[156]),
	        "7f94a6095df9780245f797123b835713352b288214b40cb938fad004f2fa700a1de61b00af02c2e959dc46497506347c21fcf46a54e4ec6fcf82389bd753054d",
	        "/usr/lib/systemd/systemd-fsck"
	);
}
static void svir_158(void) 
{
	svi_reg(&(tinfoil.validation_items[157]),
	        "d7e0640f3098403ddc039d778b88b2209ee4d28c5c76f48ca2b6fc908eba16960f17346737e679ff52da04884d580bc22d36028e8c11ae7f9330487cbc9c0277",
	        "/usr/lib/systemd/systemd-coredump"
	);
}
static void svir_159(void) 
{
	svi_reg(&(tinfoil.validation_items[158]),
	        "4d115c6ba06df4517d05449957ae8dfd5f040658322ecec9840dab6c9de27685d00a90a91451d7a4b79953d3fc181c2a1c17d2221e61b8247fa6a7f28b4212af",
	        "/usr/lib/systemd/systemd-cgroups-agent"
	);
}
static void svir_160(void) 
{
	svi_reg(&(tinfoil.validation_items[159]),
	        "affeefc1057dfacf62e4060f63f9325dc7665b51e175389e6538dff449adcd799f70e15f9ddb68524cf1d03f2c643a01315fc0158e2f24dfb3f2aaf093fcc021",
	        "/usr/lib/systemd/systemd"
	);
}
static void svir_161(void) 
{
	svi_reg(&(tinfoil.validation_items[160]),
	        "c3562221328b407e6c65125b5dfbef23f7bf646bcb3f43909bdab2d1f43f47089e64fd11ebcee487ce9bb26704afcb00c642ee3abd296348145134ffaadb7c40",
	        "/usr/lib/systemd/system-generators/systemd-gpt-auto-generator"
	);
}
static void svir_162(void) 
{
	svi_reg(&(tinfoil.validation_items[161]),
	        "cba9690c6bd6636c831343aa15e51212022ce61eb17b056440a8d1581fcb11433f76e2cd665c1ad530634182f1321c077061c716900f49f9a904e60e6039f58c",
	        "/usr/lib/systemd/system-generators/systemd-fstab-generator"
	);
}
static void svir_163(void) 
{
	svi_reg(&(tinfoil.validation_items[162]),
	        "d28760bfb13fae9081426b839ae97e9ff15b95f88286a3beebcba1cf8831f45a25c411e8b4210c4e3fa317913528367524da64f328afa7a3677e193dcd30fdf1",
	        "/usr/lib/systemd/system-generators/systemd-debug-generator"
	);
}
static void svir_164(void) 
{
	svi_reg(&(tinfoil.validation_items[163]),
	        "eb5b83d61e201ff9b9b19f212d85e7ba1b27087bc89caef72c889328da3784f3520052938b34b3827655fe0f32e0b0322651405d106f0f7eca7cd18f9eab0caa",
	        "/usr/lib/systemd/system-generators/dracut-rootfs-generator"
	);
}
static void svir_165(void) 
{
	svi_reg(&(tinfoil.validation_items[164]),
	        "8b44b6b41b2e57801c2ee6dc103542a58a8763f5938773cbdd16ae9d877b17c24d70f659f7a28eff8b65eec24e9c7295fa35dd1ced81e36ab659cc7989d032cc",
	        "/usr/lib/systemd/libsystemd-shared-249.so"
	);
}
static void svir_166(void) 
{
	svi_reg(&(tinfoil.validation_items[165]),
	        "d75a845dcaf23766ea127277f9feabb043fbdc8ce5bf8af51c5ca75a2221d85a1bd4cf3967205a65d1d41fa6991628da5dacecad757d8656990a07a69e703a89",
	        "/usr/lib/net-lib.sh"
	);
}
static void svir_167(void) 
{
	svi_reg(&(tinfoil.validation_items[166]),
	        "6d4ed45554e2a2c665b4d38621956ffca5546aebd797a0bf28250c0a38a667512d93eb7f37262c2e28c80d9682a645626862c1661ee45e4beb88253d6b8cdeec",
	        "/usr/lib/fs-lib.sh"
	);
}
static void svir_168(void) 
{
	svi_reg(&(tinfoil.validation_items[167]),
	        "1eb77c7e3117e9200ea97d4f7f5117d3c96e5ca335214e3bbb4851d964350485f4d8fd5c011933fd22d0a8b42e343c8ad09488cc8c66832aa2a82e2a456b790a",
	        "/usr/lib/dracut-lib.sh"
	);
}
static void svir_169(void) 
{
	svi_reg(&(tinfoil.validation_items[168]),
	        "fbc0fc6724fa6bf645434e17ee9dff4e4e188e0f3a076c322746230c8d2fd99395f448bc987632a59aac463dfb9377d05dbc33c5d0575e6074374e3eb8b5936c",
	        "/usr/lib/dracut-dev-lib.sh"
	);
}
static void svir_170(void) 
{
	svi_reg(&(tinfoil.validation_items[169]),
	        "31acd0039a78d5beefb924e8337321bd2b8016c959cf9f71d51d563d4cd1151446ad4671a4cdefb4fd77a20c4e943c2dd5a19857bb7df51e8e0dfaddd0312df9",
	        "/usr/lib/dracut/hooks/pre-udev/50-ifname-genrules.sh"
	);
}
static void svir_171(void) 
{
	svi_reg(&(tinfoil.validation_items[170]),
	        "21c1189591d0484c8f50b75f050c52ef9059207f15fd2d816b4ef13f8c98636074323bdbfc3817bb22a75e1de78332b1f49e37819136504d9a7349b937ffe683",
	        "/usr/lib/dracut/hooks/pre-pivot/85-write-ifcfg.sh"
	);
}
static void svir_172(void) 
{
	svi_reg(&(tinfoil.validation_items[171]),
	        "a8c81fe64e37400871d1694f523bb73a398ed8eedc23c960f3f0d7f113d0bdbc04fdae21b84e49189c041e823c241df1cd0dfcbae0c251deb493461d2205477c",
	        "/usr/lib/dracut/hooks/initqueue/timeout/99-rootfallback.sh"
	);
}
static void svir_173(void) 
{
	svi_reg(&(tinfoil.validation_items[172]),
	        "5e0e45f576ba4a83363450fc1d99858f9d3749fa701338834968916a3d9c6d98bcd31bc76c7b724239d0841a537c99665a4dbf0823cb88bd91fe23f8bf52f647",
	        "/usr/lib/dracut/hooks/initqueue/settled/99-nm-run.sh"
	);
}
static void svir_174(void) 
{
	svi_reg(&(tinfoil.validation_items[173]),
	        "83b0026310c8956d9fddeeb9dc0d11a62704517426594616fa4c3ae377b6fe3c7cf44e3ca3d1389559efe6b373427a58f1d978f997a52aa866e9c3fd7ee1f601",
	        "/usr/lib/dracut/hooks/emergency/50-plymouth-emergency.sh"
	);
}
static void svir_175(void) 
{
	svi_reg(&(tinfoil.validation_items[174]),
	        "e58335ed810a8e0f4a261b57cf2e5f650a37bb62e94075709a847f921e1a6b287ca2463d38eb40cbaf4809847c0be1dc8fbd29192e8be04048ea7aa57aa84b81",
	        "/usr/lib/dracut/hooks/cmdline/99-nm-config.sh"
	);
}
static void svir_176(void) 
{
	svi_reg(&(tinfoil.validation_items[175]),
	        "01b72229c9867e297f44768f2ebf2fa07929a980f46b2c9931cc38b6fb3998b73dd7f246f50a383a892a08e2f6b8a5d5a6074c4918e57c71f91285788b8d4356",
	        "/usr/lib/dracut/hooks/cmdline/91-dhcp-root.sh"
	);
}
static void svir_177(void) 
{
	svi_reg(&(tinfoil.validation_items[176]),
	        "7a886225ee1e7a2993c0e3b0d04b43e2eec75428040981b540ce311d56600240b24bf3d1dfaa6d80dcdb7c2eedbca5c37b4ae22270f3b60b139d6a7555bf2c12",
	        "/usr/lib/dracut/hooks/cleanup/99-memstrack-report.sh"
	);
}
static void svir_178(void) 
{
	svi_reg(&(tinfoil.validation_items[177]),
	        "5b52441eb3e8e4d5902cee4e6563cae0b8d0b141d5a24a2ae343e88cf31620052570ce42b35c8e69f9a0db325e914b3f7727b55c64557383e79e352cd38985f4",
	        "/usr/bin/vi"
	);
}
static void svir_179(void) 
{
	svi_reg(&(tinfoil.validation_items[178]),
	        "6551fae1285ed55387ebf00a35ed2c9d95e16ca7eecc56d1f6917d3113acdb9ce00f60d8b978207a2598ff4c74bb6bf808741026c0d2ca60bb9aaa8d34d9caf2",
	        "/usr/bin/uname"
	);
}
static void svir_180(void) 
{
	svi_reg(&(tinfoil.validation_items[179]),
	        "e9940eab81542676e1e8598d60e01ee847bfde04a0c2f1c8206ebef6b2584f775a9c222f5a42e9a57cfc75f3d3e3cf02df0695d33fe8ae450e94a6b45f122924",
	        "/usr/bin/umount"
	);
}
static void svir_181(void) 
{
	svi_reg(&(tinfoil.validation_items[180]),
	        "787ef7ae71688145275bdfe91c7bb046509a76de9c3da37895db3048f6951e7fb6970e300b17a8f29bb001f8d8ed51064eb9bc4dda6a88af9f140c8fb266cc07",
	        "/usr/bin/udevadm"
	);
}
static void svir_182(void) 
{
	svi_reg(&(tinfoil.validation_items[181]),
	        "398d389040f0f89ece06e2c224c4a37beaeabb8e3f7a1bef2d7fa691180e7d72232b30b1d0db10dbc50ad168d64e0db7d77b534d3d3e5cbbfc61d2f9dc8756f9",
	        "/usr/bin/true"
	);
}
static void svir_183(void) 
{
	svi_reg(&(tinfoil.validation_items[182]),
	        "f183e6d58da884c3b9408346b9492818d512f21510014cf8999b3a38cc408ecb2a966dd39b7f7dc8597485a56b4dc31830b8f68f0fda2e6baff11f245830aad7",
	        "/usr/bin/tr"
	);
}
static void svir_184(void) 
{
	svi_reg(&(tinfoil.validation_items[183]),
	        "11c71e4990f01314b9e0b91e266e018f6d07642af909a588bd6e48352a289cb0935a4a63421d9d0de5eb894b38a49ae3c40b7825bc62acb42faa0f71e102ffe3",
	        "/usr/bin/timeout"
	);
}
static void svir_185(void) 
{
	svi_reg(&(tinfoil.validation_items[184]),
	        "a1b87180235c7482313b32dee67e54d7f9c449368454526bb93441796708788a54602857e2f95e2dab55404e1311cca42cec9d2add09b5bd24cd6c0ec8dbad4e",
	        "/usr/bin/teamd"
	);
}
static void svir_186(void) 
{
	svi_reg(&(tinfoil.validation_items[185]),
	        "0424bb9173ef9d94e8029a5ff9196c0ecfdd4afe0bfa8ce796dd1c0c52dbbc47e956675ac48caf3fa8cc2225823db7af6b1da501c3c1bf80f255f61dbfc97944",
	        "/usr/bin/systemd-tty-ask-password-agent"
	);
}
static void svir_187(void) 
{
	svi_reg(&(tinfoil.validation_items[186]),
	        "a659683f56a931b44f1ce69c24c1ac62ab53ea5cf600e9992a08054b5933d4b0464ff71c8f941ed7f84038895b6b9ee2c6c9081fd36f9fa3c004f026d1cb9278",
	        "/usr/bin/systemd-tmpfiles"
	);
}
static void svir_188(void) 
{
	svi_reg(&(tinfoil.validation_items[187]),
	        "6a2ba96d14b32e582033d0fde3653741e127fc8409b50cb6fabd83853fccb73f5af648543c75a53c1a33ef8beaaff00bb3cdc6ef0ff7c7e9efbdf8c135a7b096",
	        "/usr/bin/systemd-sysusers"
	);
}
static void svir_189(void) 
{
	svi_reg(&(tinfoil.validation_items[188]),
	        "c2071697f9d757dede31afa1b52dffca53a51558589e753a81c0689484f36a2aea67cb0b30cddefaaed122ea9afb7aec66194c7946f4e03ac0e3448f0724b19c",
	        "/usr/bin/systemd-run"
	);
}
static void svir_190(void) 
{
	svi_reg(&(tinfoil.validation_items[189]),
	        "07839f0cd2617582079184a6fc3933678ed6250c4f11c52893be0980df20cbff3d72d1d680470aee5600e482dfee0f6792a875b82c28e3edd58a67119c1f24b9",
	        "/usr/bin/systemd-escape"
	);
}
static void svir_191(void) 
{
	svi_reg(&(tinfoil.validation_items[190]),
	        "bfb8f883dcb07944ac03a8a6824b492166bd21c52d48c27a1776b96241766d2c8036519db249a147072caffa046ceaae80e207af8e044e78d5ff2ec6e06201e5",
	        "/usr/bin/systemd-cgls"
	);
}
static void svir_192(void) 
{
	svi_reg(&(tinfoil.validation_items[191]),
	        "f5d688dff7ffbb5f7eb6af7939f7fc76266631dec04ba9048c5883c6f22fd4474518d30465b5cc4fd90d62ce8bd8b2e5a87bca3153355def16080a7694541fac",
	        "/usr/bin/systemd-ask-password"
	);
}
static void svir_193(void) 
{
	svi_reg(&(tinfoil.validation_items[192]),
	        "280cb95b0ba73dc5c8ae9bc12ef9a42a809de1503fb67efffb29d64aac4427967378da7bdc6e9d0e5a4d0c0f60e64725cb485cedd41e40bfa1c427c227a5cab9",
	        "/usr/bin/systemctl"
	);
}
static void svir_194(void) 
{
	svi_reg(&(tinfoil.validation_items[193]),
	        "f971695f0bc14fd45d16bab545f3f2eb22e407dc7a11c20a4994525290c0bf773f594efb3dd3178c4e4eb73e1c5210cb92902c483c731bfc4854c2b1b551914a",
	        "/usr/bin/stty"
	);
}
static void svir_195(void) 
{
	svi_reg(&(tinfoil.validation_items[194]),
	        "7d6eecc8ae453e2e056b125ef3f629aa32779d741f5aa23f842fa2799d82688948d70806e87e492d53e7fa5468c89fe1ff4868255ced18ca1da928867b635f9e",
	        "/usr/bin/stat"
	);
}
static void svir_196(void) 
{
	svi_reg(&(tinfoil.validation_items[195]),
	        "0088658666d99ed3629061aa4de4fc51d91850aaf3f34fa0a2819a5afc15bc5101e234e0c841c3b35102535e351ff556a667e8dc4e33caf772fcb8d170fb81a5",
	        "/usr/bin/sleep"
	);
}
static void svir_197(void) 
{
	svi_reg(&(tinfoil.validation_items[196]),
	        "1735ef84e210e64ebf522db6fe623f9d5824a276b5d26e84778ddf7ee55bd623e924149c52ab47587e33cd0948206020b66ef18c76940b0a6cb4937ebc7723e9",
	        "/usr/bin/setsid"
	);
}
static void svir_198(void) 
{
	svi_reg(&(tinfoil.validation_items[197]),
	        "171565123bc95c0c7df7472e9523899fd34b4be6cf0780e8ddb5e96bc4bad0a2f986a3ca0ddbc322ce189f664628138f34de9668f6431773c344ab4c353626f1",
	        "/usr/bin/setfont"
	);
}
static void svir_199(void) 
{
	svi_reg(&(tinfoil.validation_items[198]),
	        "3fb39e9fe5d09450453c0979886f797b28c51f0a48ecc9a5fb95adc28746acf893828f9b0e9a6c094df1bb53b410c2c1f7e2e45c4ffd1625dbdb9680971babce",
	        "/usr/bin/sed"
	);
}
static void svir_200(void) 
{
	svi_reg(&(tinfoil.validation_items[199]),
	        "3a063967b0de98fa5dcf582214f6dfddfd11b3b14d4ec90271efdadf5b6046799dd46dff3011c3679a3fa6a2f179824ee2e525d6aba0ac9643c1ec1542e6b41b",
	        "/usr/bin/rm"
	);
}
static void svir_201(void) 
{
	svi_reg(&(tinfoil.validation_items[200]),
	        "ec2ce4e917a0fc222979d4a46e83699a66e6b859d7ad12c7d2c71c6e89e3415ff7fba34ae406ebda9a654b4ba3d14f0a0b39004c70d419c388fab15eb8da475a",
	        "/usr/bin/readlink"
	);
}
static void svir_202(void) 
{
	svi_reg(&(tinfoil.validation_items[201]),
	        "b270ac5b8a9ad028da7a11e0f53fc40fc3ee01af35244a4b5d92f50beaf0ca65640fa946bf61872602a7a344a74f2ad5852ec51c2be6d2ded77b3883a0dc3f1e",
	        "/usr/bin/ps"
	);
}
static void svir_203(void) 
{
	svi_reg(&(tinfoil.validation_items[202]),
	        "7c62fe53825b5e04196121af87c4e9abbd894d0966905eb17c2a9b3d5cb35ce6e023b010fc7e8e83f7f423c001a42e646b12ee285b8fd11bfafcf95c4888f39d",
	        "/usr/bin/plymouth"
	);
}
static void svir_204(void) 
{
	svi_reg(&(tinfoil.validation_items[203]),
	        "e4b1aff49609d3982ab9f38ee098533ba2ea4c63eb1b2b2f93b52055135bec47b218c629bc25d1cdd38f8e56c1cd1018880c08621f6f54e6bf2e478ad1d22335",
	        "/usr/bin/pkill"
	);
}
static void svir_205(void) 
{
	svi_reg(&(tinfoil.validation_items[204]),
	        "c5467e9733162e5c3d7f9a07dcf5a7092c10d9ba7b7020e89244794449ac93bb129ae0d87d9f90c858b5d62f14ea61fee44cc59c0ebb1c10a0bff0ed3966d11a",
	        "/usr/bin/pgrep"
	);
}
static void svir_206(void) 
{
	svi_reg(&(tinfoil.validation_items[205]),
	        "87bca35a4738b2fcce96cb5e76b4daed3c1c43ffdc4be9de130115ce6af9f6b693745e209b513ed4914f1f0a7c98dd47cd9620e64f9838ef1d9a82d85fcb1e18",
	        "/usr/bin/nmcli"
	);
}
static void svir_207(void) 
{
	svi_reg(&(tinfoil.validation_items[206]),
	        "6a71af07fcb232664dff91f4ea8f40fec056d236bead127a21ced0c6cd82da1637523796cd8db74cfcb12471f0d7221694cf48d46df395381cf7213ea6339d3e",
	        "/usr/bin/nm-online"
	);
}
static void svir_208(void) 
{
	svi_reg(&(tinfoil.validation_items[207]),
	        "6d6901cac5d85d735c430c068bc3b598c5c11a5bc3a4bd5bd441df9477a1b3557a83b00d2e241a118bd894a1fac222fa3b43be4dd8dccdcbf4ae4a759671b4f7",
	        "/usr/bin/ndctl"
	);
}
static void svir_209(void) 
{
	svi_reg(&(tinfoil.validation_items[208]),
	        "485fe074af48a7743a960cc8890aca402de0c48e677dd6dabb40c861a5c43444dad0b4b57a76c61a065316eb5cbd0669319e613a0f991d55cc0a52b4996b0124",
	        "/usr/bin/mv"
	);
}
static void svir_210(void) 
{
	svi_reg(&(tinfoil.validation_items[209]),
	        "d2385caade1cd9d90e6ab7a265d6f9fdd459fd9b05eee2703006ba6e6eebd50be2c1c8464c739e363c4fd867af3df3e5987644507c1725fa6ab0588152b526dc",
	        "/usr/bin/mount"
	);
}
static void svir_211(void) 
{
	svi_reg(&(tinfoil.validation_items[210]),
	        "15743d75ae57d66b05f68d70ffa49dba2faee4330cc86d0c76f0f4d4db72b9082ccbd2e5d7793e52e9f22a1fb43fa58eb60b9ca5d282af698a425aeb4329fcd7",
	        "/usr/bin/mknod"
	);
}
static void svir_212(void) 
{
	svi_reg(&(tinfoil.validation_items[211]),
	        "95d524dc11f134f3c9d8c4977fc9663e8e72ab40b4f2470ed536acc01381e2d75a0cc8076cf509c5f959e46240f2bb5fa2c377cf63d4cbb06f7bd2f66b24322d",
	        "/usr/bin/mkfifo"
	);
}
static void svir_213(void) 
{
	svi_reg(&(tinfoil.validation_items[212]),
	        "543d844d92c2b1720cf97625633d0514961388d9817ab2ba6e268044ecb4174859403949acc83072e8aee16fa66aa84b6c9a30a40279138e5d7806fc5e6af3b5",
	        "/usr/bin/mkdir"
	);
}
static void svir_214(void) 
{
	svi_reg(&(tinfoil.validation_items[213]),
	        "07a158662b98498e627f8485aa1a2318c39def7cb0edf1daa48fc2ca4043afadb39d258ef8a42ba3895ba84e14664c25162bd8390abc3ab8887167820e0bd1dc",
	        "/usr/bin/memstrack-start"
	);
}
static void svir_215(void) 
{
	svi_reg(&(tinfoil.validation_items[214]),
	        "b9ddc84089a8718d85a27bc3b5f07df9f8f9d8a441cabe9090b5f30b8c8c9561c808c3c406a5f38ffc3e0f5bbcbcb72a0b72408d7313dc076ff47f9e061ef7dc",
	        "/usr/bin/memstrack"
	);
}
static void svir_216(void) 
{
	svi_reg(&(tinfoil.validation_items[215]),
	        "db63e32135f087504df7fc34e9085c411195b99f3fef8df68178761481a3da7dd944a0791bfb5097a7dd82249bb2acb0b0daea1d1f4107a840452da1296001bf",
	        "/usr/bin/ls"
	);
}
static void svir_217(void) 
{
	svi_reg(&(tinfoil.validation_items[216]),
	        "3b27b970a3246a45ad6589c0ea55fbec33a3a51227bb0b703f3e52a971ccc0d6cb4aa1a1ff5d06469ee97156320af9caad7085de22f9e501bd7bc7272d17632b",
	        "/usr/bin/loadkeys"
	);
}
static void svir_218(void) 
{
	svi_reg(&(tinfoil.validation_items[217]),
	        "20d57ff970272a7404d14e6f7d063994c278681682c73a8ab8683d6d2536e44625e0a8703380ad7536616eeb4d996abdbb05b19011dd3a5b356e86859d33e238",
	        "/usr/bin/ln"
	);
}
static void svir_219(void) 
{
	svi_reg(&(tinfoil.validation_items[218]),
	        "126aa131057fad2702f04275465a0b16055219784ead65475a62cbc7c10fcd2c4f2ef0fb5939b4ecb2636d9caf91a3d1256dca4323ebe143c56b19acd622ed81",
	        "/usr/bin/less"
	);
}
static void svir_220(void) 
{
	svi_reg(&(tinfoil.validation_items[219]),
	        "e2a4098377a4c4000421a1084b8f61b677502b7a060bf4252b8c3e6b6bd58b29921f0f4d8bd06bfb1bc5806cfb0493b1698c208762f0aa0942c31da53ab7d32f",
	        "/usr/bin/kmod"
	);
}
static void svir_221(void) 
{
	svi_reg(&(tinfoil.validation_items[220]),
	        "a47512d76105e8e28fe5e09ad3be776c4cd130de224dca4ea60a70f37c139bc750e5045734da3391bd392731a26842f5944db46326a4b189eb7ca210c6a3ceb2",
	        "/usr/bin/kbd_mode"
	);
}
static void svir_222(void) 
{
	svi_reg(&(tinfoil.validation_items[221]),
	        "a033ac3a647cbf490f45b7ebe3c50be0529d99671da0fedc14067c1a6975f2be08f25d029fbef668463ef67fd4d80fa32d7fecc0d6b57790f902d55424b2b714",
	        "/usr/bin/journalctl"
	);
}
static void svir_223(void) 
{
	svi_reg(&(tinfoil.validation_items[222]),
	        "a17bee1441eefc983fd212be611cbf5f942af4410fec37400e8340e2dbef0d19f273c7fe6f7c698513943857864a3c605d8010cd6ccafd833bdb96a7683314e7",
	        "/usr/bin/gzip"
	);
}
static void svir_224(void) 
{
	svi_reg(&(tinfoil.validation_items[223]),
	        "da489e66efb8dd8a452a79302ce753f0dc5a51f021c6d1b2fb1ebcf6effdefbaf037d8a43733b6be2d6714a56b07985ae322bbab2e834c94f0c76f8e8d569331",
	        "/usr/bin/grep"
	);
}
static void svir_225(void) 
{
	svi_reg(&(tinfoil.validation_items[224]),
	        "1a5c986509df98c100487a5b6440204543e20000b5c93bfff252997ecb4856c62c16dba7a77a33af5f8da4f9df950a9366f4f92c0da021b229a4781d8b8aa4ef",
	        "/usr/bin/gawk"
	);
}
static void svir_226(void) 
{
	svi_reg(&(tinfoil.validation_items[225]),
	        "9d203693c61bce0f06cca6f6ead4b29a58010fa9f2474e0d2e5af0e1de91cd62987a935ec1cf3b26c052edcc6b041c370fcffe455d9af11339fa65330821e2f2",
	        "/usr/bin/flock"
	);
}
static void svir_227(void) 
{
	svi_reg(&(tinfoil.validation_items[226]),
	        "334854271683430c2c32a4055ff4cd5b53f43fae1fccdb71880059b3228aba8f722389501319108b3c9da8a233d82e181c1a7191b17bf25a07ad06fbc53f1956",
	        "/usr/bin/findmnt"
	);
}
static void svir_228(void) 
{
	svi_reg(&(tinfoil.validation_items[227]),
	        "7f62b6ba6f87e8e3a0fae9b5daf27b55be8979c7ce272293acd99a37a856e36e4ecf3ec625e42b749bb000a89444a86e9c6dde63484318a23d63ed013acec211",
	        "/usr/bin/echo"
	);
}
static void svir_229(void) 
{
	svi_reg(&(tinfoil.validation_items[228]),
	        "409cd5c6f06f968d41481fa68824abcc0e24175a6376bf0a2c3b2461ac172b8771cc7193c0c0669e072357bd4ecced56b64be0ee6c0facb2422394cc13469ade",
	        "/usr/bin/dracut-util"
	);
}
static void svir_230(void) 
{
	svi_reg(&(tinfoil.validation_items[229]),
	        "de0a515d47806fc8f8a5200a8d236de4394dd92ea6fa6b8a1b21756445408c7ef6e133b70b0ff7ee52e35da3c81e1d38833767aa7b9a2c56d1feab5b4ebe7bd9",
	        "/usr/bin/dracut-pre-udev"
	);
}
static void svir_231(void) 
{
	svi_reg(&(tinfoil.validation_items[230]),
	        "525ef470fe178560424560818ae6f764a2be5c2ec9710ceb9fb9bba2f38c30d25ab29fa645c705db6f00bace9b6de65e8966fe891c59e85343f2a12a495a6f67",
	        "/usr/bin/dracut-pre-trigger"
	);
}
static void svir_232(void) 
{
	svi_reg(&(tinfoil.validation_items[231]),
	        "62616f3f0a29b617605e5ad796b0074e60c21dc98d90e85be6b616b380c366d3140031bfef673b4a0d70f5dd1bc7e99bfce01e3a817557c042dcee7ca7ae2f1e",
	        "/usr/bin/dracut-pre-pivot"
	);
}
static void svir_233(void) 
{
	svi_reg(&(tinfoil.validation_items[232]),
	        "ae71bd75f29773b64dbbe9902755dee241f93f8516e54bdfc5c689f3174d11e96d5d6f8f41bbe675a40c0c3940fe578084bb8a00e0b3470410f445968dc84f92",
	        "/usr/bin/dracut-pre-mount"
	);
}
static void svir_234(void) 
{
	svi_reg(&(tinfoil.validation_items[233]),
	        "002cafe9aa8e6cdb3579a5c36a408ca911ecb3246ae364e088d49365347af227c6884245910ce0e13aad7ca163f568af2e9c4b90ab144d7fc33e8341ac01fed6",
	        "/usr/bin/dracut-mount"
	);
}
static void svir_235(void) 
{
	svi_reg(&(tinfoil.validation_items[234]),
	        "ad56deb30e2ee425e153b81ef90b6e1e46e9c813d395c7ba85cb3671d6f34237b5732ac24ff8e8825fc9c3f4e84b5c7d45c9925f7af24b292577656267c8894b",
	        "/usr/bin/dracut-initqueue"
	);
}
static void svir_236(void) 
{
	svi_reg(&(tinfoil.validation_items[235]),
	        "8734e2ac401f8e6a2feb1c5f4590a17fb9e8761e239c346096a1c206f1e2c6fb1b7a7cee3d5830991ddc9fd985dadae34d63795e5146215fae618ff40ea53d13",
	        "/usr/bin/dracut-emergency"
	);
}
static void svir_237(void) 
{
	svi_reg(&(tinfoil.validation_items[236]),
	        "3a20bc69f74ced6c0d251ba3b8244c0c6d71ff407abe2171c937ae23ad88f1c21f8b4dc92bb3282a8887cfe71e8d021ffe874b734ae3b60781ec76d1469051af",
	        "/usr/bin/dracut-cmdline-ask"
	);
}
static void svir_238(void) 
{
	svi_reg(&(tinfoil.validation_items[237]),
	        "a75c88e4c77efd29df71b166a7405406a20ad6df26da520345454c316dfd4b74cbbb265d6eb1cc83c4d364977e1335870d15db67841ccaea2745a4bf7f2a6942",
	        "/usr/bin/dracut-cmdline"
	);
}
static void svir_239(void) 
{
	svi_reg(&(tinfoil.validation_items[238]),
	        "e0844dbe6a3b4923c6a8fb7cfafa19c11befc000fe865e187280cdef4ec49a000622887424382e817abb5f45a71e6c6f0363ca779ec8fd27f9b307454219d1a2",
	        "/usr/bin/dmesg"
	);
}
static void svir_240(void) 
{
	svi_reg(&(tinfoil.validation_items[239]),
	        "b3af0eaf4c9c5bf91401437d68d960c4b5027488a306a96de3364c12682cd62b8685ab552588c9d398bb48b802a3a630fe7523a760c76950ca61eb3e370244e0",
	        "/usr/bin/dbus-broker-launch"
	);
}
static void svir_241(void) 
{
	svi_reg(&(tinfoil.validation_items[240]),
	        "c884aa66cc49792352b6ba8dcddf7570805ff546614bd80e3246ffa045ea17791d6aa099c438a4ba4c26da6006ff513a87fbf00beafee31e6252ac0837dcf32b",
	        "/usr/bin/dbus-broker"
	);
}
static void svir_242(void) 
{
	svi_reg(&(tinfoil.validation_items[241]),
	        "3ec49238c55786c2f371032a38aa7926695197c9e1f28248e7a045102c22bf8600d9d793d4ed165e617904b603597754802f217070b73c197dfd37f9a7f740cd",
	        "/usr/bin/cp"
	);
}
static void svir_243(void) 
{
	svi_reg(&(tinfoil.validation_items[242]),
	        "b46b1a8194f781f2870ee8bc73af29e7119b6f08373d6f746aa877b6ef8056f4f53fb705ece653c6b0d7972d5a136430356985f95e67029a2267140aa22956eb",
	        "/usr/bin/chown"
	);
}
static void svir_244(void) 
{
	svi_reg(&(tinfoil.validation_items[243]),
	        "fee55ec5d985699ec18db0154383925921b7b18f9db99c404c3eb9b809833434c8ac147a34ce59eeb3522ddb65e3302557779a1e8f33a4fc733fd23c4a0b8397",
	        "/usr/bin/chmod"
	);
}
static void svir_245(void) 
{
	svi_reg(&(tinfoil.validation_items[244]),
	        "775a5f04e1382bc36c5ba3a6555b62347de39c11aafdbb30ac086c3e40acff04370e07465d3e4ba2d865b2888c66e4184fd560fdcffb0ef4277560f0d057e52b",
	        "/usr/bin/cat"
	);
}
static void svir_246(void) 
{
	svi_reg(&(tinfoil.validation_items[245]),
	        "4bf67ee5d0d9b1ac89eebc3b2861693c2454f7ea2c2304703be01982e290fb03710a4261afd20dbe8d859a7d8529a6013a77c661dbfa32464aedf620c04d1575",
	        "/usr/bin/busctl"
	);
}
static void svir_247(void) 
{
	svi_reg(&(tinfoil.validation_items[246]),
	        "80a20a3ae25c67f0d450e7684477f2ed862c709d6a84245bf39d3488b80e035c7b6ace048038e76c7f2e9022a3bbcaafc2580e67e35812571019986b9abbaf65",
	        "/usr/bin/bash"
	);
}
static void svir_248(void) 
{
	svi_reg(&(tinfoil.validation_items[247]),
	        "1e46c6fabb7bfe425359a5bebc136ab0232ca7d97b1da27face335a02a7f2e726501369bea71ed168380c0f85654f240eaccffa1eb92b01f2aa737a85bad0d4e",
	        "/usr/bin/arping"
	);
}
static void svir_249(void) 
{
	svi_reg(&(tinfoil.validation_items[248]),
	        "3fd78329be9db1bf7dcdc74f589182bcbd6a5c098391a65ae05103b586e7a7b8dbdbd32301c0278c814d19a73d687c7c7d19f90174d8ae92a50a850d5c372185",
	        "/shutdown"
	);
}
static void svir_250(void) 
{
	svi_reg(&(tinfoil.validation_items[249]),
	        "7942259e070fc6639bcd3f99924464b4a194266341acaa9ecdb02de5ce8b48dcea8d6f6806aa4f779096429e761deba0c613697e72475b74be1909e876cc4d35",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/sound/soundcore.ko"
	);
}
static void svir_251(void) 
{
	svi_reg(&(tinfoil.validation_items[250]),
	        "bd087b5bdc5c83777dd0a29415712d116555de7d6fc1c737735b207b50aa6d929368e98c70f4424d2edc9b18668935a4902884d52d0416c534fb0c3f3a414098",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/sound/core/snd.ko"
	);
}
static void svir_252(void) 
{
	svi_reg(&(tinfoil.validation_items[251]),
	        "83f3e1f2506559485162e9146aa741a2b92a333e4ea2a15195a9000cdf771064be7c5c120ff580d27c81649222b762b240bfdd72f815a4006667e90d07f5ffbd",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/sound/core/snd-seq-device.ko"
	);
}
static void svir_253(void) 
{
	svi_reg(&(tinfoil.validation_items[252]),
	        "f859f64233c00b8b4bba0ddb5c788093d921322fa85a951f45a80b76c9b798c08e04656481d77e87a7e21898fad5526b2c6d31907145a8cdb408d24b4639e8b2",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/sound/core/snd-rawmidi.ko"
	);
}
static void svir_254(void) 
{
	svi_reg(&(tinfoil.validation_items[253]),
	        "fa6aac4dae8fb527437916f98cddf2d8eb6e0a3165fb47b22762829fcdea11d135a236e78cef28ec931a704eb35297a99533155fef8a3636c492edb33e67ea54",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/security/keys/trusted-keys/trusted.ko"
	);
}
static void svir_255(void) 
{
	svi_reg(&(tinfoil.validation_items[254]),
	        "9567a86a47a9640141bcba6f9a1bb2cc91d16b5fe17f3f7213d548df6756f4c1df872fbd6e03d0a428f2d4e681b43588ad3bf65c2e538e6a8afe0ac606034a0e",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/net/rfkill/rfkill.ko"
	);
}
static void svir_256(void) 
{
	svi_reg(&(tinfoil.validation_items[255]),
	        "a991a7dffd8976d700a7a2a1d2caec21c9b574d2120cee64865ba04c06b05503286480eb9d2711998e6f68b14f9f745d0ee102c6b917f54db128511959a7d733",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/net/core/failover.ko"
	);
}
static void svir_257(void) 
{
	svi_reg(&(tinfoil.validation_items[256]),
	        "757c8c470f4bf9b3241fc3b2f12ca2fcb7f520e6159e70b0be072448453551e4e297a388aa47a06319ddb58bd1c6b95f7be5616c09a699ba47b3675a7844c7ca",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/lib/lz4/lz4hc_compress.ko"
	);
}
static void svir_258(void) 
{
	svi_reg(&(tinfoil.validation_items[257]),
	        "0d6b14a7acf433e514e10866e6b1ffb439ef8f14a380d404c1db06e88c0ce291cb0f5f2f9505ca633d3326dad1fd9155b4be91982b34b1c433ef6440a3fbc51b",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/lib/lz4/lz4_compress.ko"
	);
}
static void svir_259(void) 
{
	svi_reg(&(tinfoil.validation_items[258]),
	        "3820db641dcd0dadb452fb234fd459b5abd38675d1bfd46f715228093550acd320002671ce831f2e43722bdb3708fc81606f26ee8eca01d8c6712e49d2e3b1c8",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/lib/crypto/libdes.ko"
	);
}
static void svir_260(void) 
{
	svi_reg(&(tinfoil.validation_items[259]),
	        "fe3cd61840bf2cd4587d8199010e574a95e3bc4c5df205528afe07294f243bf7986c9d9e135ee91d974eef635f07425a67fb0ea5f52f6482468d90f075fd4935",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/lib/crypto/libcurve25519-generic.ko"
	);
}
static void svir_261(void) 
{
	svi_reg(&(tinfoil.validation_items[260]),
	        "921056f9e0d8943fa72eea37612ac5495d7d5e7384372d18f9801bcd5f291bce2372fd6a773e5de23940fd7613264b6e92ec79224ba3ac40870bbd0f86724626",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/lib/crypto/libblake2s-generic.ko"
	);
}
static void svir_262(void) 
{
	svi_reg(&(tinfoil.validation_items[261]),
	        "15354b3076df292939ad56c36a216ee6f1a1ebf54a35e47708b300184b8b84100228fe14d88be0f527370b7d35d5ebe1dd5cfea35996e80808741a4097534680",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/lib/asn1_encoder.ko"
	);
}
static void svir_263(void) 
{
	svi_reg(&(tinfoil.validation_items[262]),
	        "b4c2b6aaac0763de96f47e6b337454062ce4adef6efc52bdc4b91a4452ef43da2b7d41ce4083aac10c147f0a8708f1f554a562680e363fc9316cf388aa255246",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/fs/fuse/fuse.ko"
	);
}
static void svir_264(void) 
{
	svi_reg(&(tinfoil.validation_items[263]),
	        "353dbc3e2940f07114ba0d06e9e34405a724527093a880485b22b4de6192182b15bf796a7e75a0181d0393c44925daad7c0d05c91b6e88439501a6de97f2d7b4",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/fs/fat/vfat.ko"
	);
}
static void svir_265(void) 
{
	svi_reg(&(tinfoil.validation_items[264]),
	        "034a39ff9109ba5f3603a4897fd3fde4a2f43eb7f70c3e6789c8ea4514ede5f791e65955b932e71daf1e5875e2db9f99b55b0b6a76cd18734c717bbb84a635f7",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/fs/fat/fat.ko"
	);
}
static void svir_266(void) 
{
	svi_reg(&(tinfoil.validation_items[265]),
	        "cd7ef5aabc2c59de0780e92da09f405ec9d8199691e239f5ec580e7323b218b72ba49146f9d8927abce4657f43acff7f435bb2141fd691beea498b83497c7030",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/xen_wdt.ko"
	);
}
static void svir_267(void) 
{
	svi_reg(&(tinfoil.validation_items[266]),
	        "11ea9759ba44505b0ffec10c3f3c9bfce35d0bf83ade3cf61e6c093ce977b129b55dce4fb5d439084dbd92b1de957942024389f58db76bffbfc7e814337d3f2a",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/wdt_pci.ko"
	);
}
static void svir_268(void) 
{
	svi_reg(&(tinfoil.validation_items[267]),
	        "32acded35eee2883a3a7a3f9ec59f3680f32e1b6e15fceb8eeb5fba0ba480e925a8c4ad4fccfeff2af6b4df7b76fbd9f14b78bce1ee7dce85a91f0ea8f3a61f3",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/wdat_wdt.ko"
	);
}
static void svir_269(void) 
{
	svi_reg(&(tinfoil.validation_items[268]),
	        "febc1ea170deeb62a62137070c09306301a2e75c237fe457a22c0e16867eb191c34861bab8acdf101c60259f6b1c493b633052750e1c7f8ddc66926a1203e33f",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/w83977f_wdt.ko"
	);
}
static void svir_270(void) 
{
	svi_reg(&(tinfoil.validation_items[269]),
	        "cf759ee05a97aae881ce3245f4956489c821aa06fa106ba313edc289af41e6f0a3165ca214447ad06e36c799c4f846c535a0b420c49bd6d0d7eb79ded601d8d3",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/w83877f_wdt.ko"
	);
}
static void svir_271(void) 
{
	svi_reg(&(tinfoil.validation_items[270]),
	        "d7354ece747c69b34db2ecede40031be20c88d770d6daecede42e7bead979018dbcb2a0cf8e98899929dbcf2481f6b186fefa42e7aa1c6572db02055f0358917",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/w83627hf_wdt.ko"
	);
}
static void svir_272(void) 
{
	svi_reg(&(tinfoil.validation_items[271]),
	        "adbdfb6801a423707a38b9a2327d851ad91277c5360b1ec3699922f788f9a4c36d75429b2a32c9e2265f5a888b462f072e25b5bf7c2aacbcf0cbc6773d6b2746",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/via_wdt.ko"
	);
}
static void svir_273(void) 
{
	svi_reg(&(tinfoil.validation_items[272]),
	        "2721534094426841a1e09e37aac21285ccc7125c4033de07a3e2668dc57e2872f554e9aa4550535130e2cac1c192791869c5eea4b05ea5a5f94911cba641a733",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/tqmx86_wdt.ko"
	);
}
static void svir_274(void) 
{
	svi_reg(&(tinfoil.validation_items[273]),
	        "78a708d0c69cdd496dfd462b05c7e83d85895733a77596f6680535a2133e4d4d44be9f53d30e81914d2036f202993e83cde6756cb07adb37c2bfc0c4c98514ab",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/sp5100_tco.ko"
	);
}
static void svir_275(void) 
{
	svi_reg(&(tinfoil.validation_items[274]),
	        "a5f7db44897645c24770d583dce328e6f6d744822a2846c6c7c3ca40f78129fdb097724717dc57e824ce34602ea880b9eebf2553c0bf4cf7803d29b3b8e98142",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/softdog.ko"
	);
}
static void svir_276(void) 
{
	svi_reg(&(tinfoil.validation_items[275]),
	        "f923a9a7ee9371e0a28b0d36865c173fc37cdd2f67e22a543b4e236ce1674ee42969e9170f32d9605c7814474b2e6d6e224712e6c0c816eea017a140b56ce91c",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/sch311x_wdt.ko"
	);
}
static void svir_277(void) 
{
	svi_reg(&(tinfoil.validation_items[276]),
	        "8ea272c5a26525a86ed19adbe483a5486c718910b1915b45cf16d3c6fd314f4940e74f74b1061b025cb81db804f16ad972daa2b958e9a8cc30f8f93900b3328f",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/sbc_fitpc2_wdt.ko"
	);
}
static void svir_278(void) 
{
	svi_reg(&(tinfoil.validation_items[277]),
	        "fe95740bd5c15ed78adc0e779ba15c4e8f16ad8a0432bc3be0742f0e60c6f36ac0d74eaecb89a0d630330b7ea63eafbff14d9079b88e67bcd34c659994e7daf2",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/pcwd_usb.ko"
	);
}
static void svir_279(void) 
{
	svi_reg(&(tinfoil.validation_items[278]),
	        "55d237a7efd78b3aa545ae000a531f01c5aadbf4368cb4a5bb9275075e6b8785d9f2862910f731f274ebbe20b9d0cfc113e13fe84beafb7892790b821ac87b4c",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/pcwd_pci.ko"
	);
}
static void svir_280(void) 
{
	svi_reg(&(tinfoil.validation_items[279]),
	        "953e4081d73af13718a59bc73f8fc267e2c9c4447475f9fa2e21f3cb70ade01a82c25de74cba35943175f20e34df284e2591b329db6b995332c4f3edfa168258",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/nv_tco.ko"
	);
}
static void svir_281(void) 
{
	svi_reg(&(tinfoil.validation_items[280]),
	        "e950880499339b00b28e90e96c2905795feab48647809e604fc0ee5e516d913d73be3162343a22cca9eb944e526c9b9bde879a17c9a04b3e5b900b5b3b5a6963",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/nic7018_wdt.ko"
	);
}
static void svir_282(void) 
{
	svi_reg(&(tinfoil.validation_items[281]),
	        "7dd5ada2587009e888c4cefee840712767ced03146ef98a047f425bd21edabe36fe4f151039090a449b071acd6c0ce4b318568fe3bab24d0068ab0224e3b3602",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/mlx_wdt.ko"
	);
}
static void svir_283(void) 
{
	svi_reg(&(tinfoil.validation_items[282]),
	        "5532ce4cdfb066b8871739b4755a63f3d4db31a1e09a06a5541198ddd322333300e5f2aa09ce2df0c770f135349bb344a74ad4abbc0a0c9c7fa872f181c2b358",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/mei_wdt.ko"
	);
}
static void svir_284(void) 
{
	svi_reg(&(tinfoil.validation_items[283]),
	        "5a4445e606390cc98817d13eea0925aeb3efd488f09c25083aef62c9b7cfbcc27c4ae5c2e0f1245f32ba64bf7ce5b544a8f5e29278cb95a81ab781585d0ac74d",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/machzwd.ko"
	);
}
static void svir_285(void) 
{
	svi_reg(&(tinfoil.validation_items[284]),
	        "9fa7f91e5c8803e67967baad22cc08c06d0a6ac0f061d77ef5b20a7af762300a3c2bdee6cf49d1bb84aa9debb22a968bfcf98e112fff5ddf662b140183cc819d",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/it87_wdt.ko"
	);
}
static void svir_286(void) 
{
	svi_reg(&(tinfoil.validation_items[285]),
	        "a5facd814126beccc449f4a772fee1a4c18da471d4ffe502d1a293d0220cc72fbb1d97024c9d1f38317eaa4cc89088a0f6b14c33829560909f95b6312053f91b",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/it8712f_wdt.ko"
	);
}
static void svir_287(void) 
{
	svi_reg(&(tinfoil.validation_items[286]),
	        "47daf01414467d92d2daa1ba4e41c26f4ccf0b7bb87a413617ebdbce1a59ebccad0a9938ecd67258be2d740281226cbed9ee0ae64b1296c3e4508ba13903c9e7",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/ie6xx_wdt.ko"
	);
}
static void svir_288(void) 
{
	svi_reg(&(tinfoil.validation_items[287]),
	        "760afa32f3d9a3537bd08d52edd1e6aab402e2ef5aeb538d61791a5f7ab9002194a35de16e3e1575d98a9ca995b46e1fde8374e2e0b0b706986de7c0e7e565fb",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/ibmasr.ko"
	);
}
static void svir_289(void) 
{
	svi_reg(&(tinfoil.validation_items[288]),
	        "725e9f767355fbd802105bf37439dd4dea7a9ca7bb0a2117eea8af803d8e93e71abd1ce1276c5698b38789fad04e81a8ec6a8522df769db702627d5b87c17dc0",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/ib700wdt.ko"
	);
}
static void svir_290(void) 
{
	svi_reg(&(tinfoil.validation_items[289]),
	        "e7bad2c861e17462ca73708fce57f3bc0547556643fa62b2c1e6548b48f5f0ce6ce367061e5dbc293af44190c0331e49e2e692829274bb7675c66a5ff6420fc1",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/iTCO_wdt.ko"
	);
}
static void svir_291(void) 
{
	svi_reg(&(tinfoil.validation_items[290]),
	        "94bf5d66d918fabb21daeb886715cb77dbde788d0a91e76c1a1044801e41990bdb9153a6160c18b12293e6857f16da70dbe522a1b2edcc25e5451c9e5bc56ae1",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/iTCO_vendor_support.ko"
	);
}
static void svir_292(void) 
{
	svi_reg(&(tinfoil.validation_items[291]),
	        "2e2179ef01d761527062aebeee5cfbf40710ef104562d216a167573d3d61220136c9b97a365d9c1748a7735e849713281a53e978c56be9154c722831284eb8c1",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/i6300esb.ko"
	);
}
static void svir_293(void) 
{
	svi_reg(&(tinfoil.validation_items[292]),
	        "a34396b1e6c76a89bc08d6aaa3d4d82d9c7a07b7e8c4f828611669edf926dab5e9b60de9badfb4b6942acd89405572c76d3bd04b83d3fa83eb42e38eaf097655",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/hpwdt.ko"
	);
}
static void svir_294(void) 
{
	svi_reg(&(tinfoil.validation_items[293]),
	        "db7ed44be6a89bfef419202c0ce89e6b3a28190554e545a40c3d6fc0bbb4218fdad78a2e43a807a7f64aadb7e9fa691a2b72c8a253174a1eae22e3d20cf2e7fa",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/f71808e_wdt.ko"
	);
}
static void svir_295(void) 
{
	svi_reg(&(tinfoil.validation_items[294]),
	        "692fb7c057d9faf1648f71e6e338335ab58d8c2fbea994fca0cc741499814c01d647cd5dd2b0dc0d9ff910a93e21949c6ced3066ba75ca3373a5c4d4e37c9fec",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/alim7101_wdt.ko"
	);
}
static void svir_296(void) 
{
	svi_reg(&(tinfoil.validation_items[295]),
	        "99c843aa4de579e4544f5aeb43e9b1163714ec20158e80f268cccd2f6b7c7ce067c8782ea934a31f96b5fdbb1db834fdca06f76f6579680c6394bf9868f2b87a",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/alim1535_wdt.ko"
	);
}
static void svir_297(void) 
{
	svi_reg(&(tinfoil.validation_items[296]),
	        "1af46faccf540bf661fa9eca99801894909d6c7a1139d9fe57e8476b6c29c8f870c728ae709bd5089a411f7d1af93bf9e853f9a2ce732172131b770cebcc727e",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/virtio/virtio_mem.ko"
	);
}
static void svir_298(void) 
{
	svi_reg(&(tinfoil.validation_items[297]),
	        "bd48037a5ce5b94f190283b997dee48d3f42a577f9d9aae8b16e13e931b8b5a771a51660d6694e261c864788a6046eadacb8171e2ae9f234367a58d9f21377ae",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/video/backlight/lcd.ko"
	);
}
static void svir_299(void) 
{
	svi_reg(&(tinfoil.validation_items[298]),
	        "f8f4ebb20b463732309d9d48f2406f13af35a59adcc1f76ef586f781b03abd1a4bf9b988c28bb50825f695de37f7b838f0634b4a12fbc2e88a1cb6f990a1bd83",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/ucsi/ucsi_ccg.ko"
	);
}
static void svir_300(void) 
{
	svi_reg(&(tinfoil.validation_items[299]),
	        "f9d246a0f31f418f151302b34fa0ee74b8dfee0d33cae6b7eed6de6ef929043afda2e784c760863c1be22741197f3bd41b4d362fe3ba26d296ee4dc14c8e87c3",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/ucsi/ucsi_acpi.ko"
	);
}
static void svir_301(void) 
{
	svi_reg(&(tinfoil.validation_items[300]),
	        "6d739ed909e4374124c99805990cd21099f1f2f3e3febf648a41aa7e6274d5190c70015bfd776b5017c5c3bd7e732698d05ea2d1336c511a11aeb8db32b40514",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/ucsi/typec_ucsi.ko"
	);
}
static void svir_302(void) 
{
	svi_reg(&(tinfoil.validation_items[301]),
	        "cc7277083e6dac5717e615ac9b5163f431fe79a1189ec1a4bbb0bf3e8cf46abe6128a189f934f14bfdab1c59472a54f6398c83427f1c3a269c80de4bef9139d2",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/typec.ko"
	);
}
static void svir_303(void) 
{
	svi_reg(&(tinfoil.validation_items[302]),
	        "3b590df2afe4027261257b3e692ed18355636adaf12f84027b06f2aff126a2619bbe8638440604f8089a4aa173fd79207483cabed0a2daa9669eada0725f9104",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/tipd/tps6598x.ko"
	);
}
static void svir_304(void) 
{
	svi_reg(&(tinfoil.validation_items[303]),
	        "75d54f55ab331796c572c2769c1cf043347e9901a21b4aa7f457c65b57a8d517f37a0d70448d953ac42368c5e7be0060b9a62a2c021e15bd43614c5f6a0ce406",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/tcpm/typec_wcove.ko"
	);
}
static void svir_305(void) 
{
	svi_reg(&(tinfoil.validation_items[304]),
	        "6aa5c6ac6c1564593c0a40bc781c76a451c84f93da277748ecd30f6fc0299ed413911409f7b9ba32e4d2ada07bf231f977a4f0ad6922acf4596e807c6f3d85f7",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/tcpm/tcpm.ko"
	);
}
static void svir_306(void) 
{
	svi_reg(&(tinfoil.validation_items[305]),
	        "d18847d30f17a68c67bf9e0d66600c8488f72c851a1f60ece3a853a8cbe3098b4229783a56de00e619dfd28a260d377a59184368caac03bd429084b80323c929",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/tcpm/tcpci_maxim.ko"
	);
}
static void svir_307(void) 
{
	svi_reg(&(tinfoil.validation_items[306]),
	        "7bcbea22413851a8589e3ed62b3439d5475b489eb4f76d31d3c4c1022f504621a21ed22865a0c701b30c752da7d3d749e0f2e51b373a4c7679f74b59ef0c9209",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/tcpm/tcpci.ko"
	);
}
static void svir_308(void) 
{
	svi_reg(&(tinfoil.validation_items[307]),
	        "a0f5e96a6cf0f6307e0c59c448b499cdb23a358230acf642b45956e801c6c779b8c52ca892660fb75fb4519b9c9438e1b7766f902b15ef8e87e254317dd081f0",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/tcpm/fusb302.ko"
	);
}
static void svir_309(void) 
{
	svi_reg(&(tinfoil.validation_items[308]),
	        "f7353bb20c865fa650a6f5f18b7df891db56695748a8f17b66ae6ad568efa31cfbe7d19a5b6262937cb183151589cdf48d19e510415bd6842c87d3eae5fde72d",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/stusb160x.ko"
	);
}
static void svir_310(void) 
{
	svi_reg(&(tinfoil.validation_items[309]),
	        "9d334d033056b51d46f58b182fe8def9b22155ffc2cfa899c74c39e008f1fabb63e1e96baf94a9e151dc364512a76f7c1d169eef279fe23be31b4b4a77781b4e",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/mux/pi3usb30532.ko"
	);
}
static void svir_311(void) 
{
	svi_reg(&(tinfoil.validation_items[310]),
	        "414ce9e165515e320a73c47cd2828e1544a98c68a59c39020efe5cd4430b764a1796c7cf6eac26f77c97f936ffa1e7ef807b747d372b8f1cab520e076d75785e",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/mux/intel_pmc_mux.ko"
	);
}
static void svir_312(void) 
{
	svi_reg(&(tinfoil.validation_items[311]),
	        "1a65f39fa82d88ccad3727ece680a575a71439224ddc2476830bcc809313ee60ed04fd2da689b0d317f704b87b0c978a5c597f2422261a9bc2b6da66cf37dc03",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/hd3ss3220.ko"
	);
}
static void svir_313(void) 
{
	svi_reg(&(tinfoil.validation_items[312]),
	        "0fdf150017ae7effc7f8b5f1ddf36c773ee9a89b0a4f0d0a2d8c31edcb84ff0792b2088483e9cd97476baebed5fb6dddc6f6b4be62a5371810214394f4069bca",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/altmodes/typec_nvidia.ko"
	);
}
static void svir_314(void) 
{
	svi_reg(&(tinfoil.validation_items[313]),
	        "3e65fbfd52c36cfd0ecadb1a53bff3cc89331c28bcebb81435f7bc6c6036eecb032fd9c91435a47f78bb389e9126c2aef7fa47e5e0b603c82dfa20915102b71b",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/altmodes/typec_displayport.ko"
	);
}
static void svir_315(void) 
{
	svi_reg(&(tinfoil.validation_items[314]),
	        "554c568ab4ca9a2142d5924863b69effd9a3699b05537fbd69ff1d160fb68e499a09751e8e0a3ca3b972db44aba2f49c229db2105df10ba430a61cd5aa0abfa1",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/host/xhci-plat-hcd.ko"
	);
}
static void svir_316(void) 
{
	svi_reg(&(tinfoil.validation_items[315]),
	        "6251bc185fd3627b516681f71fbacc623c1bbc3379541a506d41cb7822a358b7baf01c1594d3f1af68827d0abc60ef252f19d9471c382d35872d9797b8e66489",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/tty/serial/sc16is7xx.ko"
	);
}
static void svir_317(void) 
{
	svi_reg(&(tinfoil.validation_items[316]),
	        "2c6516b3f7db351397fcf416f80f747f4c7bc199385098461016b25c549556b36b5e74dd0a6b87e0c123d0a4b34a9f148bc43761035139d72be8b73f96bdb700",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/tty/serial/jsm/jsm.ko"
	);
}
static void svir_318(void) 
{
	svi_reg(&(tinfoil.validation_items[317]),
	        "134da0b4a7cb0a368acec66124525e02b156fea0551929c45b4443d67f51877b1ad33d87e15d652cdee83b106663d035f367337cfe818beb832da21ee8ff2c70",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/tty/serial/arc_uart.ko"
	);
}
static void svir_319(void) 
{
	svi_reg(&(tinfoil.validation_items[318]),
	        "23bb97440908ff13ae7735db5604b175035a52dd1fa0dea16ab2c964b7006302ef743521dcf862767dcaf6d924804da0b46b62a651904c017671517e3f29423a",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/tty/serial/8250/serial_cs.ko"
	);
}
static void svir_320(void) 
{
	svi_reg(&(tinfoil.validation_items[319]),
	        "07382e01f8e5b50c4efe8fc1a236c287029ef7c58102d17a1de64168d555c8f7713042ca7fd4a22698134b4797c9150a1e6f624014cd9c93971e5956792949a1",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/tty/serial/8250/8250_exar.ko"
	);
}
static void svir_321(void) 
{
	svi_reg(&(tinfoil.validation_items[320]),
	        "fec327604da6e8f91189f32525fe949016577470ad56b128a9b4ab7e38fa56206c0563a6205f043ec36071eec426e2732ee0d4ea312ae4e4f0f2188830228069",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/scsi/virtio_scsi.ko"
	);
}
static void svir_322(void) 
{
	svi_reg(&(tinfoil.validation_items[321]),
	        "8dc92b738aa3730dba663c2f2db70f2f57ed02d09baa306dba4194074fa863b665b9af471c1596c536a62a740e2e8dc3cd6d82f5df68c4033d0dd6f9509dc11d",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/platform/x86/wmi.ko"
	);
}
static void svir_323(void) 
{
	svi_reg(&(tinfoil.validation_items[322]),
	        "73bef52e7731c15f309b69336cd0d48c23f3a37c59da68f02a987104ee01f77bcc32aa9328ba3438cf82b1c55e2fe476de8847bf7842d67135e8aba87fb7d301",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/platform/x86/asus-wmi.ko"
	);
}
static void svir_324(void) 
{
	svi_reg(&(tinfoil.validation_items[323]),
	        "577a439bc0fcab448c2265890ce3e1c0dece3c88f71c385b72f1b1d28d6bd4177f9296a94200501d3ec187b9760db451107ae0a84e2a72864c8759e856719d45",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/platform/surface/aggregator/surface_aggregator.ko"
	);
}
static void svir_325(void) 
{
	svi_reg(&(tinfoil.validation_items[324]),
	        "c46d46f86c2ab5c26aaea198bb4404f0b79b054b6190c252df022ab138420fb829920941b5ee47f196ea98d6151fddec5bed617c7fdc775e763239191b159bca",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-tigerlake.ko"
	);
}
static void svir_326(void) 
{
	svi_reg(&(tinfoil.validation_items[325]),
	        "875341ec2d5cad28bc0a4f8d022027b8c3fb98c7b2c1e7a39fb262bf8315a09433c52823b7399073988b4d04456978e15ab7ccf88cc009fd8aa03d0ed15f7da5",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-sunrisepoint.ko"
	);
}
static void svir_327(void) 
{
	svi_reg(&(tinfoil.validation_items[326]),
	        "b632f7c77badd0bd123fd7e0c2b02160e5e6e6ca6075b8eecea644c79a4e8954a4e7177a410eb97d71b4d5b8492e0a2e586a7e4b8ffb40e72e0b07751e032123",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-lynxpoint.ko"
	);
}
static void svir_328(void) 
{
	svi_reg(&(tinfoil.validation_items[327]),
	        "8b144c88a0909f14000fcd1be5b768e98665c4fd9258db4c3f6f33b1e2795c2d087e948f9ba71e65bf3b53d918b4b7975c33fce492dd07f738057b49e6a5b456",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-lewisburg.ko"
	);
}
static void svir_329(void) 
{
	svi_reg(&(tinfoil.validation_items[328]),
	        "42217e708a12081f10d48c2276e3ed88c8012cdc0e57451530705b9685ff32f08f88a1d17be9942974b54e890df47e880c3f24512df114149ba1df3801b106c1",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-lakefield.ko"
	);
}
static void svir_330(void) 
{
	svi_reg(&(tinfoil.validation_items[329]),
	        "8a99be1f8ae7fe1b594df47b9fb925cf07b260ca55ecc73bfd0771568f5c90b20347fd05dad6953faf4e2aff930065fb9efa91c78eb8550dc6d68a947cad68e7",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-jasperlake.ko"
	);
}
static void svir_331(void) 
{
	svi_reg(&(tinfoil.validation_items[330]),
	        "07bc2028748163afd7e0c2e3319d7b35dd20c441e8f3bc3c6dea1375d5151621b99661e277e979cbf70abf41f3ece2bbc08feeafb55ffe059cb81dfa6b183e1e",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-icelake.ko"
	);
}
static void svir_332(void) 
{
	svi_reg(&(tinfoil.validation_items[331]),
	        "79293f21632be2a02ebb0f886dfc6ddaf0021abd4f2b7510e6d50e144ac6a3b24cd1c303a405c0a991f59917740d5bc1acbcd4a3814c62a641ff7a914ab73c14",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-geminilake.ko"
	);
}
static void svir_333(void) 
{
	svi_reg(&(tinfoil.validation_items[332]),
	        "3abbe1ad89e9308b368ed7bfddc2c121a3f029a0d2fd1f8a5a6015c0cf59076f021237b80578283e334d711968b853d84cc5be6fcb27cece6aa4c5238378ef66",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-emmitsburg.ko"
	);
}
static void svir_334(void) 
{
	svi_reg(&(tinfoil.validation_items[333]),
	        "6362f7cd819df4f6c06ca42e6bf45f165cd6dcebfb65f4a1b9765b46e51740b37e117e4a7396762c82264bda4234e8f4b6aba364498c8b616396a02dc2edfe99",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-elkhartlake.ko"
	);
}
static void svir_335(void) 
{
	svi_reg(&(tinfoil.validation_items[334]),
	        "059db3945677a29988cdef78a118ea3f2eae169e1619b024ee2d221f557b4e59c30fd0e721ec938fb9c9676eb7f3d476ace5289aceeb5992d06fc580378a71fb",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-denverton.ko"
	);
}
static void svir_336(void) 
{
	svi_reg(&(tinfoil.validation_items[335]),
	        "682a6158eade10481d4f85e0bce6d7cda9987c7e69592ed305e0db42bdd553de120647e05a8d46e4a1eb50d13b5bb5558b656be3f1ac8c26fae0404624bf4dd0",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-cedarfork.ko"
	);
}
static void svir_337(void) 
{
	svi_reg(&(tinfoil.validation_items[336]),
	        "eaac1f58c1548c6815da56a995453e5923540294ef3907618f809ef9c743bd08b2d8a5c326e2b4150543c8a2f540bb9382bbda300db3b7103388cd843edcfc2b",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-cannonlake.ko"
	);
}
static void svir_338(void) 
{
	svi_reg(&(tinfoil.validation_items[337]),
	        "a2b6abf848a89e8032810c7d352bde8cc2bdfb543422d259ee315500be3e04dc6c48ae11d471bfed8d46e0dd3078e1f7ee441ca72acbf36e9c65e331eb390cfc",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-broxton.ko"
	);
}
static void svir_339(void) 
{
	svi_reg(&(tinfoil.validation_items[338]),
	        "ea5a8b0cd04685a0bd8628892e2794588b62110d5d0b5fc2f374f7309906f645e2b3184fee8a3de86bcee5be71ea0ec3d5f7f9bc2580395e280c2c32d3674275",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-alderlake.ko"
	);
}
static void svir_340(void) 
{
	svi_reg(&(tinfoil.validation_items[339]),
	        "1f36f9bee8c13d4bbb1878d8c7245c6348488e1fd07a28e4d3d93dbb75c4698bdc817269035cad31d1afc31d37803fb9a51f3c0712be72eb117d88f769d7aa67",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pci/controller/vmd.ko"
	);
}
static void svir_341(void) 
{
	svi_reg(&(tinfoil.validation_items[340]),
	        "1ecd18f6233adb42809b943196aa73f68087e4c8855852a886095100fcb8fa3bdcde96060474c320241a2b958a50432dcf86fdb440b89c77b5930e9221c6a795",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pci/controller/pci-hyperv.ko"
	);
}
static void svir_342(void) 
{
	svi_reg(&(tinfoil.validation_items[341]),
	        "9dd8a85346d52d42c17d65c55bf84106076fba09be05f9b396af3fb00a39df510ba54100fa229e1761fdc048bba05ac422d7b88f48dd4f9c115c18861c195d69",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pci/controller/pci-hyperv-intf.ko"
	);
}
static void svir_343(void) 
{
	svi_reg(&(tinfoil.validation_items[342]),
	        "5a03ea316d1f9e1fa1a8fc80e561f3a24c2285fb09942485636f73dffa77255169a1b60abfe39a658579e1b0c73c94a3028a4f4ba9a57843ae08dc3b6f63b1cb",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/nvdimm/libnvdimm.ko"
	);
}
static void svir_344(void) 
{
	svi_reg(&(tinfoil.validation_items[343]),
	        "7600a39bbf4cb545e0149506d4bd72c350c736b6d57c726b92fcf9a1f1fa83a60f9021927623fb67057d3ebba991729acf613a67723f2d5c835e762bbfe2461f",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/net/virtio_net.ko"
	);
}
static void svir_345(void) 
{
	svi_reg(&(tinfoil.validation_items[344]),
	        "48ef0135a0b5e7f782c6c50e22be8a9322f4723b2cfadea57f1ac53b04ef57dab94a05f1782ac63358a56055f5175ab86ad5b7a703e79aedf0ac1c02b0525ba2",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/net/net_failover.ko"
	);
}
static void svir_346(void) 
{
	svi_reg(&(tinfoil.validation_items[345]),
	        "d5a745fe99426702a1a79b9e0551a6a3bbd1f5ddefbb8f95e8206d0a8ad3011efc83a166378ded59b19c8bd814ba267fe3612981c3575f7cc95fcf6a86b86824",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/net/mii.ko"
	);
}
static void svir_347(void) 
{
	svi_reg(&(tinfoil.validation_items[346]),
	        "d87dfdf9d80a7cf58597c2cf8192b3527f76a8101acce2971ddf3b452f78fea203aeeafb75581a886a2d61c1af7923f2a904b056d547f3777a31994d0d9c8b8c",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/net/ethernet/realtek/8139cp.ko"
	);
}
static void svir_348(void) 
{
	svi_reg(&(tinfoil.validation_items[347]),
	        "cad2343639925927e46fc50a708722c60d5af81663b76668c5f8f909d6cbb9b0ab8ea7835db2a89d3430dd6fc0d07163fa157ef10a24ba1d8450be58d97be2b5",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/net/ethernet/intel/e1000/e1000.ko"
	);
}
static void svir_349(void) 
{
	svi_reg(&(tinfoil.validation_items[348]),
	        "0085c214dd4299f46e76a56b26a436038216d6db0d7088a14f02f9df415ea05612523a0ef93d2bfbaca46aadd47fec5de6e8ac1ba8cbe164bd057e659ae4b0e6",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/net/ethernet/intel/e100.ko"
	);
}
static void svir_350(void) 
{
	svi_reg(&(tinfoil.validation_items[349]),
	        "889846c87ff2e0d5d4f870865f008b3b7739f1534655f3f3786be9fb247e11d2b9667b8873e6c4f77347a4e31e24b58322e7cb55207518c9ff1f45c874660ce9",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/net/ethernet/amd/pcnet32.ko"
	);
}
static void svir_351(void) 
{
	svi_reg(&(tinfoil.validation_items[350]),
	        "c9b7a6464acfbd9a81909dcdf297fc9bb5ec858e1bb223f7f9bc603a3a22d95f8cc07e37ff415e813113305768394849928950050957d8b09643a9bfb043753e",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/net/ethernet/8390/ne2k-pci.ko"
	);
}
static void svir_352(void) 
{
	svi_reg(&(tinfoil.validation_items[351]),
	        "540ca827cda6dc66f7cb6060cf1dc5413f133372d5f9d0cf3a5f099831744ec6421bfb8067c08e1525781519734672bc3f560a715a97f52133e51be496ec1d97",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/net/ethernet/8390/8390.ko"
	);
}
static void svir_353(void) 
{
	svi_reg(&(tinfoil.validation_items[352]),
	        "5dc111d90cfbf5430f3c77bddf70489ebff0f922f2c37e83e118bf9b529f0ab45944d6431342025cbb0e51bffab0bf4e823b307af4589a4020045a5fb7410c36",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/misc/mei/mei.ko"
	);
}
static void svir_354(void) 
{
	svi_reg(&(tinfoil.validation_items[353]),
	        "2928d1f9be367f2a77d6247220e4c4f1895e5422614ffc3c7791b2e3c8106ffd3d10ced7cb05b2dc9fd88a9bc87dc66adc59c6616ff88327f0651c0fdbc21e5d",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/mfd/intel_pmc_bxt.ko"
	);
}
static void svir_355(void) 
{
	svi_reg(&(tinfoil.validation_items[354]),
	        "ec7529bcf4b55149f67084fe9e2560cd8b3e3ac303013780b73788040756da8fd761b34b1e9185d984e29d45d4cff9dd32e0d30c357f40897acebaea28dfdeaa",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/media/cec/core/cec.ko"
	);
}
static void svir_356(void) 
{
	svi_reg(&(tinfoil.validation_items[355]),
	        "cb282764666712fe7f7644f9fb0ca2619a2a7aef96ee87cff7ea7f8d582af0ceb639512734102b471bfa65fac1eb3ceecb7aa95175bf4a817a5c7ba0791a261a",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/sparse-keymap.ko"
	);
}
static void svir_357(void) 
{
	svi_reg(&(tinfoil.validation_items[356]),
	        "2c4255c6c35d5e7fc0e1a9fe604c387ed5093bedcd12ebe74c1c26515bdd2be530ad947b4ec1b20ca889080d22b7bfb6ed51633b8ad26d47ddc4e9a7c274ab28",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/serio/serport.ko"
	);
}
static void svir_358(void) 
{
	svi_reg(&(tinfoil.validation_items[357]),
	        "4e9d1c4182cf16f6128c4015421fee9a82f3b4d213dc97a1c9b2cdfbba08612695b7d3dd39d700ce58b38416995f522b4716b6567cb90a63c7180da883fb4319",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/serio/serio_raw.ko"
	);
}
static void svir_359(void) 
{
	svi_reg(&(tinfoil.validation_items[358]),
	        "058c191775effaddc391eec9a72e0cca5bb4be0ba196a42f4449420f2b1034d808249ddb87b1a3cced268f301adf5dd44d73b65215e5724fc4c12e6e1fd84f60",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/serio/hyperv-keyboard.ko"
	);
}
static void svir_360(void) 
{
	svi_reg(&(tinfoil.validation_items[359]),
	        "c43f1ee8a2e11842efd22bea7cd6e376a170903ea8d23ef42bed2831aa67cf81527cb064a3670cac7997b9bbceb60d08a02e8a83e362e6314d0fde2c7614270e",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/serio/arc_ps2.ko"
	);
}
static void svir_361(void) 
{
	svi_reg(&(tinfoil.validation_items[360]),
	        "f03ee3b5c09d0a9beaa3255ce9dac348baaad61808e5b2309b3116b2290927455a3d3606bee1482b7da5f401a5015a9b8ba842abcd5964e7ab68465684c63e00",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/serio/altera_ps2.ko"
	);
}
static void svir_362(void) 
{
	svi_reg(&(tinfoil.validation_items[361]),
	        "ea3a647bbe4cdda4d73ea0631f3e02e60fba61e3d8abb43532cf540bfd44b7d5f2f90ea38a5ee68e42589d8e666fc6139da44aaa2876b9dcfbc6535a6b463e76",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/rmi4/rmi_core.ko"
	);
}
static void svir_363(void) 
{
	svi_reg(&(tinfoil.validation_items[362]),
	        "5168fe8b96694a8c802a64c55660446756b56d46e27a7c709bd4fdf66bd415d7d654945ded873f146ea3f4e618e320c73b52123e29c1ec83e07f90c33615a8ae",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/keyboard/tm2-touchkey.ko"
	);
}
static void svir_364(void) 
{
	svi_reg(&(tinfoil.validation_items[363]),
	        "d5ff9f9ecf0a73030aa6dd6b675987835fa7dd7cfcd928c2cb3b7e07274730519e3cc1f311538429c2c1d5ac993eba7d9565eb781a4ef55c148b0d6f5e8851e7",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/keyboard/qt1070.ko"
	);
}
static void svir_365(void) 
{
	svi_reg(&(tinfoil.validation_items[364]),
	        "beeb459cab7a751b0bfc8b4c84c69d713d78e96a27ad98a8ab96c673efbc937974d614a7704f91a8ba1d6547cc494fff84c1fa50606dec4826429e6f77d60d3c",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/keyboard/qt1050.ko"
	);
}
static void svir_366(void) 
{
	svi_reg(&(tinfoil.validation_items[365]),
	        "607cee5a644792a0b027d8da01a2dc82506e8c726193412a4086e0522fcc0f4b77d6421d927da3d6e6455b90ba2f5478da1a209579f3e7bdb1b557649e54d9da",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/keyboard/gpio_keys_polled.ko"
	);
}
static void svir_367(void) 
{
	svi_reg(&(tinfoil.validation_items[366]),
	        "ea15885c017884ee2d1849d841e94a6efac344b8400600b49a915e28c1a463168708ab81bc0b8028736b47b37ed55660dc4f1bdff2afc646106e00b84ac649af",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/keyboard/gpio_keys.ko"
	);
}
static void svir_368(void) 
{
	svi_reg(&(tinfoil.validation_items[367]),
	        "f5a7e13311555febd5cd4396a6cca44820faff7a079fec9aa23e402844c6249fb29d6a2f3ab4b3b1a7d79c6e0bb6a842b2db1cbe4f83f9e979951b5c543c58b6",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/keyboard/applespi.ko"
	);
}
static void svir_369(void) 
{
	svi_reg(&(tinfoil.validation_items[368]),
	        "26cf02edb752683c883899d7af39d27e13fe6d62d107f3efc0db4adc8838262373e6995eb3f344eb1b8409599877d6289cdfe521dc7edf7686348fa961f68390",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/ff-memless.ko"
	);
}
static void svir_370(void) 
{
	svi_reg(&(tinfoil.validation_items[369]),
	        "9b894000edb16dcc242e44a8f73d7a5da773b38f7ef445e64d702b45f68625fad4e73ee46268eb7eeacd615fb394c48ac9690ea89aba35f5f13d881cfcf24aad",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hv/hv_vmbus.ko"
	);
}
static void svir_371(void) 
{
	svi_reg(&(tinfoil.validation_items[370]),
	        "bf5b6de47beef731968b9587b25055154e70ebe5a8338dcd7143efc25f50a7a34cf13f32d918eb69939dc152d2a9d2aeb2dc87d0d244e428d1df5c7c72d8aa97",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/wacom.ko"
	);
}
static void svir_372(void) 
{
	svi_reg(&(tinfoil.validation_items[371]),
	        "24dc7b5aacdf436304a881c4f895073a23b3f7acf230ee67b8d0884ca6d053eb572b45f00bb4dad36d8f99b9b59be35d46759990fc6df5d539a14cbf52730279",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/uhid.ko"
	);
}
static void svir_373(void) 
{
	svi_reg(&(tinfoil.validation_items[372]),
	        "7e0b0643fffeff0670cc550ac076e95ab62c9f7188bd69733c71e4a9f8b69a0392b5db220b1e2a03174593504392c146788f53a0b451e134ebe1c12ef7dc1e18",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/surface-hid/surface_kbd.ko"
	);
}
static void svir_374(void) 
{
	svi_reg(&(tinfoil.validation_items[373]),
	        "291cf528fdcc1010d146cdc0d063e6a31bed2fb080517796c4ce2214e4d38671c7716d314d207d1cff5e60b773b4c108d66aa265f9c9653480abd3716952f542",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/surface-hid/surface_hid_core.ko"
	);
}
static void svir_375(void) 
{
	svi_reg(&(tinfoil.validation_items[374]),
	        "60970d2d74211f019f2c2227bf9cc53d794026ee88b9c99f7f772ddea951f8ca1d9a834f9eeacf859d91bce328292e9e6f2085f4ca266e879f5a72d24671ea99",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/surface-hid/surface_hid.ko"
	);
}
static void svir_376(void) 
{
	svi_reg(&(tinfoil.validation_items[375]),
	        "529f29c022e77c70aba874a87e9806f64d20924aab487e81fd49b1bab4c54614639b0db3d51ae127c95f024afc2182231e921f30557acdf663d07f562f47a036",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/intel-ish-hid/intel-ishtp.ko"
	);
}
static void svir_377(void) 
{
	svi_reg(&(tinfoil.validation_items[376]),
	        "bbd4ee8885930750d46809a11efcd96b3b5e39a1ff847885e9491fdaefb63f7e5ac620534f237881b6520cf8326fcf263e45e4d7eb1fb3f0549f48592a9b1eaa",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/intel-ish-hid/intel-ishtp-loader.ko"
	);
}
static void svir_378(void) 
{
	svi_reg(&(tinfoil.validation_items[377]),
	        "f2d11541715bb94d427ac962ee455c6a962506c348ddfb2cb007aa908c9272bf5b64996145bb6b9b3f38417e4595ed76a71f0f6e9fef487c22146ff278e66548",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/intel-ish-hid/intel-ishtp-hid.ko"
	);
}
static void svir_379(void) 
{
	svi_reg(&(tinfoil.validation_items[378]),
	        "7f13185bfe546409cce6936064cda2822d22c2bdda0dd7d00a6177b1c26db1359f5e0e0a94841ebd15771ded8d9d312ede1d5cbdcb0d92395c7377290e2dc541",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/intel-ish-hid/intel-ish-ipc.ko"
	);
}
static void svir_380(void) 
{
	svi_reg(&(tinfoil.validation_items[379]),
	        "b768f26dfac424c44b167d65e5eed115bde9148d773d9e6b14ca408cfaceb11c852b3051cb5ab3892ff62238c1f313af6c01ef2766aa0c4437db7e4512536092",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/i2c-hid/i2c-hid.ko"
	);
}
static void svir_381(void) 
{
	svi_reg(&(tinfoil.validation_items[380]),
	        "ce9f2e7b91c58ff4feadd09fa9341c86f6c14f0e6cbe0fdf6920363e1a9b50b3434dc6f8439c2cf7150a83667355936a16e187c3bbacc14dae63446ddc03f3e0",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/i2c-hid/i2c-hid-acpi.ko"
	);
}
static void svir_382(void) 
{
	svi_reg(&(tinfoil.validation_items[381]),
	        "d58f84369d1ca4a986e8972300760f84bb7f2ce2c894cad2f20958ef050b86ce2693597d33b2095530aba90bc50031ed87a90f81b5a8dd4d64cbe41abad57740",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-zydacron.ko"
	);
}
static void svir_383(void) 
{
	svi_reg(&(tinfoil.validation_items[382]),
	        "0bde65a03b313c73d55cb407cc6f9f4dd9b1ded08c98439f843b377f2b5ad568fd05ae467d43bc1c6fcba2ed49c1d0490f150b42858f412ab035521939a8c1e5",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-zpff.ko"
	);
}
static void svir_384(void) 
{
	svi_reg(&(tinfoil.validation_items[383]),
	        "e9e54429a2734d019b626db77b5b2e49a8e1add3ccbd19b192ba3e938b9d1921c3e67d1ceb3316bbb88da2a3b5497a4f8cd08c9695c9da287c142f818ea9c01a",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-xinmo.ko"
	);
}
static void svir_385(void) 
{
	svi_reg(&(tinfoil.validation_items[384]),
	        "94096b054a6a9d6f4b9e788b7205dd8646821a2dc2b4f69184b0ba1a93e12b4ae21ad7189af301578177b9e2aa755695b96ba87521087ebcebaa1f98ceb34e25",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-wiimote.ko"
	);
}
static void svir_386(void) 
{
	svi_reg(&(tinfoil.validation_items[385]),
	        "7d36ba41fba506d81d3c0bbc3e6806ee313235849c717d8f2cab21efe71ae984d726787ec51e53fc390fc17e45b3ec7ea2abf607bd97aa2b631efd1d6a275811",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-waltop.ko"
	);
}
static void svir_387(void) 
{
	svi_reg(&(tinfoil.validation_items[386]),
	        "796f513a7fc4cdc11c9c62c4e0bacab9f0ca8ef37c307595dc51fdb1a64a75afc24f848a45d9c19e60f6618ceae08ae6a6545daa76b689bfb633a4ad46995f3b",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-vivaldi.ko"
	);
}
static void svir_388(void) 
{
	svi_reg(&(tinfoil.validation_items[387]),
	        "4a3d654e2c32e53ad9d139f425bfec4369940f6c9a2bafadf4ee985ac1f2d6f8379799749f6b56d93f59ab0edfebe5b71e850452029631493822366b9f0d73d1",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-viewsonic.ko"
	);
}
static void svir_389(void) 
{
	svi_reg(&(tinfoil.validation_items[388]),
	        "57fd22069da243f568c11fe5f3dbccb549e3219779964713640016d8f78f7a636c98207bbd430896e0745e4b8cc6f5bb0230c96d61a67ff0dac00de69f36ce09",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-udraw-ps3.ko"
	);
}
static void svir_390(void) 
{
	svi_reg(&(tinfoil.validation_items[389]),
	        "dda330b7639a77ce3654c945d698bcfeedf39740159879c7bd85a11cee0542f652061965ac0cdbe56e1aef878b426560b2f8884c43e8816cf4f925c71760a108",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-uclogic.ko"
	);
}
static void svir_391(void) 
{
	svi_reg(&(tinfoil.validation_items[390]),
	        "a449a1e54f5733fb40c682c1fbca092b83ad175a0ddf99070f7048d40f7133f3099231d7f12e99d56f10ed60651b20dd038b4cc90899d29c50c37f1e7b96ebb0",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-u2fzero.ko"
	);
}
static void svir_392(void) 
{
	svi_reg(&(tinfoil.validation_items[391]),
	        "91ac0f18deaeea6bbac3ead7ae024040529588f807f07b35d3140ae1ca241dcac1a50d61043fa542234acac8d343d3c81a6b2b3765a994b0d30594a54903bb40",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-twinhan.ko"
	);
}
static void svir_393(void) 
{
	svi_reg(&(tinfoil.validation_items[392]),
	        "65d0634c65662ab55e81e89855eee83330efde6fc6bed0d64166833599eef2e5e36471d3e02ffc48c7957bab0ebd3b0567cf07f980facd90c7958e446531dd3c",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-topseed.ko"
	);
}
static void svir_394(void) 
{
	svi_reg(&(tinfoil.validation_items[393]),
	        "e4bb0fb1f1d6bd6d5d92783654ab25505075ecca0592bb7dc9f6dd7f98890ca08acedc408e5916f99411d2fb178ff202a6c21b4fa37717b78b84ddff86fb2dc1",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-tmff.ko"
	);
}
static void svir_395(void) 
{
	svi_reg(&(tinfoil.validation_items[394]),
	        "a736bef598fe58edd2f372dbb19210a6cda3532f641ab629e3470a42a4d930ed1ce148c459dec1bbeefcaf28d529eb285541a24e9d0662e8614d59c58e925ba4",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-tivo.ko"
	);
}
static void svir_396(void) 
{
	svi_reg(&(tinfoil.validation_items[395]),
	        "567eada90917351a3977f418c589f2e38938037cc5a483daf5627d4aff02d3fc776f8db188e3e702fedc80196971e5ba91ed1519671b8981fe49e3bc1fc7a1a0",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-thrustmaster.ko"
	);
}
static void svir_397(void) 
{
	svi_reg(&(tinfoil.validation_items[396]),
	        "30cce9151babe71c9e48637e5c5fe5f63a75cc2e85cd2b8065fc1fdaf9520a4993456f88ccc9cdd4df0fc33266bda36c39f7015b805f7bce1af66e1c83a3f618",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-sunplus.ko"
	);
}
static void svir_398(void) 
{
	svi_reg(&(tinfoil.validation_items[397]),
	        "be838b56aae3207c076519cafc62c75f18247fce2f185e2fc5b218413e866cff32d5922d8fa2c20225b301ab9fb998cc7d58b7c0d9fb05ec73599a48d76448ff",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-steelseries.ko"
	);
}
static void svir_399(void) 
{
	svi_reg(&(tinfoil.validation_items[398]),
	        "bc49c3d61a4dc8ed65616432884d07bb028b437e9667f291c0e2c2a35bd1aa758f95a8bbb289b0bce3223a87b5f1fb3ed9b218cfa476d02c7b5b0d41f4f62a40",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-steam.ko"
	);
}
static void svir_400(void) 
{
	svi_reg(&(tinfoil.validation_items[399]),
	        "a6f6f3dd2f0cd744a17c294f299a2804fc3cd16cdf8af01b621fc0c017a35f5f616d4aa4ae3577f2b46069505059f026b0b22d8e0c7649c1eb56a76e01790da1",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-speedlink.ko"
	);
}
static void svir_401(void) 
{
	svi_reg(&(tinfoil.validation_items[400]),
	        "4ea03517552418d9bcc89be1b573738d2fd3feb339055a071236f9981871fa2ff0ebe6726e3da446284c4d1326bd0358961e3f337c4668a0ee25948b1473d7e7",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-sony.ko"
	);
}
static void svir_402(void) 
{
	svi_reg(&(tinfoil.validation_items[401]),
	        "d334ed9ea6cd20e4bac7862605a871e5d56861e32216d42de4e67fa126b5fe7aaf35a364583cfa84e2491b0e7d1a1023d763ccc49601be167bedb25f920fab3f",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-sjoy.ko"
	);
}
static void svir_403(void) 
{
	svi_reg(&(tinfoil.validation_items[402]),
	        "f143c3aa607fd162ff84bfe1d78d73e80add90109ebc0e68b95cc209d5690f3c5b720a4eb9f02cb06f773a6d65aadb70db0287eb4f5f345544458b9e4fdb9af8",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-sensor-hub.ko"
	);
}
static void svir_404(void) 
{
	svi_reg(&(tinfoil.validation_items[403]),
	        "7ae058ee30bca3291ce2f757b10fb4a47d36a9ea4f93e169ea875337b7275dbd6d27dcfb2f161a6ebef003f84333e3a45c55faedd1b983e09b0a4964c9e29a57",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-semitek.ko"
	);
}
static void svir_405(void) 
{
	svi_reg(&(tinfoil.validation_items[404]),
	        "06c4966a191791aff21d558ec3df2dbb53bec23b59d942a3ba792d4f39f4f26311d10bd5b10872c5ecce9080a7d610399c8b99946992c8dfe996873c82d4e152",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-samsung.ko"
	);
}
static void svir_406(void) 
{
	svi_reg(&(tinfoil.validation_items[405]),
	        "68638b1f25240d78b481722dba68a54fcce33e28c9a00c8dca56452babe952ac0657ca8aa4b4d86d61ceed8bef967aae01e623c272a7292cc0bdae9da92753a8",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-saitek.ko"
	);
}
static void svir_407(void) 
{
	svi_reg(&(tinfoil.validation_items[406]),
	        "ee5f36bf53e63a72ec85101abc0b45367a9f6e3b87e565a195f8125fc1dfe18455d414fe92d3f529b036a0aa0f317f7b075ab43008f37ddeb95987ffa43191af",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat.ko"
	);
}
static void svir_408(void) 
{
	svi_reg(&(tinfoil.validation_items[407]),
	        "50766ee497384c9761d16f7a290df0d487fd3eb5957347c0454b2e992bc5697a07fe3eae50dd6d03d375e2acb5157f98cc192f80e7c5d6deac001175def954c0",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-savu.ko"
	);
}
static void svir_409(void) 
{
	svi_reg(&(tinfoil.validation_items[408]),
	        "b39cca0d40161f4bbe9c292583c58955be73b0635fa02960105de59101e728e6c7c2719ca04f64c32b65ee6b0d9d3f669a23895732654ffbd0b6fabe487eae9f",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-ryos.ko"
	);
}
static void svir_410(void) 
{
	svi_reg(&(tinfoil.validation_items[409]),
	        "fdbddcccdbe28362605a1d8edd367200cb465528240b33006822f9d0fc4f5c3d1d344b0d198b490854a72502ca53a186d325fce00fa8b4a7e884fc423f2162a6",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-pyra.ko"
	);
}
static void svir_411(void) 
{
	svi_reg(&(tinfoil.validation_items[410]),
	        "1a4ac25fbf2c31e102397abf5618f0396a84bfe8fe0dccd65e3d768a73f684cd600fef98a6160e281d796a36a1be199c755302de7eaf9f008c702dc2f5fd487e",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-lua.ko"
	);
}
static void svir_412(void) 
{
	svi_reg(&(tinfoil.validation_items[411]),
	        "65022e34794ae1adc8be4e47f3765cbc7e5357e5005c63fba60d383e6ec0137fd52a76ad931c7b099df023c3f1461ac20179ad22635b851c97950a231645c7b6",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-kovaplus.ko"
	);
}
static void svir_413(void) 
{
	svi_reg(&(tinfoil.validation_items[412]),
	        "7962a93cfab4f62bf110b8e7091c5d39519b5950c2f68a9ac4ad6a6221769c64b24c77d75c998b8019672739b80b777431749330561970a239302eafee37e303",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-konepure.ko"
	);
}
static void svir_414(void) 
{
	svi_reg(&(tinfoil.validation_items[413]),
	        "17852cac612a0f4b0a89b5a1b3e9d2c5384c51195d7af5bd8d70ea1388c071e3f198d1b4db0597eadd7a68ff94b0ec74587af996db610883971b07eead5d06a4",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-koneplus.ko"
	);
}
static void svir_415(void) 
{
	svi_reg(&(tinfoil.validation_items[414]),
	        "5f2d5f0b211046247c72a9feaf45be8ad97e4207c1b6332c2af2c7e8c5ea0ed5607e69936b398cab5b6ba6de09b6370d77b3834e1325e4c5406bfaf3b327ff8d",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-kone.ko"
	);
}
static void svir_416(void) 
{
	svi_reg(&(tinfoil.validation_items[415]),
	        "8c7f7f1f261e26161f8d1c17219ef88db6e40d3e8c2f2fcc009a85b66755c1ce50381e5efc69e89b089b2f93ae1a277ff7ee7d6c0d4d745c33e18f2abce685db",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-isku.ko"
	);
}
static void svir_417(void) 
{
	svi_reg(&(tinfoil.validation_items[416]),
	        "71414a9df0eea16ee5be21f7f5cbe5c45bb4041cff9a1fd69b0e75efcc77e2d3af7348d8edeb9f3d2d13024649befb6f603aec491a59757d676620dc024fa397",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-common.ko"
	);
}
static void svir_418(void) 
{
	svi_reg(&(tinfoil.validation_items[417]),
	        "c1aee812d354612ba4a87f01ecac0610ad984bf97bdd09d2c5904990889a22d25e2d7030c0dac2beb98e9ed2e646990996f712fb40d9fdb312584e12c0bc1a4b",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-arvo.ko"
	);
}
static void svir_419(void) 
{
	svi_reg(&(tinfoil.validation_items[418]),
	        "aee9fafe2ff272442ba58b62e98d60c0fb1153b22c31d89896c93a747f390df70be158274f52baba126196208deb8e17105ccc565dc50bca2ef8485bb4359915",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-rmi.ko"
	);
}
static void svir_420(void) 
{
	svi_reg(&(tinfoil.validation_items[419]),
	        "53da8b49f938d18707d3b306709dce5474d92240e44f0268c738e25e4d0f2b3c61223954c475290a03f163cc6d1536bef7bbf791cf3f1581bbf3b03c3cd79f39",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-retrode.ko"
	);
}
static void svir_421(void) 
{
	svi_reg(&(tinfoil.validation_items[420]),
	        "4a553227a4629958e049977dd54520763805c84de6fb5d1c851039f22c9007d2b322fe473807b6cb931b1799bc431792316d8fef0958c1e78343882024611d95",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-prodikeys.ko"
	);
}
static void svir_422(void) 
{
	svi_reg(&(tinfoil.validation_items[421]),
	        "716c86234d07ccacaf59c27c38273b6fed8db8b3d2d570fdccd85d52fe79ea395567dae1dfb45399afd8a3fb222fea2d3728912278b74c86d9433c576955e9ef",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-primax.ko"
	);
}
static void svir_423(void) 
{
	svi_reg(&(tinfoil.validation_items[422]),
	        "bf87d09f203fd65b10c9b497200fa386ddc293f1cb2c97c0c2090615729ec874172dcb482367e316afcb4042fb37999679bfbdc3a9375983bc93cdf22d6ac2ac",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-playstation.ko"
	);
}
static void svir_424(void) 
{
	svi_reg(&(tinfoil.validation_items[423]),
	        "41e4fda37dfef50188bf05d35f1134e912f553097732ea91bd8038b3e99040072da5fa2ef659347b3838153244aef8ebca63ec0ebd73a832e7a8a6cc80014b00",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-plantronics.ko"
	);
}
static void svir_425(void) 
{
	svi_reg(&(tinfoil.validation_items[424]),
	        "efc25b5822aefa3435c6da8f529e3d81d87d92235a703c54faed276421f222a22efcfe01d0319dcbe1f9cee34620da3dc8ed7fdfcc3f2b56de50b58b9e8535d9",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-pl.ko"
	);
}
static void svir_426(void) 
{
	svi_reg(&(tinfoil.validation_items[425]),
	        "97a64171951d5d73fcb71d1e755812ff51b67073453824ee06c6ca1c74540d969b471620ee9fe46c1844c73d694e792d5b2255286d1becc37d4b5c30006fa4b4",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-picolcd.ko"
	);
}
static void svir_427(void) 
{
	svi_reg(&(tinfoil.validation_items[426]),
	        "04b20ef5ad08a2ca6369b308d7b498b181a6ee614e0f75e681f35868c674d820e26ffeb62818e7334cb7802fb70fe8f61b3535330383e4f88db8e5d3118db852",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-petalynx.ko"
	);
}
static void svir_428(void) 
{
	svi_reg(&(tinfoil.validation_items[427]),
	        "25cbb3abec19e9b8b97e50c27a34642636642726222728ca30a8fac09e93275bf4b0a2609aab5dc27a98bc3271aaef08d5940607b40d442dbd351046a6f74e34",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-penmount.ko"
	);
}
static void svir_429(void) 
{
	svi_reg(&(tinfoil.validation_items[428]),
	        "7f775ab64b00a83f18f02e6d9e96ac2ae89e38c0fae274b553605caf418266db6a33bacec451b890604affbd577772cc15f4f3de54a7e8a170360b9a1049e1ea",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-ortek.ko"
	);
}
static void svir_430(void) 
{
	svi_reg(&(tinfoil.validation_items[429]),
	        "e6392dabe81158e04e84cc8a85003b0f096bbffaac0e887f2a5c77cd0ef95f65d1de5436bbf41159a5225d9384c6e9620c95a7228bc0de9f223c7e46813fd10a",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-nti.ko"
	);
}
static void svir_431(void) 
{
	svi_reg(&(tinfoil.validation_items[430]),
	        "8a16df22339f77440ca1383db90aa433a28076e85d04d76da70e4aa962078241c2bc5810d6b81246a16040be2300108ed3555cc21e951e122806ed8e04e05ec2",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-multitouch.ko"
	);
}
static void svir_432(void) 
{
	svi_reg(&(tinfoil.validation_items[431]),
	        "810ee380a994616e2e75b3e94fcb5a2b2c929690c2c173c4beb99ffa18c27ed1c71f63726dcd659e5db0959e291922dceea50fe9185d19dd8652c4f1a45e3e5d",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-monterey.ko"
	);
}
static void svir_433(void) 
{
	svi_reg(&(tinfoil.validation_items[432]),
	        "d83761cf6216af7b20b2a24780fff65ffdef4d41d1900a16120036caa296efe1ce1fa7394b39728f93e18a6c9a4ba5774909c55f0f8111995fb626914372fbb3",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-microsoft.ko"
	);
}
static void svir_434(void) 
{
	svi_reg(&(tinfoil.validation_items[433]),
	        "f1c63f03d55e99fea2c9873fb135349cbfdbfeac0d00a7cd8057ecf5a5cd324c97f905cc28e0d4b9d90224b8625663dcfe7280693f2ddd7801392a38ff9e81c4",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-mf.ko"
	);
}
static void svir_435(void) 
{
	svi_reg(&(tinfoil.validation_items[434]),
	        "657727f4f9802f24d7c9780a8a426d0d701f193ebd53877ce1df8c695c4f0beafff27224249106ee7c060278e7b9ed4fea67a7ce970a870faa289309b102cf58",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-mcp2221.ko"
	);
}
static void svir_436(void) 
{
	svi_reg(&(tinfoil.validation_items[435]),
	        "c811cd529692a41823012a48198af10a1817bca5725f7bcac3c1786a3415184b9cf2bd753b773eaac4e684644c87cf316e5e21abc7c7df3d36ab2882bad6b44a",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-maltron.ko"
	);
}
static void svir_437(void) 
{
	svi_reg(&(tinfoil.validation_items[436]),
	        "c770e7217928f10e199332541bd613cd9cca185790ebff7965539a7c691d95a5d014df1e05922fd901fb213d6577640002154d7ba9883c21bc16fa4ffc0ea555",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-macally.ko"
	);
}
static void svir_438(void) 
{
	svi_reg(&(tinfoil.validation_items[437]),
	        "7792ca26929376f2c7728ee07f1f494208f25f9e6150b1622e90e2d6baeeef566ceff8fc7b9feaa73d276b3d1926bcfe09d951d3a6c029dd309300f0970f4e29",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-logitech.ko"
	);
}
static void svir_439(void) 
{
	svi_reg(&(tinfoil.validation_items[438]),
	        "77abec28f9b22c80202b8c680f4dfb9e4e07c539d02376338cc87b7b9a04b71e5dbb216206b4d1f42c80daff8e9f01924e944363d9ba7acd228427058e996f39",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-logitech-hidpp.ko"
	);
}
static void svir_440(void) 
{
	svi_reg(&(tinfoil.validation_items[439]),
	        "0d2b90268289dca5ed30f0f7c6df11e6bf96f003602d7e8cb18a5f298cbb53b8db914498a3ef864802f7f4c89a879a2e523c5b4f959622aeb8eedd5deb378c7c",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-logitech-dj.ko"
	);
}
static void svir_441(void) 
{
	svi_reg(&(tinfoil.validation_items[440]),
	        "955c5790d424676501120e41c179a0ac2f6dc49c714c35853d0f6af1b3ccce726d4dbd01254cb5475a1fb4d513b1ef8db2de2f65f9b044fc29e70a74d0876058",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-lg-g15.ko"
	);
}
static void svir_442(void) 
{
	svi_reg(&(tinfoil.validation_items[441]),
	        "57701d0c32182d70e08a14c00f984b58a7eb4116ec8b0d47e9f3b22218d0aa9b657b1d7180f75cdd70fa25d56b95fb01781fc7286489cd531a545cc99ddd9e32",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-lenovo.ko"
	);
}
static void svir_443(void) 
{
	svi_reg(&(tinfoil.validation_items[442]),
	        "8379344f1817ad262be872bc4c23b86db0593977622837200cee082e0f776b440ee07cfaeb8786b3de0a89bdc3c2d6808b3016932eb5b8febf0eb71ab2a043be",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-led.ko"
	);
}
static void svir_444(void) 
{
	svi_reg(&(tinfoil.validation_items[443]),
	        "08b2a9d1386584288bdafd70fbf15f0d1cc1d1caf527e2646222a0c8c7ec2c68d4811ef9f1cfaeb793f56d8b9dcdf3a93cc4cd15c8a9994ba0ee2574c7faf987",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-lcpower.ko"
	);
}
static void svir_445(void) 
{
	svi_reg(&(tinfoil.validation_items[444]),
	        "e9bb68f516bfdb8ec78ecd1a9df0f6a4a9257f85290437c2e4c880b7c62b44d0e2aa0ae15bd1796a990e1983d91994cbd66b10856b6116fc2a36710b403f80b2",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-kye.ko"
	);
}
static void svir_446(void) 
{
	svi_reg(&(tinfoil.validation_items[445]),
	        "a3b5497814decd5ad99715d4b4fd39fc1f90e9b148db9f5dc80ca7d6cb53cb2d668c2ea1899abe5e3dab9e967015f9670a7f61cb7b99428eab65a1bda57f7592",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-keytouch.ko"
	);
}
static void svir_447(void) 
{
	svi_reg(&(tinfoil.validation_items[446]),
	        "4ef09f3524c1f68b1dda6fa9c27af83fd2a84d257f90295221441ae40f15fd3b371e14e5593db99fc18fca8f5e4f3c66b014e5632fb8ed731809d086ab068f9b",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-kensington.ko"
	);
}
static void svir_448(void) 
{
	svi_reg(&(tinfoil.validation_items[447]),
	        "693446b4cb6553edfce6174ff1bc58101f2d3dad805879ebb0d11d28fd618bebb902f45ac803e267a6d83293be725ae10669b22a01e74d5ad54987633f3792ad",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-jabra.ko"
	);
}
static void svir_449(void) 
{
	svi_reg(&(tinfoil.validation_items[448]),
	        "8ac3d400e129f2c87e570c1d054bd280f04d2c5c59c48c7b3d8a0dec61cb3a2f9dffebd51e47f6626337550df0bb7e52a0539de4e03ed0db99c3468506c7e2a3",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-ite.ko"
	);
}
static void svir_450(void) 
{
	svi_reg(&(tinfoil.validation_items[449]),
	        "ce9a3cb156a7b188325e563a9961055274700ac629ee348f8b45289dd4b70ab008c1772f69d6bcd2cbd0da04db1b4d91d211314318b4fee654e56d4fe871a913",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-icade.ko"
	);
}
static void svir_451(void) 
{
	svi_reg(&(tinfoil.validation_items[450]),
	        "a449a18c5fd76f201580eb5017b5a3621fb3a6d4b47aea586d2484af49734f677513ef0e3d92cf5141f19f63c605e700261002ee4e96f4d119727e08114651d0",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-hyperv.ko"
	);
}
static void svir_452(void) 
{
	svi_reg(&(tinfoil.validation_items[451]),
	        "bae1ebe03f0ceb410a65a386f492557d504be3cff7a063370ab74e291dfad642e9f42fae1efa95622fa9f68eee31116b239dd2cf7aa7c2b29e331a834631dd43",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-holtekff.ko"
	);
}
static void svir_453(void) 
{
	svi_reg(&(tinfoil.validation_items[452]),
	        "11dd022d0c66ea64df662d08d068f0f65c62c50830dba86fdfcbfcee52c92c5e5eab4984913e7d5af1d9dfa98bfe49f7ef070a57a79b60d029c861c0ea7f0da5",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-holtek-mouse.ko"
	);
}
static void svir_454(void) 
{
	svi_reg(&(tinfoil.validation_items[453]),
	        "e1ec55d3e64bddd54033fcc9a9e78251d8de568950da67322e8afc36c362673fdeebde88fde9125adc1aa1c6c72d435d74057b8e2f272a37b395ae865f642b74",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-holtek-kbd.ko"
	);
}
static void svir_455(void) 
{
	svi_reg(&(tinfoil.validation_items[454]),
	        "68dad861c02a3da1ece03c0f4afca8a42b4f3c58662fde5de76c6081ca637044e59b01667468466fd6a6f0296a8254711a26e6eb871e32d513114292dfbf2431",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-gyration.ko"
	);
}
static void svir_456(void) 
{
	svi_reg(&(tinfoil.validation_items[455]),
	        "bb500c4a74e1a410d07cd16b23a4a4b21d38cf3d604b89b6c2516878ff45e53d3209252b135935b4882ac09d2c3fb592eb61cc8241a2f856cee3f1fd989d1e91",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-gt683r.ko"
	);
}
static void svir_457(void) 
{
	svi_reg(&(tinfoil.validation_items[456]),
	        "bb4b99dbc5e909071136c6b6e8fd12ec3919227b5fedead2204bdc5d79ef1e38675fbe3b890bd55babb4edc350e7014cb95dafbc453caf2bf53ac271ee8169b8",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-glorious.ko"
	);
}
static void svir_458(void) 
{
	svi_reg(&(tinfoil.validation_items[457]),
	        "b5ef5726f89ac7a7ae6391aa16e7c29d125d23b0dec9178735fdb0a3e9588a40eb1f698345ad771f2336d59067803a92fa417617bb0462410b593433d84770c9",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-gfrm.ko"
	);
}
static void svir_459(void) 
{
	svi_reg(&(tinfoil.validation_items[458]),
	        "b2804683b9d0b122a2cdf5976b58ad288bfd2b591faa25471c8c08882c0a597de30ded1cd32cd6066dcb3e23d16ef34df4a81f9417813b336958c739a0ce6a1f",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-gembird.ko"
	);
}
static void svir_460(void) 
{
	svi_reg(&(tinfoil.validation_items[459]),
	        "fef0624c3a9e0672df69068fd067f3f1ff85d1dc9895a2473b152a3483e4e07704b885923951b8a70ad54f9583fa19b9d2ef3abc6815e01d4bece04dc6dfce7a",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-gaff.ko"
	);
}
static void svir_461(void) 
{
	svi_reg(&(tinfoil.validation_items[460]),
	        "b1411bbb89f348492697f5711116f2d125c758518bbd91653bf914b7cf22692e002c6313771be40a218d360b7552538ad529e32f5cafd7b64046b0d93941d315",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-ft260.ko"
	);
}
static void svir_462(void) 
{
	svi_reg(&(tinfoil.validation_items[461]),
	        "49f410c6babd10334adfcb431e6eaf5b77a9689255848797a1f96befb9ccd8990ffad3f09f22066cd6040147e5392307deaf83441378b5db118fb6f8c5f5b47b",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-ezkey.ko"
	);
}
static void svir_463(void) 
{
	svi_reg(&(tinfoil.validation_items[462]),
	        "55042b36d3430fad945e4291154c11354185303eee3f21b66151340ac6f5239fdfe20b86123a37e79799e418156e6ea35fc1ff167d327697fe07bd09f989607b",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-emsff.ko"
	);
}
static void svir_464(void) 
{
	svi_reg(&(tinfoil.validation_items[463]),
	        "482cc1743cdd5a87e6f5e42988039b1239c8290ff44f361e5962fbeebaa5ee6c425d68fb1a8b92d1abc2329d65895e4b0aa9762916e57e0407844b41139bfa16",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-elo.ko"
	);
}
static void svir_465(void) 
{
	svi_reg(&(tinfoil.validation_items[464]),
	        "e50b8f1203dc1dda4cbaa101abccafee246953dc7cdc27394ef77ccf4033ea01c13b2e0216c890cb9e98facfa65ee59521352241f9c9bd21f95021ea7e191209",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-elecom.ko"
	);
}
static void svir_466(void) 
{
	svi_reg(&(tinfoil.validation_items[465]),
	        "61a44adcc4a6677aaf3c4a7182cd19303481e3da449b718a45e89fe261f114338e267f9c808334119ffaa31dbab3ad3c5c7018a4d6820f3107ce7c0563a341d2",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-elan.ko"
	);
}
static void svir_467(void) 
{
	svi_reg(&(tinfoil.validation_items[466]),
	        "3aa902672b40290ea038c3f8df5f5cce1844a4d1863d8b18f7a221fad7e577dee0d1b2f01685b714f7f9e4421ca9dc9a9b96be900b3225449309eb07ee8567da",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-dr.ko"
	);
}
static void svir_468(void) 
{
	svi_reg(&(tinfoil.validation_items[467]),
	        "239cb84232f2b3d2f61ad607d438c18a86395d4228c9080d54323c3a62da26bf9bcf17be81979bd5068c8598142273694b5d23271946de3dbc94ed3ca5678112",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-cypress.ko"
	);
}
static void svir_469(void) 
{
	svi_reg(&(tinfoil.validation_items[468]),
	        "d19949490b18b30f16842800fcdca0fc936d31020fe9958169b3abd5bbcf68bdc8f8055c17feb5cc5f11dc2567690a6c76fbc3b678b99c27d1559fa4e0d57fa9",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-creative-sb0540.ko"
	);
}
static void svir_470(void) 
{
	svi_reg(&(tinfoil.validation_items[469]),
	        "715bdadba7ecfac4993e4437b7181ef7e96334def15680e08a84d47eeae82dcfefba8571e301c92928372b5df998ff6bca30b0cdf1a62b227448872c349478eb",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-cp2112.ko"
	);
}
static void svir_471(void) 
{
	svi_reg(&(tinfoil.validation_items[470]),
	        "44fd02084bfff8841bc6c009943d99d7db4dda71ecfe3816d6b1ca638b40e65872299c57f94994916f07629360c947fdecc4bd844be7402139e087eb54de1fe6",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-cougar.ko"
	);
}
static void svir_472(void) 
{
	svi_reg(&(tinfoil.validation_items[471]),
	        "0d91ff2a1f879c6f3299c897775c46533a36dbdee42642f152fde831a20a2a0a97dda6f85614c8c33583bb4d19aae2a95ee8543306ad5893f83bd0f0a806ea6a",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-corsair.ko"
	);
}
static void svir_473(void) 
{
	svi_reg(&(tinfoil.validation_items[472]),
	        "5790267c6dd0d2d17dcf92c18fdc4b3787372c938a669af4491b08594299a12b158e409949b07e2c062794ffe39d1c66436660f3de28e54cc23274406527f751",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-cmedia.ko"
	);
}
static void svir_474(void) 
{
	svi_reg(&(tinfoil.validation_items[473]),
	        "1f85c7c720d4fba3b7a0f971aadd56f95419c7d6263d6aee89b5695c193428d9bae3de896b049d6813aaa88e7b5b6dec7a9b91f17cfbaa0e3ca3cc18a5475d5b",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-chicony.ko"
	);
}
static void svir_475(void) 
{
	svi_reg(&(tinfoil.validation_items[474]),
	        "7c1ae6fa6ba74d9d46a260fe02bc1fa571490b69919dfa2ec0709f9f33e9d8809700c92560ec83ec20865747bfda3a7e422e6874c8e542bbdccdabb462656b33",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-cherry.ko"
	);
}
static void svir_476(void) 
{
	svi_reg(&(tinfoil.validation_items[475]),
	        "f935f8318c38e8a34990af7060be248a457b66d649c6a3a680572067f1789b6899f1752bfccebda315ce5aaed0b173a68e6c532b24ddbe30904c472f72054b4d",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-bigbenff.ko"
	);
}
static void svir_477(void) 
{
	svi_reg(&(tinfoil.validation_items[476]),
	        "e02e3e3b533ce431d5777dae72256fba53922f9046ac384c8a9c32e5f6d740435fabbc5903066e7977e8f72ea4c81a5891c6ff4b0dd953a90f4d1c277e37380f",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-betopff.ko"
	);
}
static void svir_478(void) 
{
	svi_reg(&(tinfoil.validation_items[477]),
	        "384e72c7570cecd1435928e3782803f9783cfdb9acc2c8291eafa90667ccb42e36b6bd11cff122c97246f512a310488580f01634ebe6a982a1b2246d80aa8d2c",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-belkin.ko"
	);
}
static void svir_479(void) 
{
	svi_reg(&(tinfoil.validation_items[478]),
	        "99f7dc579a374de390d92e65880351e481bb89edae9229ac7f290db3dfd8b68654148add45c94dc021b0cf1b057b1dd589b106c2d5a855f04d47e12fd442e72a",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-axff.ko"
	);
}
static void svir_480(void) 
{
	svi_reg(&(tinfoil.validation_items[479]),
	        "6d28a2e46fb87f1c8066bbea58fa6a5fc90f3e1f088bad555ac44a81064d25d192c8cf18a1d74b63bc698ef28ccf934aecf8c4625af03b6e0b30f31f62bf89c5",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-aureal.ko"
	);
}
static void svir_481(void) 
{
	svi_reg(&(tinfoil.validation_items[480]),
	        "ce7c38fe144dd5fe1037e0396e3851d239775d86fd34c095e5c2041ee9e58736612822ec0729f1994742407da8ef7b7ec92f42aacd9178a9a151b24f4f135586",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-asus.ko"
	);
}
static void svir_482(void) 
{
	svi_reg(&(tinfoil.validation_items[481]),
	        "a0f7556373a7c53d870247f532fb96805494928d7f72363c9ab8dab68bac6cfa0be3be3c3f9757a295de71f5eed81e310db856ff6068e8fd882b8bc8e55df0e7",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-appleir.ko"
	);
}
static void svir_483(void) 
{
	svi_reg(&(tinfoil.validation_items[482]),
	        "acb7fc0f902e7b31f814926df4ca1c106df0a3e4643c1128de606c8f4591d52da7060f22d62dbb8680149f8064b150f9617977129d3e4c20582c5536bc42ebee",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-apple.ko"
	);
}
static void svir_484(void) 
{
	svi_reg(&(tinfoil.validation_items[483]),
	        "156eff94611ee3aa76163381ab7bfcf602dab5ab3254671c5386ad10e694ede3bd8fa2aa2f8c981dfe753718cb4c62b29a803fa369cd29107b0cfede0144ccf5",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-alps.ko"
	);
}
static void svir_485(void) 
{
	svi_reg(&(tinfoil.validation_items[484]),
	        "f9bbed3d2a645e80246cd398b3ed51398522e3f6f76370007939bb2f87321f7e995b80b4e194553324865f6f9ca7f683252115236ee23d18450a20345d4d58f4",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-accutouch.ko"
	);
}
static void svir_486(void) 
{
	svi_reg(&(tinfoil.validation_items[485]),
	        "4a44d6339854ad416c862ce8c9c753605bca976735e1ddfde49bba10046f8db08e933bb9d755474313d1d82e76678d740a33181a0a66423ada595a5eb07297fb",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-a4tech.ko"
	);
}
static void svir_487(void) 
{
	svi_reg(&(tinfoil.validation_items[486]),
	        "8643d0d50568b608a6e5733157cda7f5d4e1331c920cc06beaf1ebb89b23e9926ef0d28514f22a255702334a931a30e9bce83036d1b51945b95c7da371d3a91b",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/amd-sfh-hid/amd_sfh.ko"
	);
}
static void svir_488(void) 
{
	svi_reg(&(tinfoil.validation_items[487]),
	        "a32cfa2929a27064ffac7f9afbba1f87ea19e192ff7f257f673810ac82c726b8dd025737b704ad2ecd9401aa31425c35dd142b3fb930b7bfc63201f8c0f9e5e3",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/gpu/drm/ttm/ttm.ko"
	);
}
static void svir_489(void) 
{
	svi_reg(&(tinfoil.validation_items[488]),
	        "afe5e174ddf103f07e0b31957836b67461c116bcf4995a272cbcf941345db4d09da2b8cc6d6d1f8e10686388f070082581b8b25552469f3ad23a5ebddac16ec5",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/gpu/drm/qxl/qxl.ko"
	);
}
static void svir_490(void) 
{
	svi_reg(&(tinfoil.validation_items[489]),
	        "5b7c2cb2f31bd832ae7c8cc49053a41ab040cf1d21841e7ce59064937684624bc9c0b4ae24a842f2a885bf93ac04946f69590a111be94882009b5065dd5998b2",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/gpu/drm/drm_ttm_helper.ko"
	);
}
static void svir_491(void) 
{
	svi_reg(&(tinfoil.validation_items[490]),
	        "c0301a2847fd3d9c78b72b45a213a22b864cf82f38bbc59715011e9e9baee2937895c135f0dea29ab169b96de040717e02533269518ee7a36678ba82b1e8cc4e",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/gpu/drm/drm_kms_helper.ko"
	);
}
static void svir_492(void) 
{
	svi_reg(&(tinfoil.validation_items[491]),
	        "735634a285cf6ef0a60fd73a7ba066fc84cbdca5a98534bd184c9ccc73f08845d70fff2e09d95f968293126f0116aad66155ce346c387c09dd60d9f730f21a1d",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/gpu/drm/drm.ko"
	);
}
static void svir_493(void) 
{
	svi_reg(&(tinfoil.validation_items[492]),
	        "d69c19080e3b727311e3ea3d9f81e1b3bd4555bf4c902b6f72d5740634258f87682602a8701154388bec94237c4f3a7829aa75f6e6c1971a62f952321c72c7d9",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/firmware/qemu_fw_cfg.ko"
	);
}
static void svir_494(void) 
{
	svi_reg(&(tinfoil.validation_items[493]),
	        "7bafa77db43a98a317d13d8975429245c37363b42e77e371268bab6c1d8e31b6d6cbc743ce8462ee96b5986b6075dea342127afcf26a104f567089d01c947bbc",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/char/virtio_console.ko"
	);
}
static void svir_495(void) 
{
	svi_reg(&(tinfoil.validation_items[494]),
	        "1d6f27d24c77658fc8868d2c39b9dc47c52942484bc26b260c7e902b66d8c1f4050c35daed83b3a447e46d65d3aa125533744115adbde9cc8206da6e7ff336ac",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/char/ipmi/ipmi_si.ko"
	);
}
static void svir_496(void) 
{
	svi_reg(&(tinfoil.validation_items[495]),
	        "8489f5bf4f7ea97325d6796e71be871698353d12c1d9b920ad26ebcf00f9236bce99858084ca9a8f903469cb40f0b99d88f9c2ee3f6cc0d8f7b31b39bcdeab72",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/char/ipmi/ipmi_msghandler.ko"
	);
}
static void svir_497(void) 
{
	svi_reg(&(tinfoil.validation_items[496]),
	        "242d0875165204c3ce268eed923e3c36703de49e1e5a5744c8310ed19dc4d6f8a9268da09db3bb26682d0dd496ac8bf10a321f1c3cddac328002f145893d20e6",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/char/ipmi/ipmi_devintf.ko"
	);
}
static void svir_498(void) 
{
	svi_reg(&(tinfoil.validation_items[497]),
	        "7fee6cd6e2a3c4cfb14e665fa987d1ac1cdbc7fdaf4bd1a499722e97e643718ff285224b74b7241005f30e42b1dea23aa853f90e8b8064d7dc1397c122a74b49",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/block/zram/zram.ko"
	);
}
static void svir_499(void) 
{
	svi_reg(&(tinfoil.validation_items[498]),
	        "c52b04a17a71c47b1b814f09e306887ffb979e8dd31e315a8e421a8525524214e807c71970da0b81ce77921aa7ffe56ecbbf212aeb13a1e872477ba04d89ec6e",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/block/virtio_blk.ko"
	);
}
static void svir_500(void) 
{
	svi_reg(&(tinfoil.validation_items[499]),
	        "26cbe98fcfea0a9169f489b561d23a45c496a44750d2aa8191594cfc45c0f5490f190349b904167ace20c57487daaaa9debef2d52c280a38e600f35255ef9a6a",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/base/regmap/regmap-spi.ko"
	);
}
static void svir_501(void) 
{
	svi_reg(&(tinfoil.validation_items[500]),
	        "ffd287d6c77d6ae90064ec6d0401ce09b98230f0068cb18a942f8e4e132a8a8d8a4f14cd09a3d43febd9057d9913b18402067ea092f695f39e3c4cbcdce36360",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/ata/pata_acpi.ko"
	);
}
static void svir_502(void) 
{
	svi_reg(&(tinfoil.validation_items[501]),
	        "7cf0c04276fea3ea79b33e47c138c9faa244e1289b82ef3b7af1e5afd566b49433e3ea95df59c85487724ac2b89d2b2b1a7016cc53b107a52636c4c403b82de3",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/ata/ata_generic.ko"
	);
}
static void svir_503(void) 
{
	svi_reg(&(tinfoil.validation_items[502]),
	        "23d2696e227e8a17bd8b6c72b41c93d00480f336e077a5a814b02f814eb7388dbebd422a484337832e089f04685640247761113f63c762afa6079c6db471bff9",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/acpi/video.ko"
	);
}
static void svir_504(void) 
{
	svi_reg(&(tinfoil.validation_items[503]),
	        "d133f21ed15e423c9d70f7027258c4157f169eeaf63b8a7ecaa83306af71f5fd5f31efa1115aec0d97c5ff8e15d298307c1932a1d70a1e990f816ad8f0b77609",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/acpi/nfit/nfit.ko"
	);
}
static void svir_505(void) 
{
	svi_reg(&(tinfoil.validation_items[504]),
	        "d3fcacd56aa26793b6fa19f20965860446826756d556ce36aad49f1d439e91fd03eaeacc1cea3b203d86a3b2debb2c3044868b4450da0f8edf28d9d0fc28deb1",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/zstd.ko"
	);
}
static void svir_506(void) 
{
	svi_reg(&(tinfoil.validation_items[505]),
	        "acdc51541366ab5282e176394f2dd7d5f556945ccce90a1bf60751720da0dba6e5d4a87db3b4f4c048427849ebec0f3291c582437648903c2142e58205d8e7fc",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/xcbc.ko"
	);
}
static void svir_507(void) 
{
	svi_reg(&(tinfoil.validation_items[506]),
	        "b893952cfd6569f792868ddfa3860fb70c64524d514c163847172a51ff39c58294728ada60076190b4c50b669d92abe720c6f94a00bfae9a1669b0dbed063b53",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/wp512.ko"
	);
}
static void svir_508(void) 
{
	svi_reg(&(tinfoil.validation_items[507]),
	        "c5fdd4c212d77d33897520a1cff9cdd343029fccfbad0a9252cb47376ac5bd0b27748354dae4ead3dd15b25bf8debfb3b03fa8c66295414327c1a0d20d575f9b",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/vmac.ko"
	);
}
static void svir_509(void) 
{
	svi_reg(&(tinfoil.validation_items[508]),
	        "c4402675d66fac2367c0f282687c18927fa67b5c7078e87140ad09c92125ba2daed8c72d2d3914410b9c9221cbb83acc72c44df1873f50312aa24f0330d9435a",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/twofish_generic.ko"
	);
}
static void svir_510(void) 
{
	svi_reg(&(tinfoil.validation_items[509]),
	        "f65cea7cfb92c1348b2984383729a152338422ddb19b33b24d5769ce4724e2907c38647c6c93a5c9360e00861c9f33a17995a3a192b29184889d33cc90bcce9e",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/twofish_common.ko"
	);
}
static void svir_511(void) 
{
	svi_reg(&(tinfoil.validation_items[510]),
	        "c4729ce0d0f2b02586d13c48f0da105d45705ddd39c592258768220ba3fa7708fa032184fa3a51681b8d1a13146a4cbbf9834eb33413a2e0b1ec945e800b6321",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/tcrypt.ko"
	);
}
static void svir_512(void) 
{
	svi_reg(&(tinfoil.validation_items[511]),
	        "6a179d235e4821443cdd973c38772ed67191f6880659895bb1aaae5de8939a5471e5ef68e8cd1d6eade33e740216fc7b32e577a20a6219d2ec4ab357fd1206b7",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/streebog_generic.ko"
	);
}
static void svir_513(void) 
{
	svi_reg(&(tinfoil.validation_items[512]),
	        "8afebbb0b3a7b261ea95cd30b1b25db25316b9c3ef141cd1891534ad8c6c0c07cacc3c08672dc6e80340fb443ff8f69468138b5a748c69222f184c2447de4a79",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/serpent_generic.ko"
	);
}
static void svir_514(void) 
{
	svi_reg(&(tinfoil.validation_items[513]),
	        "05fed665ae99c21e2a62997565f4b025ec23954770ee4a4aaeb8e73eb0da79097cbec81ba25ab7af94eabefa42642d071103ae840e62ba130793bebf88816d19",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/rmd160.ko"
	);
}
static void svir_515(void) 
{
	svi_reg(&(tinfoil.validation_items[514]),
	        "b1e18ce425f91f22c27c6551aa64b1b98276ba9c6049452fe691b64a28effed7b655a2936c7a302fdba9e4f19d794c1fd66ce6e6b4ee1ac309dcfe95313ecabb",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/poly1305_generic.ko"
	);
}
static void svir_516(void) 
{
	svi_reg(&(tinfoil.validation_items[515]),
	        "2475edde05aee9d8aa3b3403dc11c9b9e43fad4784b95b73d9fb71e0c3463f7f6bdff3123187c012cbce168070b12ebb6e0770f6b0476a3a4ffb0719c2fcdaee",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/pcrypt.ko"
	);
}
static void svir_517(void) 
{
	svi_reg(&(tinfoil.validation_items[516]),
	        "2fd8740d5221ff8c90720f468ceefdd5ff4a81696426cafe4ed572de36a87fe0cd8be1890d143c8d5929ebc7991b6d01ed38822339db0d2a0230447e2fcbfbad",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/pcbc.ko"
	);
}
static void svir_518(void) 
{
	svi_reg(&(tinfoil.validation_items[517]),
	        "a1e5c0bb1dabc88472fad0fad506eff453b0dcbf6e9476eb1232ab9fe5d199845c0ff1d89c917c4587acc2ccc6072241129b6fd243c4ca8695afb2d5b2f5518a",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/nhpoly1305.ko"
	);
}
static void svir_519(void) 
{
	svi_reg(&(tinfoil.validation_items[518]),
	        "51a9e539975f73faebcb5cea62c8228abdd264d472259d173c99099aa4ef6ffea7236618f77488327f7dabb6d8ae1e0ac5224e95018b661a8932648ff360ebde",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/michael_mic.ko"
	);
}
static void svir_520(void) 
{
	svi_reg(&(tinfoil.validation_items[519]),
	        "a1ff680525fa83404f4cde63f03e4d14886b0791ff15d52ee28d86e3702240185c1ea2552f394cdc34eb33a8e2c8fa394b91691831b4f7e0ecd8e1f76cd48128",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/md4.ko"
	);
}
static void svir_521(void) 
{
	svi_reg(&(tinfoil.validation_items[520]),
	        "6623a451cee045f82e5dc98c55dac039c0d65c93ce6e766bfe3c4eeb89b88edff98934ea35a65b2c1887e00754044388b03442e463f7a9ea667925e21fa26db1",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/lz4hc.ko"
	);
}
static void svir_522(void) 
{
	svi_reg(&(tinfoil.validation_items[521]),
	        "c2b83b10638f45f47cfbd979794624bc8070d12ed7a418797e4c66091d43623850781acb552d398b071eb01fcdb823b1bbed88d29c6943b38916a366f7b788d6",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/lz4.ko"
	);
}
static void svir_523(void) 
{
	svi_reg(&(tinfoil.validation_items[522]),
	        "c74dc04f12b2d19b1b28de6930e2aef024cf79426b9636bba5e8467ea105463774612b0c84bd96d41ee70507951fb2df582c3c2a90ffd7be0f797068bf8d478d",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/keywrap.ko"
	);
}
static void svir_524(void) 
{
	svi_reg(&(tinfoil.validation_items[523]),
	        "1013265772117cdbcb60b11c42e485adb1f2f91c7d1b07ed47eba398a16f635f09daedbf65235cd29efc2f45aa2fa00c4081e965775cacdcd8a9d61ca97c5f3a",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/fcrypt.ko"
	);
}
static void svir_525(void) 
{
	svi_reg(&(tinfoil.validation_items[524]),
	        "2871198badffc730fa3567071824c2779939d03823aa90afaa1ede1cf6359789a8e5f148291c5c5f68ab0bd0b6833dcacbc2dfd290ff1bd7bed4bd48d78fe0f7",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/essiv.ko"
	);
}
static void svir_526(void) 
{
	svi_reg(&(tinfoil.validation_items[525]),
	        "6cb9fd23dd1d1b71c886834fc47b962efda6253824f1e62cebb98d96d575fafc5e2985a656f8bf5cc356ab4f60bd31837680cb02990f483f4a529de16dac5400",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/ecrdsa_generic.ko"
	);
}
static void svir_527(void) 
{
	svi_reg(&(tinfoil.validation_items[526]),
	        "a00addff8739a5398f2d11608026f89163a5b7ae4efa94daa117f6f46c88e8040c74dac7691751826eac2941a9357a577412047291ffcfa3c969dfd487b9d819",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/echainiv.ko"
	);
}
static void svir_528(void) 
{
	svi_reg(&(tinfoil.validation_items[527]),
	        "5a50169b99c5215555dae1dab6e9e1a9c1455f6f43fb57c46cd4e4fe4deabd7132a3bd1ecd012cda69379890804a5fad96b151bda6b7c93f3daebf1518f5fc7d",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/ecdh_generic.ko"
	);
}
static void svir_529(void) 
{
	svi_reg(&(tinfoil.validation_items[528]),
	        "5c2610cb174a4f648ca3992ecd09bbaebdb883d8f770838c05c14a75280dafd9103afa3a49c76e1d787337190919a2becd5e152a744ea1c49b365ce54b322698",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/des_generic.ko"
	);
}
static void svir_530(void) 
{
	svi_reg(&(tinfoil.validation_items[529]),
	        "74c265297c3a7bf53f859323582f1bdf6f77100b53ed8d48cbd839cae5817e359ae8cf3aab7dcc2eb8af6a6ccec00c5121cebde4762c3de316bc0132a2648bc1",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/curve25519-generic.ko"
	);
}
static void svir_531(void) 
{
	svi_reg(&(tinfoil.validation_items[530]),
	        "e36d23868223db69ccd771a089e49237f0b88f711ac23a44c7627e70afc1691a2710df4c008781ecebe5424934819a439225b5a3c164ca1514f7de560ad285d3",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/crypto_user.ko"
	);
}
static void svir_532(void) 
{
	svi_reg(&(tinfoil.validation_items[531]),
	        "783a489c25459dd42b3c1207984ea79ff142a0b4d1fb83c1385fd0aa56781fccad40b6a6de81bf380ecd497b30c2fcd08d35a7453010ce55329906768f432dc8",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/crypto_engine.ko"
	);
}
static void svir_533(void) 
{
	svi_reg(&(tinfoil.validation_items[532]),
	        "c38ba1ae8ef4ab312d3b24e679ea1cf3859429c70d0ee5a073e1e238a073c297837e238039f2bc32898a7c860cf72b5400311669d52850458a1bb641de07bcde",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/crc32_generic.ko"
	);
}
static void svir_534(void) 
{
	svi_reg(&(tinfoil.validation_items[533]),
	        "c59457196be3c67e6769f716a3c9d5cb569397df06769e6f0529753ff7e54452f011cc48e925586380e25577cd2bba78e5199c81ad2cb01780720c308e5b47e5",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/chacha_generic.ko"
	);
}
static void svir_535(void) 
{
	svi_reg(&(tinfoil.validation_items[534]),
	        "db23eaa905f6dec5803206f6345f8dd601636be3609663c8465882ca46f8de230a37b6b04e643af7641b254f5ab30ae76278cc2df37638b73ceb8178503e936e",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/chacha20poly1305.ko"
	);
}
static void svir_536(void) 
{
	svi_reg(&(tinfoil.validation_items[535]),
	        "49f948a2bc0f7e6933af9135c3a026fc063776c2f10e4c772d5a8a80dbab9e2d53518edabd11d4bcad0d3415e049f1103d32a2fff6279563f730c6da56db107b",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/cast_common.ko"
	);
}
static void svir_537(void) 
{
	svi_reg(&(tinfoil.validation_items[536]),
	        "8015fdb3f9c948d94779bf83797a573dd0c958918a74e632c7a4ab4ac1e95191b42919936ebee94b105742a011725975fcf11c2f1b9e28e241313f4d2478fc7b",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/cast6_generic.ko"
	);
}
static void svir_538(void) 
{
	svi_reg(&(tinfoil.validation_items[537]),
	        "48cb224c37fda0a8c81248a101f6665e9cf94c9b2906fc3d4981f6d6ccd62216af703362dee5fb4a594302ee8185bc1e535876e6fc997750cd8112b67f08e85e",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/cast5_generic.ko"
	);
}
static void svir_539(void) 
{
	svi_reg(&(tinfoil.validation_items[538]),
	        "c2cd2e5177eeef3df8a054a2af6cfe23646cf2eb3de728d328ce3ebfb3573a3ec1e44aa00df5432059438aaf32b6d1b8198a7fbf1fc1903122ecaa425c4b2773",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/camellia_generic.ko"
	);
}
static void svir_540(void) 
{
	svi_reg(&(tinfoil.validation_items[539]),
	        "980dc3e59defc35260dbed0b50f6791f7137afbabd97be661529cc311a1077f8aa1dbecac195b18f8f0c6e28cccd0c640330a956a6f29683f8d9bf7f3337aafa",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/blowfish_generic.ko"
	);
}
static void svir_541(void) 
{
	svi_reg(&(tinfoil.validation_items[540]),
	        "2d2755eb4a9dd523a82260a68d49769e3e9a199fa05fdf8107cc8ea1f32ee49319d7f59f11b398ad3aeca4d511c3c321a258af86cb22c9eb60cbcf5979ee5bd0",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/blowfish_common.ko"
	);
}
static void svir_542(void) 
{
	svi_reg(&(tinfoil.validation_items[541]),
	        "5e44769f3d356350fd67305c18629f3944d79a93f7fa496acc3d6ade3ebf13ab26990eedfc75aeec8eb4dbeb8dbb8736f1acd506516a27a08c948a7965b65adb",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/blake2s_generic.ko"
	);
}
static void svir_543(void) 
{
	svi_reg(&(tinfoil.validation_items[542]),
	        "3782f7cb8e28dab391ce1062fb4d8c7c1273af0a53889f4a228dd1ac3a1177ef60ca6bc38a7ad1ebdd00222131378155889cf0361c2943457783af1c4e3e6025",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/async_tx/raid6test.ko"
	);
}
static void svir_544(void) 
{
	svi_reg(&(tinfoil.validation_items[543]),
	        "7ee1b8ba4062a52b69f72ab31edba794880dbfe0ef9a0bd758d4c4583abf43bd698cedae6cce9970c62735c55b34f2c29848204582cdc042671bae16768b8625",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/async_tx/async_xor.ko"
	);
}
static void svir_545(void) 
{
	svi_reg(&(tinfoil.validation_items[544]),
	        "b411824afd8075555a868c5ecce8cca7740aa8db3361ec76a6e22c566b6db3f506ebe705b5e1ebc2f0afa8bd4054cf49fc751ab7841aa454698f7d88d95adf12",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/async_tx/async_tx.ko"
	);
}
static void svir_546(void) 
{
	svi_reg(&(tinfoil.validation_items[545]),
	        "4d27c11c6cd658edc240d1e7525f119814f438ae15ef269c5d85b2783224ae58fd7f89ee76c1e1acb760b4db231d78c915d74e29e63b2b3850bef583399edb5f",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/async_tx/async_raid6_recov.ko"
	);
}
static void svir_547(void) 
{
	svi_reg(&(tinfoil.validation_items[546]),
	        "246e13edfffba7bb41d8c2f4f65185acd4093104e70e4d61aa0e0f41af7140c2f78aa78a4d7684e9ee4507831144ab09a7cb750fbfee50e80e0d714e25137fbb",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/async_tx/async_pq.ko"
	);
}
static void svir_548(void) 
{
	svi_reg(&(tinfoil.validation_items[547]),
	        "1aceade68f272c2b7c56ab14ef371453aa276f634d23c8e4756ff6e8f97b093abb2e9df20b1a49443eedc5ac81aaa3d943f7a97c37ed62e1a2f5d1ae2d162721",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/async_tx/async_memcpy.ko"
	);
}
static void svir_549(void) 
{
	svi_reg(&(tinfoil.validation_items[548]),
	        "8e28d675738e3eab1e96c3235b389c895aa7309cc2f221da30a61e7a4b50db532a8fbbbbc8563855bc3ccd4e18fcbd5329ddfd76c731fd8f0de2d5888d63e8a8",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/asymmetric_keys/tpm_key_parser.ko"
	);
}
static void svir_550(void) 
{
	svi_reg(&(tinfoil.validation_items[549]),
	        "3f3e518e9925cb31db1dcd369e18fc0156265e40e2f8fcef56c796a198432fa1a9ca7be6bd2a940f8956f1ebc704f3510fd5c221fa5fc6430fc06395705d3b7e",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/asymmetric_keys/pkcs8_key_parser.ko"
	);
}
static void svir_551(void) 
{
	svi_reg(&(tinfoil.validation_items[550]),
	        "994ae64fd556dd2a6be1f09b9624213863852bbfcc6636a5dec36a7c0740bf66db5fbcc5a44ed8dcfb5a06a41f1a634ca84ca5108cfba01ebf924f78ff9bb1a2",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/asymmetric_keys/asym_tpm.ko"
	);
}
static void svir_552(void) 
{
	svi_reg(&(tinfoil.validation_items[551]),
	        "e48e9468c824c9be1fe8deffb53a3f35927ae40c44dd56f39587d074c30b3301e2a500736816adbc9a9ca5e9d185aa114c08fadfbfafa29cf450ba646b97807e",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/ansi_cprng.ko"
	);
}
static void svir_553(void) 
{
	svi_reg(&(tinfoil.validation_items[552]),
	        "6098c48a8ba338fb337ece8fc8705a4d45699a6d5f7795c666c5f9c4eab83707061b175e49cb946b54f010446bc0e4c0e0a2ed35df20bbbb19fefc1d005b8fcb",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/aes_ti.ko"
	);
}
static void svir_554(void) 
{
	svi_reg(&(tinfoil.validation_items[553]),
	        "e32bc610eab7ce3dfdac122f57720bc29bb9bcb234e53a54a9c759a44272339b3a0b13a1e0618c0df0c3da294a1bdb5e77a6610dc9a966e46d3bff70b08724ad",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/aegis128.ko"
	);
}
static void svir_555(void) 
{
	svi_reg(&(tinfoil.validation_items[554]),
	        "a879873225fe14213f04917dd6b2187b7830fb2458caf2d0beb3e5483fe3edf2dbd523b3a24ef0187ab84621d0edb031ae61eecf6884e5e1da3b5ea3b9a7e604",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/adiantum.ko"
	);
}
static void svir_556(void) 
{
	svi_reg(&(tinfoil.validation_items[555]),
	        "26eee70fa318ff66f8ef014ecee2a41271fb9ee2373bec15596b7a9f769d3b07ebecce7726e5f3279c34ebfab31f943e6be041d033a6149c9a8d5c6030f307d3",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/arch/x86/crypto/sha256-ssse3.ko"
	);
}
static void svir_557(void) 
{
	svi_reg(&(tinfoil.validation_items[556]),
	        "e3e4d26231f53acfc72a05fb0d92169534aaf2319c45e3107e39181699d9bc128f344e7244a091b1230fedc5b26ba8b4a5db0a994f34e911636d49ebbc534576",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/arch/x86/crypto/ghash-clmulni-intel.ko"
	);
}
static void svir_558(void) 
{
	svi_reg(&(tinfoil.validation_items[557]),
	        "5d7ae459a6a73202471508fb3c23281084914aa6062d77eda77b3d4547cc75f6a318ff617b268f203c14f4d5ecde68e0f160c6bc735327d7cdf0a7dd53fa7810",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/arch/x86/crypto/crct10dif-pclmul.ko"
	);
}
static void svir_559(void) 
{
	svi_reg(&(tinfoil.validation_items[558]),
	        "fe9496964c124ab3d1a4715cb2e3cb4405c2dfb0d7bdd0bbb14427d7fe5bb25ade50144d25b7612f47571fff9992053f3b1a81ca5900c4ecc0c56d03774eec5e",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/arch/x86/crypto/crc32c-intel.ko"
	);
}
static void svir_560(void) 
{
	svi_reg(&(tinfoil.validation_items[559]),
	        "2e95dc6c17c5294ba7805fbba2333493af7ec5cf84f02213bc454b298a896263b4235ff68424aa2d81157e8835fddaebba392ea3e73ffa77fbb9fb4d16baa6d8",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/arch/x86/crypto/crc32-pclmul.ko"
	);
}
static void svir_561(void) 
{
	svi_reg(&(tinfoil.validation_items[560]),
	        "fa7a544b98c6c938c4421acf1037fb771519da4f3cc675edb59fddca1f4fec46c1e5500d2cb57f68437f7fed3c7dc23b4baf59afb1dd02c893dbba42f7785fc1",
	        "/usr/lib/modules/5.14.13-tinfoil+/extra/slowboot.ko"
	);
}


//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/*******************************************************************************
* Register all the svirs and then validated them all counting the failures     *
*******************************************************************************/
static void slowboot_run_test(void)
{
	int j;


//##########TEMPLATE_PARM_SP##################################################=>	

	int validation_count = 561;
	svir_1();
	svir_2();
	svir_3();
	svir_4();
	svir_5();
	svir_6();
	svir_7();
	svir_8();
	svir_9();
	svir_10();
	svir_11();
	svir_12();
	svir_13();
	svir_14();
	svir_15();
	svir_16();
	svir_17();
	svir_18();
	svir_19();
	svir_20();
	svir_21();
	svir_22();
	svir_23();
	svir_24();
	svir_25();
	svir_26();
	svir_27();
	svir_28();
	svir_29();
	svir_30();
	svir_31();
	svir_32();
	svir_33();
	svir_34();
	svir_35();
	svir_36();
	svir_37();
	svir_38();
	svir_39();
	svir_40();
	svir_41();
	svir_42();
	svir_43();
	svir_44();
	svir_45();
	svir_46();
	svir_47();
	svir_48();
	svir_49();
	svir_50();
	svir_51();
	svir_52();
	svir_53();
	svir_54();
	svir_55();
	svir_56();
	svir_57();
	svir_58();
	svir_59();
	svir_60();
	svir_61();
	svir_62();
	svir_63();
	svir_64();
	svir_65();
	svir_66();
	svir_67();
	svir_68();
	svir_69();
	svir_70();
	svir_71();
	svir_72();
	svir_73();
	svir_74();
	svir_75();
	svir_76();
	svir_77();
	svir_78();
	svir_79();
	svir_80();
	svir_81();
	svir_82();
	svir_83();
	svir_84();
	svir_85();
	svir_86();
	svir_87();
	svir_88();
	svir_89();
	svir_90();
	svir_91();
	svir_92();
	svir_93();
	svir_94();
	svir_95();
	svir_96();
	svir_97();
	svir_98();
	svir_99();
	svir_100();
	svir_101();
	svir_102();
	svir_103();
	svir_104();
	svir_105();
	svir_106();
	svir_107();
	svir_108();
	svir_109();
	svir_110();
	svir_111();
	svir_112();
	svir_113();
	svir_114();
	svir_115();
	svir_116();
	svir_117();
	svir_118();
	svir_119();
	svir_120();
	svir_121();
	svir_122();
	svir_123();
	svir_124();
	svir_125();
	svir_126();
	svir_127();
	svir_128();
	svir_129();
	svir_130();
	svir_131();
	svir_132();
	svir_133();
	svir_134();
	svir_135();
	svir_136();
	svir_137();
	svir_138();
	svir_139();
	svir_140();
	svir_141();
	svir_142();
	svir_143();
	svir_144();
	svir_145();
	svir_146();
	svir_147();
	svir_148();
	svir_149();
	svir_150();
	svir_151();
	svir_152();
	svir_153();
	svir_154();
	svir_155();
	svir_156();
	svir_157();
	svir_158();
	svir_159();
	svir_160();
	svir_161();
	svir_162();
	svir_163();
	svir_164();
	svir_165();
	svir_166();
	svir_167();
	svir_168();
	svir_169();
	svir_170();
	svir_171();
	svir_172();
	svir_173();
	svir_174();
	svir_175();
	svir_176();
	svir_177();
	svir_178();
	svir_179();
	svir_180();
	svir_181();
	svir_182();
	svir_183();
	svir_184();
	svir_185();
	svir_186();
	svir_187();
	svir_188();
	svir_189();
	svir_190();
	svir_191();
	svir_192();
	svir_193();
	svir_194();
	svir_195();
	svir_196();
	svir_197();
	svir_198();
	svir_199();
	svir_200();
	svir_201();
	svir_202();
	svir_203();
	svir_204();
	svir_205();
	svir_206();
	svir_207();
	svir_208();
	svir_209();
	svir_210();
	svir_211();
	svir_212();
	svir_213();
	svir_214();
	svir_215();
	svir_216();
	svir_217();
	svir_218();
	svir_219();
	svir_220();
	svir_221();
	svir_222();
	svir_223();
	svir_224();
	svir_225();
	svir_226();
	svir_227();
	svir_228();
	svir_229();
	svir_230();
	svir_231();
	svir_232();
	svir_233();
	svir_234();
	svir_235();
	svir_236();
	svir_237();
	svir_238();
	svir_239();
	svir_240();
	svir_241();
	svir_242();
	svir_243();
	svir_244();
	svir_245();
	svir_246();
	svir_247();
	svir_248();
	svir_249();
	svir_250();
	svir_251();
	svir_252();
	svir_253();
	svir_254();
	svir_255();
	svir_256();
	svir_257();
	svir_258();
	svir_259();
	svir_260();
	svir_261();
	svir_262();
	svir_263();
	svir_264();
	svir_265();
	svir_266();
	svir_267();
	svir_268();
	svir_269();
	svir_270();
	svir_271();
	svir_272();
	svir_273();
	svir_274();
	svir_275();
	svir_276();
	svir_277();
	svir_278();
	svir_279();
	svir_280();
	svir_281();
	svir_282();
	svir_283();
	svir_284();
	svir_285();
	svir_286();
	svir_287();
	svir_288();
	svir_289();
	svir_290();
	svir_291();
	svir_292();
	svir_293();
	svir_294();
	svir_295();
	svir_296();
	svir_297();
	svir_298();
	svir_299();
	svir_300();
	svir_301();
	svir_302();
	svir_303();
	svir_304();
	svir_305();
	svir_306();
	svir_307();
	svir_308();
	svir_309();
	svir_310();
	svir_311();
	svir_312();
	svir_313();
	svir_314();
	svir_315();
	svir_316();
	svir_317();
	svir_318();
	svir_319();
	svir_320();
	svir_321();
	svir_322();
	svir_323();
	svir_324();
	svir_325();
	svir_326();
	svir_327();
	svir_328();
	svir_329();
	svir_330();
	svir_331();
	svir_332();
	svir_333();
	svir_334();
	svir_335();
	svir_336();
	svir_337();
	svir_338();
	svir_339();
	svir_340();
	svir_341();
	svir_342();
	svir_343();
	svir_344();
	svir_345();
	svir_346();
	svir_347();
	svir_348();
	svir_349();
	svir_350();
	svir_351();
	svir_352();
	svir_353();
	svir_354();
	svir_355();
	svir_356();
	svir_357();
	svir_358();
	svir_359();
	svir_360();
	svir_361();
	svir_362();
	svir_363();
	svir_364();
	svir_365();
	svir_366();
	svir_367();
	svir_368();
	svir_369();
	svir_370();
	svir_371();
	svir_372();
	svir_373();
	svir_374();
	svir_375();
	svir_376();
	svir_377();
	svir_378();
	svir_379();
	svir_380();
	svir_381();
	svir_382();
	svir_383();
	svir_384();
	svir_385();
	svir_386();
	svir_387();
	svir_388();
	svir_389();
	svir_390();
	svir_391();
	svir_392();
	svir_393();
	svir_394();
	svir_395();
	svir_396();
	svir_397();
	svir_398();
	svir_399();
	svir_400();
	svir_401();
	svir_402();
	svir_403();
	svir_404();
	svir_405();
	svir_406();
	svir_407();
	svir_408();
	svir_409();
	svir_410();
	svir_411();
	svir_412();
	svir_413();
	svir_414();
	svir_415();
	svir_416();
	svir_417();
	svir_418();
	svir_419();
	svir_420();
	svir_421();
	svir_422();
	svir_423();
	svir_424();
	svir_425();
	svir_426();
	svir_427();
	svir_428();
	svir_429();
	svir_430();
	svir_431();
	svir_432();
	svir_433();
	svir_434();
	svir_435();
	svir_436();
	svir_437();
	svir_438();
	svir_439();
	svir_440();
	svir_441();
	svir_442();
	svir_443();
	svir_444();
	svir_445();
	svir_446();
	svir_447();
	svir_448();
	svir_449();
	svir_450();
	svir_451();
	svir_452();
	svir_453();
	svir_454();
	svir_455();
	svir_456();
	svir_457();
	svir_458();
	svir_459();
	svir_460();
	svir_461();
	svir_462();
	svir_463();
	svir_464();
	svir_465();
	svir_466();
	svir_467();
	svir_468();
	svir_469();
	svir_470();
	svir_471();
	svir_472();
	svir_473();
	svir_474();
	svir_475();
	svir_476();
	svir_477();
	svir_478();
	svir_479();
	svir_480();
	svir_481();
	svir_482();
	svir_483();
	svir_484();
	svir_485();
	svir_486();
	svir_487();
	svir_488();
	svir_489();
	svir_490();
	svir_491();
	svir_492();
	svir_493();
	svir_494();
	svir_495();
	svir_496();
	svir_497();
	svir_498();
	svir_499();
	svir_500();
	svir_501();
	svir_502();
	svir_503();
	svir_504();
	svir_505();
	svir_506();
	svir_507();
	svir_508();
	svir_509();
	svir_510();
	svir_511();
	svir_512();
	svir_513();
	svir_514();
	svir_515();
	svir_516();
	svir_517();
	svir_518();
	svir_519();
	svir_520();
	svir_521();
	svir_522();
	svir_523();
	svir_524();
	svir_525();
	svir_526();
	svir_527();
	svir_528();
	svir_529();
	svir_530();
	svir_531();
	svir_532();
	svir_533();
	svir_534();
	svir_535();
	svir_536();
	svir_537();
	svir_538();
	svir_539();
	svir_540();
	svir_541();
	svir_542();
	svir_543();
	svir_544();
	svir_545();
	svir_546();
	svir_547();
	svir_548();
	svir_549();
	svir_550();
	svir_551();
	svir_552();
	svir_553();
	svir_554();
	svir_555();
	svir_556();
	svir_557();
	svir_558();
	svir_559();
	svir_560();
	svir_561();


//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	for (j = 0; j < validation_count; j++) {
		tinfoil.failures += tinfoil_unwrap(
			&(tinfoil.validation_items[j]));
	}
	if (tinfoil.failures > 0) {
		GLOW
	}
}

// init
static int slowboot_mod_init(void)
{
	if (mode == 0)
		mode = SLWBT_MODE_REG;
		
	printk(KERN_INFO "Beginning SlowBoot with mode=%u\n", mode);
	
	tinfoil.failures = 0;
	tinfoil.st = NULL;
	tinfoil.st = (struct kstat *)kmalloc(sizeof(struct kstat), GFP_KERNEL);
	if (!tinfoil.st)
		return -ENOMEM; // CHECK
	
	switch (mode) {
	case SLWBT_MODE_REG:
		slowboot_run_test();
		break;
	default:
		break;
	}
	kfree(tinfoil.st);
	return 0;
}
// exit

static int __ref kernel_init(void *unused)
{
	int ret;

	/*
	 * Wait until kthreadd is all set-up.
	 */
	wait_for_completion(&kthreadd_done);

	kernel_init_freeable();
	/* need to finish all async __init code before freeing the memory */
	async_synchronize_full();
	kprobe_free_init_mem();
	ftrace_free_init_mem();
	kgdb_free_init_mem();
	free_initmem();
	mark_readonly();

	/*
	 * Kernel mappings are now finalized - update the userspace page-table
	 * to finalize PTI.
	 */
	pti_finalize();


	system_state = SYSTEM_RUNNING;
	numa_default_policy();

	rcu_end_inkernel_boot();

	do_sysctl_args();
	

	slowboot_mod_init();
	if (ramdisk_execute_command) {
		ret = run_init_process(ramdisk_execute_command);
		if (!ret)
			return 0;
		pr_err("Failed to execute %s (error %d)\n",
		       ramdisk_execute_command, ret);
	}
	
	/*
	 * We try each of these until one succeeds.
	 *
	 * The Bourne shell can be used instead of init if we are
	 * trying to recover a really broken machine.
	 */
	if (execute_command) {
		ret = run_init_process(execute_command);
		if (!ret)
			return 0;
		panic("Requested init %s failed (error %d).",
		      execute_command, ret);
	}

	if (CONFIG_DEFAULT_INIT[0] != '\0') {
		ret = run_init_process(CONFIG_DEFAULT_INIT);
		if (ret)
			pr_err("Default init %s failed (error %d)\n",
			       CONFIG_DEFAULT_INIT, ret);
		else
			return 0;
	}

	

	if (!try_to_run_init_process("/sbin/init") ||
	    !try_to_run_init_process("/etc/init") ||
	    !try_to_run_init_process("/bin/init") ||
	    !try_to_run_init_process("/bin/sh"))
		return 0;

	panic("No working init found.  Try passing init= option to kernel. "
	      "See Linux Documentation/admin-guide/init.rst for guidance.");
}
//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

/* Open /dev/console, for stdin/stdout/stderr, this should never fail */
void __init console_on_rootfs(void)
{
	struct file *file = filp_open("/dev/console", O_RDWR, 0);

	if (IS_ERR(file)) {
		pr_err("Warning: unable to open an initial console.\n");
		return;
	}
	init_dup(file);
	init_dup(file);
	init_dup(file);
	fput(file);
}

static noinline void __init kernel_init_freeable(void)
{
	/* Now the scheduler is fully set up and can do blocking allocations */
	gfp_allowed_mask = __GFP_BITS_MASK;

	/*
	 * init can allocate pages on any node
	 */
	set_mems_allowed(node_states[N_MEMORY]);

	cad_pid = get_pid(task_pid(current));

	smp_prepare_cpus(setup_max_cpus);

	workqueue_init();

	init_mm_internals();

	rcu_init_tasks_generic();
	do_pre_smp_initcalls();
	lockup_detector_init();

	smp_init();
	sched_init_smp();

	padata_init();
	page_alloc_init_late();
	/* Initialize page ext after all struct pages are initialized. */
	page_ext_init();

	do_basic_setup();

	kunit_run_all_tests();

	wait_for_initramfs();
	console_on_rootfs();
	/*
	 * check if there is an early userspace init.  If yes, let it do all
	 * the work
	 */
	if (init_eaccess(ramdisk_execute_command) != 0) {
		ramdisk_execute_command = NULL;
		prepare_namespace();
	}

	/*
	 * Ok, we have completed the initial bootup, and
	 * we're essentially up and running. Get rid of the
	 * initmem segments and start the user-mode stuff..
	 *
	 * rootfs is available now, try loading the public keys
	 * and default modules
	 */

	integrity_load_keys();
}
