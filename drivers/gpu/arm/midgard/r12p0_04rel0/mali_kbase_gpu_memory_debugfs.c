/*
 *
 * (C) COPYRIGHT 2012-2015 ARM Limited. All rights reserved.
 *
 * This program is free software and is provided to you under the terms of the
 * GNU General Public License version 2 as published by the Free Software
 * Foundation, and any use by you of this program is subject to the terms
 * of such GNU licence.
 *
 * A copy of the licence is included with the program, and can also be obtained
 * from Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 */



#include <mali_kbase_gpu_memory_debugfs.h>

#ifdef CONFIG_DEBUG_FS
/** Show callback for the @c gpu_memory debugfs file.
 *
 * This function is called to get the contents of the @c gpu_memory debugfs
 * file. This is a report of current gpu memory usage.
 *
 * @param sfile The debugfs entry
 * @param data Data associated with the entry
 *
 * @return 0 if successfully prints data in debugfs entry file
 *         -1 if it encountered an error
 */

#define GPU_MEMORY_SEQ_BUF_SIZE 20*PAGE_SIZE

static inline bool is_region_growable(struct kbase_va_region *reg)
{
	return GROWABLE_FLAGS_REQUIRED & reg->flags;
}

static inline void seq_print_mem_type(struct seq_file *sfile,
		struct kbase_mem_phy_alloc *alloc)
{
	if (alloc)
		switch (alloc->type) {
			case KBASE_MEM_TYPE_NATIVE:
				seq_puts(sfile, "NATI");
				return;
			case KBASE_MEM_TYPE_IMPORTED_UMP:
				seq_puts(sfile, "IUMP");
				return;
			case KBASE_MEM_TYPE_IMPORTED_UMM:
				seq_puts(sfile, "IUMM");
				return;
			case KBASE_MEM_TYPE_ALIAS:
				seq_puts(sfile, "ALIA");
				return;
			case KBASE_MEM_TYPE_TB:
				seq_puts(sfile, "  TB");
				return;
			case KBASE_MEM_TYPE_RAW:
				seq_puts(sfile, " RAW");
				return;
			case KBASE_MEM_TYPE_IMPORTED_USER_BUF:
				seq_puts(sfile, "USRB");
				return;
		}
	seq_puts(sfile, "UNKN");
}

static inline void seq_print_gpu_mappings(struct seq_file *sfile,
		struct kbase_mem_phy_alloc *alloc)
{
	seq_printf(sfile, "%6u",
			alloc ? atomic_read(&alloc->gpu_mappings) : 0);
}

static inline void seq_print_flags(struct seq_file *sfile,
	       struct kbase_va_region *reg)
{
	seq_printf(sfile, "%s%s%s %s%s%s",
		(KBASE_REG_CPU_CACHED & reg->flags) ?  "c" : "-",
		(KBASE_REG_CPU_RD & reg->flags) ?  "r" : "-",
		(KBASE_REG_CPU_WR & reg->flags) ?  "w" : "-",
		(KBASE_REG_GPU_RD & reg->flags) ?  "r" : "-",
		(KBASE_REG_GPU_WR & reg->flags) ?  "w" : "-",
		(KBASE_REG_GPU_NX & reg->flags) ?  "-" : "x");
}

#if MALI_GMC
static inline size_t count_compressed_pages(struct kbase_mem_phy_alloc *alloc)
{
	size_t i, ret = 0;

	for (i = 0; i < alloc->nents; i++)
		if (kbase_is_entry_compressed(alloc->pages[i]))
			ret++;
	return ret;
}
#else
static inline size_t count_compressed_pages(struct kbase_mem_phy_alloc *alloc)
{
	return 0;
}
#endif

static inline void seq_print_reg(struct seq_file *sfile,
		struct kbase_va_region *reg)
{
	struct kbase_mem_phy_alloc *cpu_alloc = reg->cpu_alloc,
		*gpu_alloc = reg->gpu_alloc;
	kbase_mem_phy_alloc_get(cpu_alloc);
	KBASE_DEBUG_ASSERT(gpu_alloc->type == cpu_allocs->type);
	seq_printf(sfile, "    %8llu %7zu ",
			reg->start_pfn, reg->nr_pages);
	if (is_region_growable(reg))
		seq_printf(sfile, "%7zu  ", reg->extent);
	else
		seq_puts(sfile, "      -  ");

	seq_printf(sfile, "%8zu", cpu_alloc ? cpu_alloc->nents : 0);
	seq_puts(sfile, "       ");
	seq_printf(sfile, "%8zu", (gpu_alloc && (cpu_alloc != gpu_alloc)) ? gpu_alloc->nents : 0);
#if MALI_GMC
	seq_printf(sfile, " %7zu  ", count_compressed_pages(cpu_alloc));
#else
	seq_puts(sfile, "      -       ");
#endif

	seq_print_flags(sfile, reg);
	seq_putc(sfile, ' ');
	seq_print_gpu_mappings(sfile, gpu_alloc);
	seq_puts(sfile, "   ");
	seq_print_mem_type(sfile, cpu_alloc);
	seq_putc(sfile, '\n');
	kbase_mem_phy_alloc_put(cpu_alloc);
}


static void kbasep_show_kctx_overall_native_memory(
		struct seq_file *sfile,
		struct kbase_context *kctx)
{
	struct rb_node *node;
	struct kbase_va_region *reg = NULL;
	unsigned long backed_pages_overall = 0;
	unsigned long compressed_pages_overall = 0;
	int i = 0;

	kbase_gpu_vm_lock(kctx);
	for_each_rb_node(&(kctx->reg_rbtree), node) {
                reg = rb_entry(node, struct kbase_va_region, rblink);
                if (!is_region_free(reg) && reg->cpu_alloc &&
			reg->cpu_alloc->type == KBASE_MEM_TYPE_NATIVE) {
			backed_pages_overall += reg->cpu_alloc->nents;
			if (reg->cpu_alloc != reg->gpu_alloc) {
				KBASE_DEBUG_ASSERT(reg->cpu_alloc->nents != reg->gpu_alloc->nents);
				backed_pages_overall *= 2;
			}
#if MALI_GMC
			compressed_pages_overall += count_compressed_pages(reg->cpu_alloc);
			if (reg->cpu_alloc != reg->gpu_alloc) {
				compressed_pages_overall += count_compressed_pages(reg->gpu_alloc);
			}
#endif
		}

	}
	kbase_gpu_vm_unlock(kctx);
	for (; i < 90; i++)
		seq_putc(sfile, '-');
	seq_putc(sfile, '\n');
	seq_printf(sfile, "native memory overall: %8lu (pages)\n", backed_pages_overall);
	seq_printf(sfile, "native memory compressed: %8lu (pages)\n", compressed_pages_overall);
	seq_putc(sfile, '\n');
}


static void kbasep_gpu_memory_show_kctx(
		struct seq_file *sfile,
		struct kbase_context *kctx)
{
	struct rb_node *node;
	struct kbase_va_region *reg = NULL;

	kbase_gpu_vm_lock(kctx);
	seq_printf(sfile, /* header */
		"        pfn    pages  extent    backed(cpu) backed(gpu)  compr    flags  gpu_map type\n");

	/* through all gpu VAs */
	for_each_rb_node(&(kctx->reg_rbtree), node) {
		reg = rb_entry(node, struct kbase_va_region, rblink);
		if (!is_region_free(reg))
			seq_print_reg(sfile, reg);
	}

	kbase_gpu_vm_unlock(kctx);
}

static int kbasep_gpu_memory_seq_show(struct seq_file *sfile, void *data)
{
	struct list_head *entry;
	const struct list_head *kbdev_list;

	kbdev_list = kbase_dev_list_get();
	list_for_each(entry, kbdev_list) {
		struct kbase_device *kbdev = NULL;
		struct kbasep_kctx_list_element *element;

		kbdev = list_entry(entry, struct kbase_device, entry);
		/* output the total memory usage and cap for this device */
		seq_printf(sfile, "%-16s  %10u\n",
				kbdev->devname,
				atomic_read(&(kbdev->memdev.used_pages)));
		mutex_lock(&kbdev->kctx_list_lock);
		list_for_each_entry(element, &kbdev->kctx_list, link) {
			int ret = 0;
			struct task_struct *tsk;
			char tsk_name[TASK_COMM_LEN] = "";
			struct kbase_context *kctx = element->kctx;

			rcu_read_lock();
			tsk = find_task_by_vpid(kctx->tgid);
			if (tsk) {
				get_task_struct(tsk);
				get_task_comm(tsk_name, tsk);
				put_task_struct(tsk);
			}
			rcu_read_unlock();

			/* output the memory usage and cap for each kctx
			* opened on this device */
			ret = seq_printf(sfile,
				"  kctx-0x%p pid:%u tgid:%u comm:%s all: %u OOM see:%u\n",
				kctx, kctx->pid, kctx->tgid, tsk_name,
				atomic_read(&kctx->used_pages),
				atomic_read(&kctx->nonmapped_pages));
			kbasep_gpu_memory_show_kctx(sfile, kctx);
			kbasep_show_kctx_overall_native_memory(sfile, kctx);
		}
		mutex_unlock(&kbdev->kctx_list_lock);
	}
	kbase_dev_list_put(kbdev_list);
	return 0;
}

/*
 *  File operations related to debugfs entry for gpu_memory
 */
static int kbasep_gpu_memory_debugfs_open(struct inode *in, struct file *file)
{
	return single_open_size(file, kbasep_gpu_memory_seq_show,
			NULL, GPU_MEMORY_SEQ_BUF_SIZE);
}

static const struct file_operations kbasep_gpu_memory_debugfs_fops = {
	.open = kbasep_gpu_memory_debugfs_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/*
 *  Initialize debugfs entry for gpu_memory
 */
void kbasep_gpu_memory_debugfs_init(struct kbase_device *kbdev)
{
	debugfs_create_file("gpu_memory", S_IRUGO,
			kbdev->mali_debugfs_directory, NULL,
			&kbasep_gpu_memory_debugfs_fops);
	return;
}

#else
/*
 * Stub functions for when debugfs is disabled
 */
void kbasep_gpu_memory_debugfs_init(struct kbase_device *kbdev)
{
	return;
}
#endif
