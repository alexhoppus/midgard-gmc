/*
 * Copyright 2016 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Authors:
 * [ initial prototype implementation ]
 *   Dmitry Safonov <0x7f454c46@gmail.com> (ex-employee)
 * [ development of the current version ]
 *   Alexander Yashchenko <a.yashchenko@samsung.com>
 * [ small fixes ]
 *   Sergei Rogachev <s.rogachev@samsung.com>
 *
 * This file is part of MALI Midgard Reclaimer for NATIVE memory
 * allocations also known as "Midgard GMC" (graphical memory compression).
 *
 * "Midgard GMC" is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * Foobar is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with "Midgard GMC".  If not, see <http://www.gnu.org/licenses/>.
 */

#define pr_fmt(fmt) "kbase-gmc: " fmt

#include "mali_kbase_gmc.h"
#include "mali_kbase_debug.h"
#include "mali_kbase_mem_linux.h"
#include "mali_kbase_hwaccess_time.h"
#include <linux/delay.h>
#include <linux/pagemap.h>
#include <linux/bug.h>
#include <linux/freezer.h>
#include <linux/page-flags.h>
#include <linux/kthread.h>
#include <linux/wait.h>

static atomic_t n_gmc_workers = ATOMIC_INIT(0);
static atomic_t n_gmc_workers_failed = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(gmc_wait);

#define GMC_WORKER_TIMEOUT_MS 10000

/**
 * kbase_gmc_unlock_task - Unlock function, which unlocks mmap_sem and kbase_gpu_vm_lock
 * of appropriate task and puts related reference counters.
 *
 * @gmc_tsk:        Info about related taask
 * @op:             Operation may be GMC_COMPRESS, GMC_DECOMPRESS, GMC_COUNT_DECOMPRESSED
 *
 * Returns: nothing
 */
static void kbase_gmc_unlock_task(struct kbase_gmc_tsk *gmc_tsk, enum kbase_gmc_op op)
{
	if (!(op == GMC_COMPRESS)) {
		kbase_gpu_vm_unlock(gmc_tsk->kctx);
	} else {
		kbase_gpu_vm_unlock(gmc_tsk->kctx);
		up_write(&gmc_tsk->task->mm->mmap_sem);
		mmdrop(gmc_tsk->task->mm);
		put_task_struct(gmc_tsk->task);
	}
}

/**
 * kbase_gmc_trylock_task - Complex lock function, which locks mmap_sem and kbase_gpu_vm_lock
 * of appropriate task and takes needed reference counters.
 *
 * @gmc_tsk:        Info about related taask
 * @op:             Operation may be GMC_COMPRESS, GMC_DECOMPRESS, GMC_COUNT_DECOMPRESSED
 *
 * Return: 0 if lock was taken without problems, or -1 if mm or task doesn't exists
 * at the moment.
 *
 * Note:
 * This function behaves differently if op == GMC_COMPRESS. In this case the mmap_sem and mm, task
 * reference counters should be taken into consideration, because CPU mappings will be shrinked
 * before compression.
 */
static int kbase_gmc_trylock_task(struct kbase_gmc_tsk *gmc_tsk, enum kbase_gmc_op op)
{
	struct task_struct *tsk;
	if (!(op == GMC_COMPRESS)) {
		/*op != GMC_COMPRESS */
		kbase_gpu_vm_lock(gmc_tsk->kctx);
	} else {
		/*op == GMC_COMPRESS */
		lockdep_assert_held(&gmc_tsk->kctx->reg_lock);
		rcu_read_lock();
		tsk = find_task_by_vpid(gmc_tsk->kctx->tgid);
		if (!tsk) {
			/* Task is gone nothing to do */
			rcu_read_unlock();
			pr_debug("task is gone, can't lock\n");
			return -ESRCH;
		}
		get_task_struct(tsk);
		rcu_read_unlock();
		task_lock(tsk);
		if (tsk->mm)
			atomic_inc(&tsk->mm->mm_count);
		else {
			task_unlock(tsk);
			put_task_struct(tsk);
			pr_debug("mm is gone, can't lock\n");
			return -ESRCH;
		}
		task_unlock(tsk);
		down_write(&tsk->mm->mmap_sem);
		kbase_gpu_vm_lock(gmc_tsk->kctx);
		gmc_tsk->task = tsk;
	}
	return 0;
}

void kbase_gmc_dma_unmap_page(struct kbase_device *kbdev, struct page *page)
{
	dma_unmap_page(kbdev->dev, kbase_dma_addr(page),
			PAGE_SIZE, DMA_FROM_DEVICE);
	lock_page(page);
	ClearPagePrivate(page);
	unlock_page(page);
}

dma_addr_t kbase_gmc_dma_map_page(struct kbase_device *kbdev, struct page *page)
{
	dma_addr_t dma_addr;
	dma_addr = dma_map_page(kbdev->dev, page, 0, PAGE_SIZE,
			DMA_TO_DEVICE);
	if (dma_mapping_error(kbdev->dev, dma_addr)) {
		pr_alert("%s: dma_mapping_error!\n", __func__);
		return (dma_addr_t)(0ULL);
	}
	lock_page(page);
	SetPagePrivate(page);
	kbase_set_dma_addr(page, dma_addr);
	unlock_page(page);
	return dma_addr;
}

/**
 * kbase_gmc_page_decompress - Decompress physical page.
 *
 * @phys_addr_t:        Physical page address
 * @kbdev:              Kbase device
 *
 * Return: 0 if page was decompressed or error code if something is wrong.
 */
static int kbase_gmc_page_decompress(phys_addr_t *p, struct kbase_device *kbdev)
{
	struct page *page;
	dma_addr_t dma_addr;
	int err;
	gfp_t flags;
	struct gmc_storage_handle *handle;

	BUG_ON(!kbase_is_entry_compressed(*p));

	handle = kbase_get_gmc_handle(*p);
#if defined(CONFIG_ARM) && !defined(CONFIG_HAVE_DMA_ATTRS) && LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0)
	flags = GFP_USER | __GFP_ZERO;
#else
	flags = GFP_HIGHUSER | __GFP_ZERO;
#endif
	page = alloc_page(flags);
	if (!page) {
		pr_err("Unable to allocate a page for decompression.\n");
		return -ENOMEM;
	}
	err = gmc_storage_get_page(kbdev->kbase_gmc_device.storage, page, handle);
	if (err) {
		pr_alert("%s: can't get page for handle: %p err: %d\n", __func__,
				handle, (int)err);
		__free_page(page);
		return -EINVAL;
	}
	dma_addr = kbase_gmc_dma_map_page(kbdev, page);
	*p = page_to_phys(page);
	BUG_ON(dma_addr != *p);
	return 0;
}

/**
 * kbase_gmc_page_compress - Compress physical page.
 *
 * @phys_addr_t:        Physical page address
 * @kbdev:              Kbase device
 *
 * Return: 0 if page was compressed or error code if something is wrong.
 */
static int kbase_gmc_page_compress(phys_addr_t *p, struct kbase_device *kbdev)
{
	struct page *page;
	struct gmc_storage_handle *handle;

	BUG_ON(kbase_is_entry_compressed(*p));
	page = pfn_to_page(PFN_DOWN(*p));
	if (!kbase_dma_addr(page)) {
		pr_debug("compression for physaddr %llu initiated,\
			but dma address was not set\n", (unsigned long long) *p);
		return -EINVAL;
	}

	kbase_gmc_dma_unmap_page(kbdev, page);

	handle = gmc_storage_put_page(kbdev->kbase_gmc_device.storage, page);
	if (IS_ERR(handle)) {
		dma_addr_t dma_addr;
		dma_addr = kbase_gmc_dma_map_page(kbdev, page);
		BUG_ON(dma_addr != *p);
		if (PTR_ERR(handle) != -EFBIG) {
			pr_alert("can't compress physaddr %llu, err: %p\n",
				(unsigned long long) *p, handle);
			return -EINVAL;
		}
		pr_debug("physaddr %llu is badly compressed, skipping it\n", (unsigned long long) *p);
		return 0;
	}

	*p = kbase_set_gmc_handle(handle);
	put_page(page);
	return 0;
}

/**
 * region_should_be_compressed - should this region be compressed or not.
 *
 * @reg:        Region to be compressed
 *
 * Return: True if region should be compressed, False otherwise.
 */
static bool region_should_be_compressed(struct kbase_va_region *reg)
{
	bool compress = true;
	if (reg->cpu_alloc != reg->gpu_alloc) {
		/*Now don't touch regions with infinite cache feature */
		compress = false;
	} else if (reg->flags & KBASE_REG_DONT_NEED) {
		/*This region will be deleted soon*/
		compress = false;
	}
	return compress;
}

/**
 * kbase_gmc_compress_alloc - Compress pages in specified allocation.
 *
 * @alloc:        Physical pages allocation
 * @start_idx:    Start index
 * @nr:           Number of pages
 *
 * Return: 0 on success or error.
 */
static int kbase_gmc_compress_alloc(struct kbase_mem_phy_alloc *alloc, u64 start_idx, size_t nr)
{
	int i, ret = 0;
	for (i = start_idx; i < start_idx + nr; i++) {
		phys_addr_t *p = &alloc->pages[i];
		if (*p && kbase_is_entry_decompressed(*p)) {
			ret = kbase_gmc_page_compress(p, alloc->imported.kctx->kbdev);
			if (ret) {
				pr_err("can't compress page, physaddr %llu\n", (unsigned long long) *p);
				return ret;
			}
		}
	}
	return ret;
}

/**
 * kbase_gmc_compress_region - Compress pages in specified region. This function
 * implements CPU & GPU unmapping before pages would be compressed.
 *
 * @reg:        Graphical memory region
 * @vpfn:       Strarting virtual pfn
 * @nr:         Number of pages
 *
 * Return: Number of pages to be compressed or error.
 *
 * Note:
 * This function must be invoked only under appropriate task (kctx) gpu_vm_lock and mmap_sem.
 */
static int kbase_gmc_compress_region(struct kbase_va_region *reg, u64 vpfn, size_t nr)
{
	int ret = 0;
	if (!region_should_be_compressed(reg))
		return ret;
	/* unmap all pages from CPU */
	ret = kbase_mem_shrink_cpu_mapping(reg->kctx, reg, 0, reg->cpu_alloc->nents);
	if (ret)
		return ret;

	/* unmap all pages from GPU */
	ret = kbase_mem_shrink_gpu_mapping(reg->kctx, reg, 0, reg->gpu_alloc->nents);
	if (ret)
		return ret;

	pr_debug("%s kctx %d region %p, pfn range [%llu, %llu]\n",
		__func__, (int)reg->kctx->tgid, reg, vpfn, vpfn + nr);
	return kbase_gmc_compress_alloc(reg->cpu_alloc, vpfn - reg->start_pfn, nr);
}

/**
 * kbase_gmc_invalidate_alloc - Invalidates entire page set from alloc
 * @kctx:        Graphical context
 * @start:       phy addr to start with
 * @pages_num:   number of pages to invalidate
 *
 * Return: nothing
 */
void kbase_gmc_invalidate_alloc(struct kbase_context *kctx,
		phys_addr_t *start, size_t pages_num)
{
	size_t i;

	lockdep_assert_held(&kctx->reg_lock);

	for (i = 0; i < pages_num; i++) {
		phys_addr_t *p = &start[i];

		if (*p && kbase_is_entry_compressed(*p)) {
			pr_debug("%s handle %p\n", __func__, kbase_get_gmc_handle(*p));
			gmc_storage_invalidate_page(kctx->kbdev->kbase_gmc_device.storage,
				kbase_get_gmc_handle(*p));
			*p = 0;
		}
	}
}

/**
 * kbase_gmc_decompress_alloc - Decompress entire page set from alloc
 * @kctx:        Graphical context
 * @start:       phy addr to start with
 * @pages_num:   number of pages to invalidate
 *
 * Return: 0 if success, or error if decompression failed
 */
static int kbase_gmc_decompress_alloc(struct kbase_mem_phy_alloc *alloc, u64 start_idx, size_t nr)
{
	int i, ret = 0;
	for (i = start_idx; i < start_idx + nr; i++) {
		phys_addr_t *p = &alloc->pages[i];
		if (*p && kbase_is_entry_compressed(*p)) {
			ret = kbase_gmc_page_decompress(p, alloc->imported.kctx->kbdev);
			if (ret) {
				pr_err("can't decompress page, physaddr %llu\n", (unsigned long long) *p);
				return ret;
			}
		}
	}
	return ret;
}

static int kbase_gmc_decompress_region(struct kbase_va_region *reg, u64 vpfn, size_t nr)
{
	return kbase_gmc_decompress_alloc(reg->cpu_alloc, vpfn - reg->start_pfn, nr);
}


/**
 * kbase_gmc_walk_region - Performs GMC specific action with region pages. This
 * walker function could, compress, decompress or count pages to be compressed.
 * @reg:        Graphical memory region
 * @op:         Operation - could be GMC_COMPRESS, GMC_DECOMPRESS or
 *              GMC_COUNT_DECOMPRESSED
 *
 * Return: 0 on success or error.
 */
static int kbase_gmc_walk_region(struct kbase_va_region *reg, enum kbase_gmc_op op)
{
	int ret = 0;
	struct kbase_mem_phy_alloc *cpu_alloc = reg->cpu_alloc;
	struct kbase_mem_phy_alloc *gpu_alloc = reg->gpu_alloc;

	if (!cpu_alloc)
		return ret;

	kbase_mem_phy_alloc_get(cpu_alloc);
	kbase_mem_phy_alloc_get(gpu_alloc);

	/* if allocation is KBASE_MEM_TYPE_IMPORTED_UMM i.e.,
	 * it's used for DMA operations between drivers, so
	 * don't touch it (it's usally DRM/GEM memory) */
	if (cpu_alloc->type != KBASE_MEM_TYPE_NATIVE) {
		kbase_mem_phy_alloc_put(gpu_alloc);
		kbase_mem_phy_alloc_put(cpu_alloc);
		return ret;
	}

	switch (op) {
	case GMC_DECOMPRESS:
		ret = kbase_gmc_decompress_region(reg, reg->start_pfn, cpu_alloc->nents);
		break;
	case GMC_COMPRESS:
		ret = kbase_gmc_compress_region(reg, reg->start_pfn, cpu_alloc->nents);
		break;
	default:
		pr_err("Invalid GMC operation\n");
		ret = -EINVAL;
	}

	kbase_mem_phy_alloc_put(gpu_alloc);
	kbase_mem_phy_alloc_put(cpu_alloc);
	return ret;
}

/**
 * kbase_gmc_walk_region_work - Worker function for handling per-region workload.
 *
 * @work:      Work struct
 *
 * Return:     Nothing.
 */
void kbase_gmc_walk_region_work(struct work_struct *work)
{
	int ret = 0;
	struct kbase_va_region *reg = container_of(work, struct kbase_va_region, gmc_work);
	pr_debug("worker [%p] have started, op %d\n", work, reg->op);
	ret = kbase_gmc_walk_region(reg, reg->op);
	if (ret) {
		pr_err("worker [%p] has errors during operation %d\n", work, reg->op);
		atomic_inc(&n_gmc_workers_failed);
	}
	atomic_dec(&n_gmc_workers);
	wake_up_interruptible(&gmc_wait);
}

/**
 * kbase_gmc_walk_kctx - Walk through not freed kctxs regions.
 *
 * @kctx:      Graphical context
 * @op:         Operation - could be GMC_COMPRESS, GMC_DECOMPRESS or
 *
 * Return: 0 on success or error.
 */
static int kbase_gmc_walk_kctx(struct kbase_context *kctx, enum kbase_gmc_op op)
{
	int ret = 0;
	struct rb_node *node;
	struct kbase_va_region *reg = NULL;
	struct kbase_gmc_tsk gmc_tsk;
	int n_workers_failed = 0;
	gmc_tsk.kctx = kctx;
	gmc_tsk.task = NULL;

	KBASE_DEBUG_ASSERT(!atomic_read(&n_gmc_workers));
	atomic_set(&n_gmc_workers_failed, 0);
	ret = kbase_gmc_trylock_task(&gmc_tsk, op);
	if (ret)
		return ret;

	for_each_rb_node(&(kctx->reg_rbtree), node) {
		reg = rb_entry(node, struct kbase_va_region, rblink);
		if (!is_region_free(reg)) {
			reg->op = op;
			atomic_inc(&n_gmc_workers);
			queue_work(system_unbound_wq, &reg->gmc_work);
		}
	}
	while (atomic_read(&n_gmc_workers) > 0) {
		int err = wait_event_interruptible_timeout(gmc_wait,
			!atomic_read(&n_gmc_workers),
			msecs_to_jiffies(GMC_WORKER_TIMEOUT_MS));
		if (err <= 0) {
			pr_alert("Timeout while waiting GMC workers, \
				it takes more than %d sec\n",
				GMC_WORKER_TIMEOUT_MS);
			kbase_gmc_unlock_task(&gmc_tsk, op);
			return -ETIMEDOUT;
		}
	}
	kbase_gmc_unlock_task(&gmc_tsk, op);
	n_workers_failed = atomic_read(&n_gmc_workers_failed);
	if (n_workers_failed > 0) {
		pr_err("%d workers has failed to complete\n", n_workers_failed);
		ret = -EINVAL;
	}
	return ret;
}

int kbase_get_compressed_region(struct kbase_va_region *reg, u64 vpfn, size_t nr)
{
	return kbase_gmc_decompress_region(reg, vpfn, nr);
}

int kbase_get_compressed_alloc(struct kbase_mem_phy_alloc *alloc, u64 start_idx, size_t nr)
{
	return kbase_gmc_decompress_alloc(alloc, start_idx, nr);
}

#if KBASE_DEBUG_DISABLE_ASSERTS
void kbase_pages_decompressed_assert(phys_addr_t *p, size_t nr)
{
}
#else
void kbase_pages_decompressed_assert(phys_addr_t *p, size_t nr)
{
	size_t i;

	for (i = 0; i < nr; i++) {
		if (!p[i])
			continue;
		KBASE_DEBUG_ASSERT(kbase_is_entry_decompressed(p[i]));
	}
}
#endif

/**
 * kbase_gmc_walk_device - Walk through device kctxs and find one associated
 * with pid.
 *
 * @kbdev:      Kbase_device
 * @pid:        Traget pid to compress
 * @op:         Operation - could be GMC_COMPRESS, GMC_DECOMPRESS or
 *              GMC_COUNT_DECOMPRESSED
 * Return: Number of pages handled by operation op.
 */
int kbase_gmc_walk_device(struct kbase_device *kbdev, pid_t pid, enum kbase_gmc_op op)
{
	int ret = 0;
	struct kbasep_kctx_list_element *element;
	mutex_lock(&kbdev->kctx_list_lock);
	list_for_each_entry(element, &kbdev->kctx_list, link) {
		struct kbase_context *kctx = element->kctx;
		if (kctx->tgid == pid || pid == GMC_HANDLE_ALL_KCTXS) {
			ret = kbase_gmc_walk_kctx(kctx, op);
			if (ret)
				goto out;
		}
	}
out:
	mutex_unlock(&kbdev->kctx_list_lock);
	return ret;
}

/**
 * kbase_gmc_compress - Compress graphical kctx data, associated with pid
 * @pid:        Traget pid to compress
 * @gmc_dev:    graphical memory compression device passed from generic layer
 *
 * Return: 0 if success error if compression is failed.
 */
int kbase_gmc_compress(pid_t pid, struct gmc_device *gmc_dev)
{
	struct kbase_device *kbdev = container_of(gmc_dev, struct kbase_device, kbase_gmc_device);
	return kbase_gmc_walk_device(kbdev, pid, GMC_COMPRESS);
}

/**
 * kbase_gmc_decompress - Decompress graphical kctx data, associated with pid
 * @pid:        Traget pid to decompress
 * @gmc_dev:    graphical memory compression device passed from generic layer
 *
 * Return: 0 if success error if decompression is failed.
 */
int kbase_gmc_decompress(pid_t pid, struct gmc_device *gmc_dev)
{
	struct kbase_device *kbdev = container_of(gmc_dev, struct kbase_device, kbase_gmc_device);
	return kbase_gmc_walk_device(kbdev, pid, GMC_DECOMPRESS);
}
