#ifndef _MALI_GMC_H
#define _MALI_GMC_H

#include <linux/gmc.h>
#include <mali_kbase.h>
#include <kernel.h>

#define PAGE_FAULT_MAP_BLOCK		1
#define PAGE_FAULT_MAP_BLOCK_MASK	(PAGE_FAULT_MAP_BLOCK - 1)
#define GMC_PF_OUT_OF_BOUNDS		1
#define GMC_HANDLE_ALL_KCTXS		0

enum kbase_gmc_op {
	GMC_COMPRESS,
	GMC_DECOMPRESS,
	GMC_COUNT_DECOMPRESSED,
};

struct kbase_gmc_tsk {
	struct kbase_context *kctx;
	struct task_struct *task;
	int trylock_status;
};

/* worker for doing parallel gmc operations */
void kbase_gmc_walk_region_work(struct work_struct *work);
/* bring back compressed pages and optionally map them back to gpu,
 * the region is given as input */
int kbase_get_compressed_region(struct kbase_va_region *reg, u64 vpfn, size_t nr);
/* bring back compressed pages (the alloc is given as input) */
int kbase_get_compressed_alloc(struct kbase_mem_phy_alloc *alloc, u64 start_idx, size_t nr);
/* assert if pages are compressed */
void kbase_pages_decompressed_assert(phys_addr_t *p, size_t nr);
/* this will be removed soon */
void kbase_gmc_invalidate_alloc(struct kbase_context *kctx,
		phys_addr_t *start, size_t pages_num);
/* generic gmc interface for compression / decompression */
int kbase_gmc_compress(pid_t pid, struct gmc_device *gmc_dev);
int kbase_gmc_decompress(pid_t pid, struct gmc_device *gmc_dev);

#define KBASE_ENTRY_COMPRESSED 0x01

#define for_each_rb_node(root, node) \
	for (node = rb_first(root); node; node = rb_next(node))

static inline bool is_region_free(struct kbase_va_region *reg)
{
	return (KBASE_REG_FREE & reg->flags);
}

static inline bool kbase_is_entry_compressed(phys_addr_t p)
{
	return !!(p & KBASE_ENTRY_COMPRESSED);
}

static inline bool kbase_is_entry_decompressed(phys_addr_t p)
{
	return !kbase_is_entry_compressed(p);
}

static inline void kbase_clear_entry_compressed(phys_addr_t *p)
{
	*p &= (~KBASE_ENTRY_COMPRESSED);
}

static inline phys_addr_t kbase_set_gmc_handle(struct gmc_storage_handle *handle)
{
	return ((phys_addr_t) handle | KBASE_ENTRY_COMPRESSED);
}

static inline struct gmc_storage_handle *kbase_get_gmc_handle(phys_addr_t p)
{
	return (struct gmc_storage_handle *)(p & ~KBASE_ENTRY_COMPRESSED);
}
#endif
