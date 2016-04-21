/*blabla*/
#ifndef __NMC_H__
#define __NMC_H__

#include <linux/types.h>
#include <linux/gmc_storage.h>

#define GMC_FS_MAX_DENTRIES 3

struct gmc_fs {
	struct dentry *dentries[GMC_FS_MAX_DENTRIES];
};

struct gmc_device {
	struct list_head list;

	struct gmc_ops     *ops;
	struct gmc_storage *storage;

	struct gmc_fs      fs;
};

int gmc_register_device(struct gmc_ops *gmc_operations, struct gmc_device *device);

struct gmc_ops {
	int (*compress_kctx) (pid_t, struct gmc_device *);
	int (*decompress_kctx) (pid_t, struct gmc_device *);
};

#endif
