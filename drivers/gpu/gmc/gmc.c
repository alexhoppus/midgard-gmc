/*
 * gmc.c - implementation of generic interface for communication with user
 * space daemon that can be used to implement 'native' memory compression
 * facilities in GPU kernel driver.
 */
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/threads.h>
#include <linux/gmc_storage.h>
#include <linux/gmc.h>

#include <asm/uaccess.h>

static atomic_t gmc_device_number = ATOMIC_INIT(0);
static struct dentry *gmc_root_dentry = NULL;

static unsigned int gmc_alloc_device_number(void)
{
	return atomic_add_return(1, &gmc_device_number) - 1;
}

static unsigned long read_pid(const char __user *ubuf, size_t len, loff_t *offp)
{
	unsigned long pid;
	char buf[32];

	if (len > sizeof(buf) - 1)
		return -EINVAL;

	if (copy_from_user(buf, ubuf, len))
		return -EFAULT;
	buf[len] = '\0';

	if (kstrtoul(&buf[0], 10, &pid) != 0)
		return -EINVAL;

        if ((pid < 0) || (pid > PID_MAX_DEFAULT))
		return -EINVAL;

	return pid;
}

static int gmc_decompress_pid(struct gmc_device *device, unsigned long pid)
{
	if (!device->ops) {
		pr_info("gmc operations have not been registered\n");
		return -EINVAL;
	}

	if (!device->ops->decompress_kctx)
		return -EINVAL;

	return device->ops->decompress_kctx(pid, device);
}

static int gmc_compress_pid(struct gmc_device *device, unsigned long pid)
{
	if (!device->ops) {
		pr_info("gmc operations have not been registered\n");
		return -EINVAL;
	}

	if (!device->ops->compress_kctx)
		return -EINVAL;

	return device->ops->compress_kctx(pid, device);
}

static ssize_t gmc_compress_write(struct file *file, const char __user *ubuf,
	size_t len, loff_t *offp)
{
	struct gmc_device *device = (struct gmc_device *)
		file->f_inode->i_private;
	unsigned long ret;

	BUG_ON(!device);

	ret = read_pid(ubuf, len, offp);
	if (IS_ERR_VALUE(ret))
		return ret;

	pr_info("gmc_compress_write pid %lu\n", ret);

	ret = gmc_compress_pid(device, ret);
	if (ret)
		return ret;

	return len;
}

static ssize_t gmc_decompress_write(struct file *file, const char __user *ubuf,
	size_t len, loff_t *offp)
{
	struct gmc_device *device = (struct gmc_device *)
		file->f_inode->i_private;
	unsigned long ret;

	BUG_ON(!device);

	ret = read_pid(ubuf, len, offp);
	if (IS_ERR_VALUE(ret))
		return ret;

	pr_info("gmc_decompress_write pid %lu\n", ret);

	ret = gmc_decompress_pid(device, ret);
	if (ret)
		return ret;

	return len;
}

static ssize_t gmc_storage_stat_read(struct file *file, char __user *ubuf,
			    size_t len, loff_t *offp)
{
	ssize_t ret, out_offset, out_count;
	char *buf;

	struct gmc_device *device = (struct gmc_device *)
		file->f_inode->i_private;

	BUG_ON(!device);

	out_count = 1024;
	buf = kmalloc(out_count, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	out_offset = 0;
	out_offset += snprintf(buf + out_offset, out_count,
			"ComprSize:    %10llu kB\n",
			(unsigned long long) atomic64_read(
				&device->storage->stat.compr_data_size) / 1024);
	out_offset += snprintf(buf + out_offset, out_count,
			"StoredSize:   %10llu kB\n",
			(unsigned long long) atomic64_read(
				&device->storage->stat.nr_pages) * 4);
	out_offset += snprintf(buf + out_offset, out_count,
			"ZeroedSize:   %10llu kB\n",
			(unsigned long long) atomic64_read(
				&device->storage->stat.nr_zero_pages) * 4);

	ret = simple_read_from_buffer(ubuf, len, offp, buf, out_offset);
	kfree(buf);

	return ret;
}

static const struct file_operations gmc_compress_fops = {
	.open = simple_open,
        .llseek = no_llseek,
	.write = gmc_compress_write
};

static const struct file_operations gmc_decompress_fops = {
	.open = simple_open,
        .llseek = no_llseek,
	.write = gmc_decompress_write
};

static const struct file_operations gmc_storage_stat_fops = {
	.open = simple_open,
	.read = gmc_storage_stat_read,
	.llseek = no_llseek
};

static int gmc_fs_init(void)
{
	gmc_root_dentry = debugfs_create_dir("gmc", NULL);
	if (!gmc_root_dentry) {
		pr_err("Unable to create gmc debugfs directory\n");
		return -EINVAL;
	}

	return 0;
}

/*
 * 6 characters of the "device" word, maximum 10 digits in unsigned int, zero
 * symbol and padding up to 32 bytes.
 */
#define GMC_DIRNAME_LENGTH 32

/**
 * gmc_register_device() - register a new graphical device in the GMC subsystem.
 *
 * @gmc_operations: a pointer to the gmc_operations structure provided by the
 * user of the GMC subsystem.
 * @gmc_device: a pointer to generic gmc device, built in platform device
 * Returns 0 on success and error code if something is wrong.
 */
int gmc_register_device(struct gmc_ops *gmc_operations, struct gmc_device *device)
{
	char                dirname[GMC_DIRNAME_LENGTH];
	struct gmc_storage *storage;
	struct dentry      *device_dir_dentry;

	unsigned int id;
	int i;

	/*
	 * This data structure describes files associated with some particular
	 * device registered in the GMC subsystem. This data is used by a
	 * generic piece of code below to create necessary debugfs dentries in
	 * the GMC file hierarchy.
	 */
	struct {
		const char                   *name;
		const struct file_operations *fops_p;
	} files[] = {
		{"compress",     &gmc_compress_fops},
		{"decompress",   &gmc_decompress_fops},
		{"storage_stat", &gmc_storage_stat_fops},
	};

	BUILD_BUG_ON(ARRAY_SIZE(files) > GMC_FS_MAX_DENTRIES);

	id = gmc_alloc_device_number();
	snprintf(dirname, GMC_DIRNAME_LENGTH, "device%d", id);
	dirname[GMC_DIRNAME_LENGTH - 1] = '\0';

	storage = gmc_storage_create();
	if (!storage) {
		pr_err("Unable to create a storage for the device.\n");
		goto error_out;
	}

	device->storage = storage;
	device->ops = gmc_operations;

	/* Lazy creation of the root GMC dentry. */
	if (!gmc_root_dentry) {
		if (gmc_fs_init())
			goto error_destroy_storage;
	}

	device_dir_dentry = debugfs_create_dir(dirname, gmc_root_dentry);
	if (!device_dir_dentry) {
		pr_err("Unable to create gmc device debugfs directory\n");
		goto error_cleanup_debugfs;
	}

	/*
	 * Create necessary dentries, pass a pointer to the device
	 * structure to initialize the private fields of the corresponding
	 * inodes.
	 */
	for (i = 0; i < ARRAY_SIZE(files); i++) {
		struct dentry *dir_entry = debugfs_create_file(files[i].name,
				S_IRUGO, device_dir_dentry, device,
				files[i].fops_p);
		if (!dir_entry) {
			pr_err("Unable to create %s file\n", files[i].name);
			goto error_cleanup_debugfs;
		}

		device->fs.dentries[i] = dir_entry;
	}

	return 0;

error_cleanup_debugfs:
	debugfs_remove_recursive(gmc_root_dentry);
	kfree(storage);
error_destroy_storage:
	gmc_storage_destroy(storage);
error_out:
	return -EINVAL;
}

MODULE_AUTHOR("Sergei Rogachev <s.rogachev@samsung.com>");
MODULE_AUTHOR("Yashchenko Alexander <a.yashchenko@samsung.com>");
MODULE_DESCRIPTION("GPU memory compression infrastructure");
MODULE_LICENSE("GPL");
