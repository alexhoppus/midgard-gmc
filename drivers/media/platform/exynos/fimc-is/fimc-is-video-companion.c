/*
 * Samsung Exynos5 SoC series FIMC-IS driver
 *
 * exynos5 fimc-is video functions
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/videodev2.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <linux/firmware.h>
#include <linux/dma-mapping.h>
#include <linux/scatterlist.h>
#include <linux/videodev2_exynos_camera.h>
#include <linux/v4l2-mediabus.h>
#include <linux/bug.h>

#include "fimc-is-device-companion.h"
#include "fimc-is-video.h"
#include "fimc-is-core.h"

const struct v4l2_file_operations fimc_is_comp_video_fops;
const struct v4l2_ioctl_ops fimc_is_comp_video_ioctl_ops;
const struct vb2_ops fimc_is_comp_qops;

int fimc_is_comp_video_probe(void *data)
{
	int ret = 0;
	char name[255];
	u32 number;
	struct fimc_is_device_companion *device;
	struct fimc_is_video *video;

	BUG_ON(!data);

	device = data;
	video = &device->video;
	snprintf(name, sizeof(name), "%s%d", FIMC_IS_VIDEO_SENSOR_NAME, 9);
	number = FIMC_IS_VIDEO_SS0_NUM + 9;

	if (!device->pdev) {
		err("pdev is NULL");
		ret = -EINVAL;
		goto p_err;
	}

	ret = fimc_is_video_probe(video,
		name,
		number,
		VFL_DIR_RX,
		&device->mem,
		&device->v4l2_dev,
		&video->lock,
		&fimc_is_comp_video_fops,
		&fimc_is_comp_video_ioctl_ops);
	if (ret)
		dev_err(&device->pdev->dev, "%s failed(%d)\n", __func__, ret);

p_err:
	info("[CP%d:V:X] %s(%d)\n", number, __func__, ret);
	return ret;
}

extern int fimc_is_ois_sine_mode(struct fimc_is_core *core, int mode);

static int fimc_is_comp_video_s_ctrl(struct file *file, void *priv,
	struct v4l2_control *ctrl)
{
	int ret = 0;
	struct fimc_is_video *video;
	struct fimc_is_device_companion *device;

	dbg_isp("%s\n", __func__);

	video = video_drvdata(file);
	device = container_of(video, struct fimc_is_device_companion, video);

	if (!device->pdev) {
		err("pdev is NULL");
		ret = -EINVAL;
		goto p_err;
	}

	switch (ctrl->id) {
	case V4L2_CID_CAMERA_OIS_SINE_MODE:
		if (fimc_is_ois_sine_mode(device->private_data, ctrl->value)) {
			err("failed to set ois sine mode : %d\n - %d",
			ctrl->value, ret);
			ret = -EINVAL;
		}
		break;

	default:
		info("unsupported ioctl(%d, sine id = %d)\n", ctrl->id, V4L2_CID_CAMERA_OIS_SINE_MODE);
		ret = -EINVAL;
		break;
	}

p_err:
	return ret;
}

/*
 * =============================================================================
 * Video File Opertation
 * =============================================================================
 */

static int fimc_is_comp_video_open(struct file *file)
{
	int ret = 0;
	struct fimc_is_video *video;
	struct fimc_is_video_ctx *vctx;
	struct fimc_is_device_companion *device;
	struct platform_device *fimc_is_pdev;
	struct fimc_is_core *core;

	/* HACK: ugly workaround to prevent systemd/udev messing in driver state */
	if (strcmp("v4l_id", current->comm) == 0)
		return -EINVAL;

	fimc_is_pdev = to_platform_device(fimc_is_dev);
	exynos_fimc_is_cfg_cam_clk(fimc_is_pdev);

	vctx = NULL;
	video = video_drvdata(file);
	device = container_of(video, struct fimc_is_device_companion, video);
	core = device->private_data;

	ret = open_vctx(file, video, &vctx, FRAMEMGR_ID_INVALID, FRAMEMGR_ID_INVALID);
	if (ret) {
		err("open_vctx failed(%d)", ret);
		goto p_err;
	}

	info("[CP%d:V:%d] %s\n", video->id, vctx->instance, __func__);

	ret = fimc_is_companion_open(device);
	if (ret) {
		merr("fimc_is_comp_open failed(%d)", vctx, ret);
		close_vctx(file, video, vctx);
		goto p_err;
	}

	core->fimc_is_companion_opened = 1;
p_err:
	return ret;
}

static int fimc_is_comp_video_close(struct file *file)
{
	int ret = 0;
	struct fimc_is_video *video = NULL;
	struct fimc_is_video_ctx *vctx = NULL;
	struct fimc_is_device_companion *device = NULL;
	struct fimc_is_core *core;

	BUG_ON(!file);

	video = video_drvdata(file);
	device = container_of(video, struct fimc_is_device_companion, video);
	core = device->private_data;

	vctx = file->private_data;
	if (!vctx) {
		err("vctx is NULL");
		ret = -EINVAL;
		goto p_err;
	}

	info("[CP:V:%d] %s\n", vctx->instance, __func__);

	ret = fimc_is_companion_close(device);
	if (ret)
		err("fimc_is_companion_close failed(%d)", ret);

	ret = close_vctx(file, video, vctx);
	if (ret)
		err("close_vctx failed(%d)", ret);

p_err:
	core->fimc_is_companion_opened = 0;
	return ret;
}

const struct v4l2_file_operations fimc_is_comp_video_fops = {
	.owner		= THIS_MODULE,
	.open		= fimc_is_comp_video_open,
	.release	= fimc_is_comp_video_close,
	.unlocked_ioctl	= video_ioctl2,
};

/*
 * =============================================================================
 * Video Ioctl Opertation
 * =============================================================================
 */

const struct v4l2_ioctl_ops fimc_is_comp_video_ioctl_ops = {
	.vidioc_s_ctrl			= fimc_is_comp_video_s_ctrl,
};

const struct vb2_ops fimc_is_comp_qops = {
};
