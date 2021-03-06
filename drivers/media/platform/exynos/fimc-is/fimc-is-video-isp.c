/*
 * Samsung Exynos5 SoC series FIMC-IS driver
 *
 * exynos5 fimc-is video functions
 *
 * Copyright (c) 2011 Samsung Electronics Co., Ltd
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
#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <linux/firmware.h>
#include <linux/dma-mapping.h>
#include <linux/scatterlist.h>
#include <linux/videodev2.h>
#include <linux/videodev2_exynos_camera.h>
#include <linux/v4l2-mediabus.h>
#include <linux/bug.h>

#include "fimc-is-core.h"
#include "fimc-is-param.h"
#include "fimc-is-cmd.h"
#include "fimc-is-regs.h"
#include "fimc-is-err.h"
#include "fimc-is-video.h"
#include "fimc-is-metadata.h"

extern struct fimc_is_from_info		*sysfs_finfo;
extern struct fimc_is_from_info		*sysfs_pinfo;
extern bool is_dumped_fw_loading_needed;

const struct v4l2_file_operations fimc_is_isp_video_fops;
const struct v4l2_ioctl_ops fimc_is_isp_video_ioctl_ops;
const struct vb2_ops fimc_is_isp_qops;

int fimc_is_isp_video_probe(void *data)
{
	int ret = 0;
	struct fimc_is_core *core;
	struct fimc_is_video *video;

	BUG_ON(!data);

	core = data;
	video = &core->video_isp;

	if (!core->pdev) {
		err("pdev is NULL");
		ret = -EINVAL;
		goto p_err;
	}

	ret = fimc_is_video_probe(video,
		FIMC_IS_VIDEO_ISP_NAME,
		FIMC_IS_VIDEO_ISP_NUM,
		VFL_DIR_M2M,
		&core->mem,
		&core->v4l2_dev,
		&video->lock,
		&fimc_is_isp_video_fops,
		&fimc_is_isp_video_ioctl_ops);
	if (ret)
		dev_err(&core->pdev->dev, "%s failed(%d)\n", __func__, ret);

p_err:
	return ret;
}

/*
 * =============================================================================
 * Video File Opertation
 * =============================================================================
 */

static int fimc_is_isp_video_open(struct file *file)
{
	int ret = 0;
	struct fimc_is_core *core;
	struct fimc_is_video *video;
	struct fimc_is_video_ctx *vctx;
	struct fimc_is_device_ischain *device;

	vctx = NULL;
	video = video_drvdata(file);
	core = container_of(video, struct fimc_is_core, video_isp);

	if (!core->fimc_is_companion_opened) {
		pr_info("%s: /dev/video109 (companion) must be opened first\n",
			__func__);
		return -EINVAL;
	}

	ret = open_vctx(file, video, &vctx, FRAMEMGR_ID_ISP_GRP, FRAMEMGR_ID_INVALID);
	if (ret) {
		err("open_vctx failed(%d)", ret);
		goto p_err;
	}

	info("[ISP:V:%d] %s\n", vctx->instance, __func__);

	device = &core->ischain[vctx->instance];

	ret = fimc_is_video_open(vctx,
		device,
		VIDEO_ISP_READY_BUFFERS,
		video,
		FIMC_IS_VIDEO_TYPE_OUTPUT,
		&fimc_is_isp_qops,
		&fimc_is_ischain_isp_ops,
		NULL);
	if (ret) {
		err("fimc_is_video_open failed");
		close_vctx(file, video, vctx);
		goto p_err;
	}

	ret = fimc_is_ischain_open(device, vctx, &core->minfo);
	if (ret) {
		err("fimc_is_ischain_open failed");
		close_vctx(file, video, vctx);
		goto p_err;
	}

p_err:
	return ret;
}

static int fimc_is_isp_video_close(struct file *file)
{
	int ret = 0;
	struct fimc_is_video *video = NULL;
	struct fimc_is_video_ctx *vctx = NULL;
	struct fimc_is_device_ischain *device = NULL;

	BUG_ON(!file);

	vctx = file->private_data;
	if (!vctx) {
		err("vctx is NULL");
		ret = -EINVAL;
		goto p_err;
	}

	video = vctx->video;
	if (!video) {
		err("video is NULL");
		ret = -EINVAL;
		goto p_err;
	}

	info("[ISP:V:%d] %s\n", video->id, __func__);

	device = vctx->device;
	if (!device) {
		err("device is NULL");
		ret = -EINVAL;
		goto p_err;
	}

	fimc_is_hw_logdump(device->interface);

	fimc_is_ischain_close(device, vctx);
	fimc_is_video_close(vctx);

	ret = close_vctx(file, video, vctx);
	if (ret < 0)
		err("close_vctx failed(%d)", ret);

p_err:
	return ret;
}

static unsigned int fimc_is_isp_video_poll(struct file *file,
	struct poll_table_struct *wait)
{
	u32 ret = 0;
	struct fimc_is_video_ctx *vctx = file->private_data;

	ret = fimc_is_video_poll(file, vctx, wait);
	if (ret)
		merr("fimc_is_video_poll failed(%d)", vctx, ret);

	return ret;
}

static int fimc_is_isp_video_mmap(struct file *file,
	struct vm_area_struct *vma)
{
	int ret = 0;
	struct fimc_is_video_ctx *vctx = file->private_data;

	ret = fimc_is_video_mmap(file, vctx, vma);
	if (ret)
		merr("fimc_is_video_mmap failed(%d)", vctx, ret);

	return ret;
}

const struct v4l2_file_operations fimc_is_isp_video_fops = {
	.owner		= THIS_MODULE,
	.open		= fimc_is_isp_video_open,
	.release	= fimc_is_isp_video_close,
	.poll		= fimc_is_isp_video_poll,
	.unlocked_ioctl	= video_ioctl2,
	.mmap		= fimc_is_isp_video_mmap,
};

/*
 * =============================================================================
 * Video Ioctl Opertation
 * =============================================================================
 */

static int fimc_is_isp_video_querycap(struct file *file, void *fh,
					struct v4l2_capability *cap)
{
	struct fimc_is_core *isp = video_drvdata(file);

	strlcpy(cap->driver, FIMC_IS_DRV_NAME, sizeof(cap->driver));
	strlcpy(cap->card, FIMC_IS_DRV_NAME, sizeof(cap->card));
	snprintf(cap->bus_info, sizeof(cap->bus_info), "platform:%s",
					dev_name(&isp->pdev->dev));
	cap->device_caps = V4L2_CAP_STREAMING | V4L2_CAP_VIDEO_CAPTURE_MPLANE;
	cap->capabilities = cap->device_caps | V4L2_CAP_DEVICE_CAPS;

	return 0;
}

static int fimc_is_isp_video_enum_fmt_mplane(struct file *file, void *priv,
	struct v4l2_fmtdesc *f)
{
	dbg_isp("%s\n", __func__);
	return 0;
}

static int fimc_is_isp_video_get_format_mplane(struct file *file, void *fh,
	struct v4l2_format *format)
{
	dbg_isp("%s\n", __func__);
	return 0;
}

static int fimc_is_isp_video_set_format_mplane(struct file *file, void *fh,
	struct v4l2_format *format)
{
	int ret = 0;
	struct fimc_is_video_ctx *vctx = file->private_data;
	struct fimc_is_queue *queue;
	struct fimc_is_device_ischain *device;

	BUG_ON(!vctx);

	mdbgv_isp("%s\n", vctx, __func__);

	queue = GET_VCTX_QUEUE(vctx, format);
	device = vctx->device;

	ret = fimc_is_video_set_format_mplane(file, vctx, format);
	if (ret)
		merr("fimc_is_video_set_format_mplane failed(%d)", vctx, ret);

	fimc_is_ischain_isp_s_format(device,
		queue->framecfg.width,
		queue->framecfg.height);

	return ret;
}

static int fimc_is_isp_video_cropcap(struct file *file, void *fh,
						struct v4l2_cropcap *cropcap)
{
	dbg_isp("%s\n", __func__);
	return 0;
}

static int fimc_is_isp_video_get_crop(struct file *file, void *fh,
						struct v4l2_crop *crop)
{
	dbg_isp("%s\n", __func__);
	return 0;
}

static int fimc_is_isp_video_set_crop(struct file *file, void *fh,
	const struct v4l2_crop *crop)
{
	struct fimc_is_video_ctx *vctx = file->private_data;
	struct fimc_is_device_ischain *ischain;

	BUG_ON(!vctx);

	mdbgv_isp("%s\n", vctx, __func__);

	ischain = vctx->device;
	BUG_ON(!ischain);

	fimc_is_ischain_isp_s_format(ischain,
		crop->c.width, crop->c.height);

	return 0;
}

static int fimc_is_isp_video_reqbufs(struct file *file, void *priv,
	struct v4l2_requestbuffers *buf)
{
	int ret = 0;
	struct fimc_is_video_ctx *vctx = file->private_data;
	struct fimc_is_device_ischain *device;

	BUG_ON(!vctx);

	mdbgv_isp("%s(buffers : %d)\n", vctx, __func__, buf->count);

	device = vctx->device;
	if (!device) {
		merr("device is NULL", vctx);
		ret = -EINVAL;
		goto p_err;
	}

	ret = fimc_is_ischain_isp_reqbufs(device, buf->count);
	if (ret) {
		merr("isp_reqbufs failed(%d)", vctx, ret);
		goto p_err;
	}

	ret = fimc_is_video_reqbufs(file, vctx, buf);
	if (ret)
		merr("fimc_is_video_reqbufs failed(error %d)", vctx, ret);

p_err:
	return ret;
}

static int fimc_is_isp_video_querybuf(struct file *file, void *priv,
	struct v4l2_buffer *buf)
{
	int ret;
	struct fimc_is_video_ctx *vctx = file->private_data;

	mdbgv_isp("%s\n", vctx, __func__);

	ret = fimc_is_video_querybuf(file, vctx, buf);
	if (ret)
		merr("fimc_is_video_querybuf failed(%d)", vctx, ret);

	return ret;
}

static int fimc_is_isp_video_qbuf(struct file *file, void *priv,
	struct v4l2_buffer *buf)
{
	int ret = 0;
	struct fimc_is_video_ctx *vctx = file->private_data;
	struct fimc_is_queue *queue;

	BUG_ON(!vctx);

#ifdef DBG_STREAMING
	mdbgv_isp("%s(index : %d)\n", vctx, __func__, buf->index);
#endif

	queue = GET_VCTX_QUEUE(vctx, buf);

	if (!test_bit(FIMC_IS_QUEUE_STREAM_ON, &queue->state)) {
		merr("stream off state, can NOT qbuf", vctx);
		ret = -EINVAL;
		goto p_err;
	}

	ret = fimc_is_video_qbuf(file, vctx, buf);
	if (ret)
		merr("fimc_is_video_qbuf failed(%d)", vctx, ret);

p_err:
	return ret;
}

static int fimc_is_isp_video_dqbuf(struct file *file, void *priv,
	struct v4l2_buffer *buf)
{
	int ret = 0;
	struct fimc_is_video_ctx *vctx = file->private_data;

#ifdef DBG_STREAMING
	mdbgv_isp("%s\n", vctx, __func__);
#endif

	ret = fimc_is_video_dqbuf(file, vctx, buf);
	if (ret)
		merr("fimc_is_video_dqbuf failed(%d)", vctx, ret);

	return ret;
}

static int fimc_is_isp_video_streamon(struct file *file, void *priv,
	enum v4l2_buf_type type)
{
	int ret = 0;
	struct fimc_is_video_ctx *vctx = file->private_data;

	mdbgv_isp("%s\n", vctx, __func__);

	ret = fimc_is_video_streamon(file, vctx, type);
	if (ret)
		merr("fimc_is_video_streamon failed(%d)", vctx, ret);

	return ret;
}

static int fimc_is_isp_video_streamoff(struct file *file, void *priv,
	enum v4l2_buf_type type)
{
	int ret = 0;
	struct fimc_is_video_ctx *vctx = file->private_data;

	mdbgv_isp("%s\n", vctx, __func__);

	ret = fimc_is_video_streamoff(file, vctx, type);
	if (ret)
		merr("fimc_is_video_streamoff failed(%d)", vctx, ret);

	return ret;
}

static int fimc_is_isp_video_enum_input(struct file *file, void *priv,
						struct v4l2_input *input)
{
	/* Todo : add to enum input control code */
	return 0;
}

static int fimc_is_isp_video_g_input(struct file *file, void *priv,
	unsigned int *input)
{
	/* Todo : add to get input control code */
	return 0;
}

static int fimc_is_isp_video_s_input(struct file *file, void *priv,
	unsigned int input)
{
	int ret = 0;
	struct fimc_is_video_ctx *vctx = file->private_data;
	struct fimc_is_device_ischain *device;

	BUG_ON(!vctx);
	BUG_ON(!vctx->device);

	mdbgv_isp("%s(input : %08X)\n", vctx, __func__, input);

	device = vctx->device;

	ret = fimc_is_ischain_isp_s_input(device, input);
	if (ret) {
		merr("fimc_is_ischain_isp_s_input failed", vctx);
		goto p_err;
	}

	/* if there's only one group of isp, defines group id to 3a0 connected */
	if (GET_FIMC_IS_NUM_OF_SUBIP2(device, 3a0)
			|| GET_FIMC_IS_NUM_OF_SUBIP2(device, 3a1))
		goto p_err;

	ret = fimc_is_ischain_init_wrap(device, input);
	if (ret) {
		merr("fimc_is_device_init(%d) failed", vctx, input);
		goto p_err;
	}

p_err:
	return ret;
}

static int fimc_is_isp_video_s_ctrl(struct file *file, void *priv,
					struct v4l2_control *ctrl)
{
	int ret = 0;
	int i2c_clk;
	struct fimc_is_video *video;
	struct fimc_is_video_ctx *vctx = file->private_data;
	struct fimc_is_device_ischain *device;
	struct fimc_is_core *core;

	BUG_ON(!vctx);
	BUG_ON(!vctx->device);
	BUG_ON(!vctx->video);

	dbg_isp("%s\n", __func__);

	device = vctx->device;
	video = vctx->video;
	core = container_of(video, struct fimc_is_core, video_isp);

	i2c_clk = I2C_L0;

	switch (ctrl->id) {
	case V4L2_CID_IS_DEBUG_DUMP:
		info("Print fimc-is info dump by HAL");
		if (device != NULL) {
			fimc_is_hw_logdump(device->interface);
			fimc_is_hw_regdump(device->interface);
			CALL_POPS(device, print_clk, device->pdev);
		}
		if (ctrl->value) {
			err("BUG_ON from HAL");
			BUG();
		}
		break;
	case V4L2_CID_IS_DEBUG_SYNC_LOG:
		fimc_is_logsync(device->interface, ctrl->value, IS_MSG_TEST_SYNC_LOG);
		break;
	case V4L2_CID_IS_G_CAPABILITY:
		BUG();
		ret = fimc_is_ischain_g_capability(device, NULL);
//		ret = fimc_is_ischain_g_capability(device, ctrl->value);
		dbg_isp("V4L2_CID_IS_G_CAPABILITY : %X\n", ctrl->value);
		break;
	case V4L2_CID_IS_FORCE_DONE:
		set_bit(FIMC_IS_GROUP_REQUEST_FSTOP, &device->group_isp.state);
		break;
	case V4L2_CID_IS_DVFS_LOCK:
		ret = fimc_is_itf_i2c_lock(device, I2C_L0, true);
		if (ret) {
			err("fimc_is_itf_i2_clock fail\n");
			break;
		}
		ret = fimc_is_itf_i2c_lock(device, I2C_L0, false);
		if (ret) {
			err("fimc_is_itf_i2c_unlock fail\n");
			break;
		}
		dbg_isp("V4L2_CID_IS_DVFS_LOCK : %d\n", ctrl->value);
		break;
	case V4L2_CID_IS_DVFS_UNLOCK:
		ret = fimc_is_itf_i2c_lock(device, i2c_clk, true);
		if (ret) {
			err("fimc_is_itf_i2_clock fail\n");
			break;
		}
		ret = fimc_is_itf_i2c_lock(device, i2c_clk, false);
		if (ret) {
			err("fimc_is_itf_i2c_unlock fail\n");
			break;
		}
		dbg_isp("V4L2_CID_IS_DVFS_UNLOCK : %d I2C(%d)\n", ctrl->value, i2c_clk);
		break;
	case V4L2_CID_IS_SET_SETFILE:
		if (test_bit(FIMC_IS_SUBDEV_START, &device->group_isp.leader.state)) {
			err("Setting setfile is only avaiable before starting device!! (0x%08x)",
					ctrl->value);
			ret = -EINVAL;
		} else {
			device->setfile = ctrl->value;
			minfo("[ISP:V] setfile: 0x%08X\n", vctx, ctrl->value);
		}
		break;
	case V4L2_CID_IS_COLOR_RANGE:
		if (test_bit(FIMC_IS_SUBDEV_START, &device->group_isp.leader.state)) {
			err("failed to change color range: device started already (0x%08x)",
					ctrl->value);
			ret = -EINVAL;
		} else {
			device->color_range &= ~FIMC_IS_ISP_CRANGE_MASK;

			if (ctrl->value)
				device->color_range	|=
					(FIMC_IS_CRANGE_LIMITED << FIMC_IS_ISP_CRANGE_SHIFT);
		}
		break;
#if 0
	case V4L2_CID_IS_MAP_BUFFER:
		{
			struct fimc_is_queue *queue;
			struct fimc_is_framemgr *framemgr;
			struct fimc_is_frame *frame;
			struct dma_buf *dmabuf;
			struct dma_buf_attachment *attachment;
			dma_addr_t dva;
			struct v4l2_buffer *buf = NULL;
			struct v4l2_plane *planes;
			size_t size;
			u32 write, plane, group_id;

			size = sizeof(struct v4l2_buffer);
			buf = kmalloc(size, GFP_KERNEL);
			if (!buf) {
				merr("kmalloc failed", vctx);
				ret = -EINVAL;
				goto p_err;
			}

			ret = copy_from_user(buf, (void __user *)ctrl->value, size);
			if (ret) {
				merr("copy_from_user failed(%d)", vctx, ret);
				kfree(buf);
				ret = -EINVAL;
				goto p_err;
			}

			if (!V4L2_TYPE_IS_MULTIPLANAR(buf->type)) {
				merr("single plane is not supported", vctx);
				kfree(buf);
				ret = -EINVAL;
				goto p_err;
			}

			if (buf->index >= FRAMEMGR_MAX_REQUEST) {
				merr("buffer index is invalid(%d)", vctx, buf->index);
				kfree(buf);
				ret = -EINVAL;
				goto p_err;
			}

			if (buf->length > VIDEO_MAX_PLANES) {
				merr("planes[%d] is invalid", vctx, buf->length);
				kfree(buf);
				ret = -EINVAL;
				goto p_err;
			}

			queue = GET_QUEUE(vctx, buf->type);
			if (queue->vbq->memory != V4L2_MEMORY_DMABUF) {
				merr("memory type(%d) is not supported", vctx, queue->vbq->memory);
				kfree(buf);
				ret = -EINVAL;
				goto p_err;
			}

			size = sizeof(struct v4l2_plane) * buf->length;
			planes = kmalloc(size, GFP_KERNEL);
			if (IS_ERR(planes)) {
				merr("kmalloc failed(%p)", vctx, planes);
				kfree(buf);
				ret = -EINVAL;
				goto p_err;
			}

			ret = copy_from_user(planes, (void __user *)buf->m.planes, size);
			if (ret) {
				merr("copy_from_user failed(%d)", vctx, ret);
				kfree(planes);
				kfree(buf);
				ret = -EINVAL;
				goto p_err;
			}

			framemgr = &queue->framemgr;
			frame = &framemgr->frame[buf->index];
			if (test_bit(FRAME_MAP_MEM, &frame->memory)) {
				merr("this buffer(%d) is already mapped", vctx, buf->index);
				kfree(planes);
				kfree(buf);
				ret = -EINVAL;
				goto p_err;
			}

			/* only last buffer need to map */
			if (buf->length > 0) {
				plane = buf->length - 1;
			} else {
				merr("buf size is abnormal(%d)", vctx, buf->length);
				kfree(planes);
				kfree(buf);
				ret = -EINVAL;
				goto p_err;
			}
			dmabuf = dma_buf_get(planes[plane].m.fd);
			if (IS_ERR(dmabuf)) {
				merr("dma_buf_get failed(%p)", vctx, dmabuf);
				kfree(planes);
				kfree(buf);
				ret = -EINVAL;
				goto p_err;
			}

			attachment = dma_buf_attach(dmabuf, &device->pdev->dev);
			if (IS_ERR(attachment)) {
				merr("dma_buf_attach failed(%p)", vctx, attachment);
				kfree(planes);
				kfree(buf);
				dma_buf_put(dmabuf);
				ret = -EINVAL;
				goto p_err;
			}

			write = !V4L2_TYPE_IS_OUTPUT(buf->type);
			dva = ion_iovmm_map(attachment, 0, dmabuf->size, write, plane);
			if (IS_ERR_VALUE(dva)) {
				merr("ion_iovmm_map failed(%X)", vctx, dva);
				kfree(planes);
				kfree(buf);
				dma_buf_detach(dmabuf, attachment);
				dma_buf_put(dmabuf);
				ret = -EINVAL;
				goto p_err;
			}

			group_id = GROUP_ID(device->group_isp.id);
			ret = fimc_is_itf_map(device, group_id, dva, dmabuf->size);
			if (ret) {
				merr("fimc_is_itf_map failed(%d)", vctx, ret);
				kfree(planes);
				kfree(buf);
				dma_buf_detach(dmabuf, attachment);
				dma_buf_put(dmabuf);
				goto p_err;
			}

			minfo("[ISP:V] buffer%d.plane%d mapping\n", vctx, buf->index, plane);
			set_bit(FRAME_MAP_MEM, &frame->memory);
			dma_buf_detach(dmabuf, attachment);
			dma_buf_put(dmabuf);
			kfree(planes);
			kfree(buf);
		}
		break;
#endif
	default:
		err("unsupported ioctl(%d)\n", ctrl->id);
		ret = -EINVAL;
		break;
	}

#if 0
p_err:
#endif
	return ret;
}

static int fimc_is_isp_video_g_ctrl(struct file *file, void *priv,
	struct v4l2_control *ctrl)
{
	int ret = 0;
	struct fimc_is_video_ctx *vctx = file->private_data;
	struct fimc_is_device_ischain *ischain = vctx->device;

	dbg_isp("%s\n", __func__);

	switch (ctrl->id) {
	case V4L2_CID_IS_BDS_WIDTH:
		ctrl->value = ischain->chain0_width;
		break;
	case V4L2_CID_IS_BDS_HEIGHT:
		ctrl->value = ischain->chain0_height;
		break;
	default:
		err("unsupported ioctl(%d)\n", ctrl->id);
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int fimc_is_isp_video_g_ext_ctrl(struct file *file, void *priv,
	struct v4l2_ext_controls *ctrls)
{
	int ret = 0;
	struct v4l2_ext_control *ctrl;

	dbg_isp("%s\n", __func__);


	ctrl = ctrls->controls;

	switch (ctrl->id) {
	default:
		err("unsupported ioctl(%d)\n", ctrl->id);
		ret = -EINVAL;
		break;
	}

	return ret;
}

const struct v4l2_ioctl_ops fimc_is_isp_video_ioctl_ops = {
	.vidioc_querycap		= fimc_is_isp_video_querycap,
	.vidioc_enum_fmt_vid_out_mplane	= fimc_is_isp_video_enum_fmt_mplane,
	.vidioc_g_fmt_vid_out_mplane	= fimc_is_isp_video_get_format_mplane,
	.vidioc_s_fmt_vid_out_mplane	= fimc_is_isp_video_set_format_mplane,
	.vidioc_cropcap			= fimc_is_isp_video_cropcap,
	.vidioc_g_crop			= fimc_is_isp_video_get_crop,
	.vidioc_s_crop			= fimc_is_isp_video_set_crop,
	.vidioc_reqbufs			= fimc_is_isp_video_reqbufs,
	.vidioc_querybuf		= fimc_is_isp_video_querybuf,
	.vidioc_qbuf			= fimc_is_isp_video_qbuf,
	.vidioc_dqbuf			= fimc_is_isp_video_dqbuf,
	.vidioc_streamon		= fimc_is_isp_video_streamon,
	.vidioc_streamoff		= fimc_is_isp_video_streamoff,
	.vidioc_enum_input		= fimc_is_isp_video_enum_input,
	.vidioc_g_input			= fimc_is_isp_video_g_input,
	.vidioc_s_input			= fimc_is_isp_video_s_input,
	.vidioc_s_ctrl			= fimc_is_isp_video_s_ctrl,
	.vidioc_g_ctrl			= fimc_is_isp_video_g_ctrl,
	.vidioc_g_ext_ctrls		= fimc_is_isp_video_g_ext_ctrl,
};

static int fimc_is_isp_queue_setup(struct vb2_queue *vbq,
	const struct v4l2_format *fmt,
	unsigned int *num_buffers, unsigned int *num_planes,
	unsigned int sizes[],
	void *allocators[])
{
	int ret = 0;
	struct fimc_is_video_ctx *vctx = vbq->drv_priv;
	struct fimc_is_video *video;
	struct fimc_is_queue *queue;

	BUG_ON(!vctx);
	BUG_ON(!vctx->video);

	mdbgv_isp("%s\n", vctx, __func__);

	queue = GET_SRC_QUEUE(vctx);
	video = vctx->video;

	ret = fimc_is_queue_setup(queue,
		video->alloc_ctx,
		num_planes,
		sizes,
		allocators);
	if (ret)
		merr("fimc_is_queue_setup failed(%d)", vctx, ret);

	return ret;
}

static int fimc_is_isp_buffer_prepare(struct vb2_buffer *vb)
{
	/*dbg_isp("%s\n", __func__);*/
	return 0;
}

static inline void fimc_is_isp_wait_prepare(struct vb2_queue *vbq)
{
	fimc_is_queue_wait_prepare(vbq);
}

static inline void fimc_is_isp_wait_finish(struct vb2_queue *vbq)
{
	fimc_is_queue_wait_finish(vbq);
}

static int fimc_is_isp_start_streaming(struct vb2_queue *vbq,
	unsigned int count)
{
	int ret = 0;
	struct fimc_is_video_ctx *vctx = vbq->drv_priv;
	struct fimc_is_queue *queue;
	struct fimc_is_device_ischain *device;
	struct fimc_is_subdev *leader;

	BUG_ON(!vctx);

	mdbgv_isp("%s\n", vctx, __func__);

	queue = GET_SRC_QUEUE(vctx);
	device = vctx->device;
	leader = &device->group_isp.leader;

	ret = fimc_is_queue_start_streaming(queue, device, leader, vctx);
	if (ret)
		merr("fimc_is_queue_start_streaming failed(%d)", vctx, ret);

	return ret;
}

static void fimc_is_isp_stop_streaming(struct vb2_queue *q)
{
	int ret = 0;
	struct fimc_is_video_ctx *vctx = q->drv_priv;
	struct fimc_is_queue *queue;
	struct fimc_is_device_ischain *device;
	struct fimc_is_subdev *leader;

	BUG_ON(!vctx);

	mdbgv_isp("%s\n", vctx, __func__);

	queue = GET_SRC_QUEUE(vctx);
	device = vctx->device;
	if (!device) {
		err("device is NULL");
		return;
	}
	leader = &device->group_isp.leader;

	ret = fimc_is_queue_stop_streaming(queue, device, leader, vctx);
	if (ret)
		merr("fimc_is_queue_stop_streaming failed(%d)", vctx, ret);
}

static void fimc_is_isp_buffer_queue(struct vb2_buffer *vb)
{
	int ret = 0;
	u32 index;
	struct fimc_is_video_ctx *vctx = vb->vb2_queue->drv_priv;
	struct fimc_is_queue *queue;
	struct fimc_is_video *video;
	struct fimc_is_device_ischain *device;

	BUG_ON(!vctx);
	index = vb->v4l2_buf.index;

#ifdef DBG_STREAMING
	mdbgv_isp("%s(%d)\n", vctx, __func__, index);
#endif

	queue = GET_SRC_QUEUE(vctx);
	video = vctx->video;
	device = vctx->device;

	ret = fimc_is_queue_buffer_queue(queue, video->vb2, vb);
	if (ret) {
		merr("fimc_is_queue_buffer_queue failed(%d)", vctx, ret);
		return;
	}

	ret = fimc_is_ischain_isp_buffer_queue(device, queue, index);
	if (ret) {
		merr("fimc_is_ischain_isp_buffer_queue failed(%d)", vctx, ret);
		return;
	}
}

static void fimc_is_isp_buffer_finish(struct vb2_buffer *vb)
{
	struct fimc_is_video_ctx *vctx = vb->vb2_queue->drv_priv;
	struct fimc_is_device_ischain *device = vctx->device;

	if (vb->state != VB2_BUF_STATE_DONE && vb->state != VB2_BUF_STATE_ERROR) {
		merr("unsupported buffer state %d", vctx, vb->state);
		return;
	}

#ifdef DBG_STREAMING
	mdbgv_isp("%s(%d)\n", vctx, __func__, vb->v4l2_buf.index);
#endif

	fimc_is_ischain_isp_buffer_finish(device, vb->v4l2_buf.index);
}

const struct vb2_ops fimc_is_isp_qops = {
	.queue_setup		= fimc_is_isp_queue_setup,
	.buf_prepare		= fimc_is_isp_buffer_prepare,
	.buf_queue		= fimc_is_isp_buffer_queue,
	.buf_finish		= fimc_is_isp_buffer_finish,
	.wait_prepare		= fimc_is_isp_wait_prepare,
	.wait_finish		= fimc_is_isp_wait_finish,
	.start_streaming	= fimc_is_isp_start_streaming,
	.stop_streaming		= fimc_is_isp_stop_streaming,
};
