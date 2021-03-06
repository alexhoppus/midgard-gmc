/* linux/arch/arm/plat-s5p/include/plat/fimc_is.h
 *
 * Copyright (C) 2011 Samsung Electronics, Co. Ltd
 *
 * Exynos 4 series FIMC-IS slave device support
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef EXYNOS_FIMC_IS_H_
#define EXYNOS_FIMC_IS_H_ __FILE__

#define FIMC_IS_MAKE_QOS_IDX_NM(__LV) __LV ## _IDX
#define FIMC_IS_DECLARE_QOS_ENUM(__TYPE) enum FIMC_IS_DVFS_ ## __TYPE ## _LV_IDX

#include <linux/videodev2.h>

#define FIMC_IS_DEV_NAME			"exynos-fimc-is"
#include <linux/platform_device.h>

/* FIMC-IS DVFS LEVEL enum (INT, MIF, I2C) */
enum FIMC_IS_INT_LV {
	FIMC_IS_INT_L0,
	FIMC_IS_INT_L1,
	FIMC_IS_INT_L1_1,
	FIMC_IS_INT_L1_2,
	FIMC_IS_INT_L1_3,
};

enum FIMC_IS_MIF_LV {
	FIMC_IS_MIF_L0,
	FIMC_IS_MIF_L1,
	FIMC_IS_MIF_L2,
	FIMC_IS_MIF_L3,
	FIMC_IS_MIF_L4,
};

/*
 * On some soc, It needs to notify change of INT clock to F/W.
 * Because I2C clock can be take affect from other clock change(like INT)
 */
enum FIMC_IS_I2C_LV {
	FIMC_IS_I2C_L0,
	FIMC_IS_I2C_L1,
	FIMC_IS_I2C_L1_1,
	FIMC_IS_I2C_L1_3,
};

/* FIMC-IS DVFS SCENARIO enum */
enum FIMC_IS_SCENARIO_ID {
	FIMC_IS_SN_DEFAULT,
	FIMC_IS_SN_FRONT_PREVIEW,
	FIMC_IS_SN_FRONT_CAPTURE,
	FIMC_IS_SN_FRONT_CAMCORDING,
	FIMC_IS_SN_FRONT_VT1,
	FIMC_IS_SN_FRONT_VT2,
	FIMC_IS_SN_REAR_PREVIEW_FHD,
	FIMC_IS_SN_REAR_PREVIEW_FHD_BNS_OFF,
	FIMC_IS_SN_REAR_PREVIEW_WHD,
	FIMC_IS_SN_REAR_PREVIEW_UHD,
	FIMC_IS_SN_REAR_CAPTURE,
	FIMC_IS_SN_REAR_CAMCORDING_FHD,
	FIMC_IS_SN_REAR_CAMCORDING_FHD_BNS_OFF,
	FIMC_IS_SN_REAR_CAMCORDING_WHD,
	FIMC_IS_SN_REAR_CAMCORDING_UHD,
	FIMC_IS_SN_DUAL_PREVIEW,
	FIMC_IS_SN_DUAL_CAPTURE,
	FIMC_IS_SN_DUAL_CAMCORDING,
	FIMC_IS_SN_HIGH_SPEED_FPS,
	FIMC_IS_SN_DIS_ENABLE,
	FIMC_IS_SN_MAX,
	FIMC_IS_SN_END,
};

enum FIMC_IS_DVFS_QOS_TYPE {
	FIMC_IS_DVFS_CPU_MIN,
	FIMC_IS_DVFS_CPU_MAX,
	FIMC_IS_DVFS_INT,
	FIMC_IS_DVFS_MIF,
	FIMC_IS_DVFS_I2C,
	FIMC_IS_DVFS_CAM,
	FIMC_IS_DVFS_DISP,
	FIMC_IS_DVFS_PWM,
	FIMC_IS_DVFS_END,
};

#define SET_QOS_WITH_CPU(t, s, i, m, _i, c, d, p, cmin, cmax)	\
	(t)[s][FIMC_IS_DVFS_INT]	= i;	\
	(t)[s][FIMC_IS_DVFS_MIF]	= m;	\
	(t)[s][FIMC_IS_DVFS_I2C]	= _i;	\
	(t)[s][FIMC_IS_DVFS_CAM]	= c;	\
	(t)[s][FIMC_IS_DVFS_DISP]	= d;	\
	(t)[s][FIMC_IS_DVFS_PWM]	= p;	\
	(t)[s][FIMC_IS_DVFS_CPU_MIN]	= cmin;	\
	(t)[s][FIMC_IS_DVFS_CPU_MAX]	= cmax;

#define SET_QOS(t, s, i, m, _i, c, d, p)	\
	(t)[s][FIMC_IS_DVFS_INT]	= i;	\
	(t)[s][FIMC_IS_DVFS_MIF]	= m;	\
	(t)[s][FIMC_IS_DVFS_I2C]	= _i;	\
	(t)[s][FIMC_IS_DVFS_CAM]	= c;	\
	(t)[s][FIMC_IS_DVFS_DISP]	= d;	\
	(t)[s][FIMC_IS_DVFS_PWM]	= p;	\
	(t)[s][FIMC_IS_DVFS_CPU_MIN]	= 0;	\
	(t)[s][FIMC_IS_DVFS_CPU_MAX]	= 0;

enum FIMC_IS_CLK_GATE {
	FIMC_IS_GATE_3AA1_IP,
	FIMC_IS_GATE_ISP_IP,
	FIMC_IS_GATE_DRC_IP,
	FIMC_IS_GATE_SCC_IP,
	FIMC_IS_GATE_ODC_IP,
	FIMC_IS_GATE_DIS_IP,
	FIMC_IS_GATE_3DNR_IP,
	FIMC_IS_GATE_SCP_IP,
	FIMC_IS_GATE_FD_IP,
	FIMC_IS_GATE_3AA0_IP,
	FIMC_IS_CLK_GATE_MAX,
};

enum FIMC_IS_GRP {
	FIMC_IS_GRP_3A0,
	FIMC_IS_GRP_3A1,
	FIMC_IS_GRP_ISP,
	FIMC_IS_GRP_DIS,
	FIMC_IS_GRP_MAX,
};

enum FIMC_IS_CLK_GATE_USR_SCENARIO {
	CLK_GATE_NOT_FULL_BYPASS_SN = 1,
	CLK_GATE_FULL_BYPASS_SN,
	CLK_GATE_DIS_SN,
};

/*
 * struct exynos_fimc_is_subip_info
 *   This info describes what and how many subip fimc-is has.
 *   In machine data, this info should be defined.
 */
struct exynos_fimc_is_subip_ext {
	bool valid;
	bool full_bypass;
	u32 version;
	u32 base_addr;
};

struct exynos_fimc_is_subip_info {
	/* You can add more new subip */
	struct exynos_fimc_is_subip_ext _mcuctl;
	struct exynos_fimc_is_subip_ext _3a0;
	struct exynos_fimc_is_subip_ext _3a1;
	struct exynos_fimc_is_subip_ext _isp;
	struct exynos_fimc_is_subip_ext _drc;
	struct exynos_fimc_is_subip_ext _scc;
	struct exynos_fimc_is_subip_ext _odc;
	struct exynos_fimc_is_subip_ext _dis;
	struct exynos_fimc_is_subip_ext _dnr;
	struct exynos_fimc_is_subip_ext _scp;
	struct exynos_fimc_is_subip_ext _fd;
	struct exynos_fimc_is_subip_ext _pwm;
};

/**
* struct exynos_platform_fimc_is - camera host interface platform data
*
* @isp_info: properties of camera sensor required for host interface setup
*/
struct exynos_platform_fimc_is {
	int	hw_ver;
	struct exynos_fimc_is_subip_info *subip_info;
	int	(*cfg_gpio)(struct platform_device *pdev, int channel, bool flag_on);
	int	(*clk_cfg)(struct platform_device *pdev);
	int	(*clk_on)(struct platform_device *pdev);
	int	(*clk_off)(struct platform_device *pdev);
	int	(*print_clk)(struct platform_device *pdev);
	int	(*print_cfg)(struct platform_device *pdev, u32 channel);
	int	(*print_pwr)(struct platform_device *pdev);

	u32	companion_spi_channel;
	bool	use_two_spi_line;
	u32	use_sensor_dynamic_voltage_mode;
	bool use_ois;
	bool use_ois_hsi2c;
	bool use_module_check;
};

extern struct device *fimc_is_dev;

extern void exynos_fimc_is_set_platdata(struct exynos_platform_fimc_is *pd);

int fimc_is_set_parent_dt(struct platform_device *pdev,
	const char *child, const char *parent);
int fimc_is_set_rate_dt(struct platform_device *pdev,
	const char *conid, unsigned int rate);
unsigned int  fimc_is_get_rate_dt(struct platform_device *pdev,
	const char *conid);
unsigned int  fimc_is_enable_dt(struct platform_device *pdev,
	const char *conid);
void  fimc_is_disable_dt(struct platform_device *pdev,
	const char *conid);

/* platform specific clock functions */
/* exynos 5 */
extern int exynos_fimc_is_cfg_clk(struct platform_device *pdev);
extern int exynos_fimc_is_cfg_cam_clk(struct platform_device *pdev);
extern int exynos_fimc_is_clk_on(struct platform_device *pdev);
extern int exynos_fimc_is_clk_off(struct platform_device *pdev);
extern int exynos_fimc_is_print_clk(struct platform_device *pdev);

extern int exynos_fimc_is_print_cfg(struct platform_device *pdev, u32 channel);
extern int exynos_fimc_is_print_pwr(struct platform_device *pdev);
#endif /* EXYNOS_FIMC_IS_H_ */
