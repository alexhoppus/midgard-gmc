/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * Header for EXYNOS PMU Driver support
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __EXYNOS_PMU_PRIV_H
#define __EXYNOS_PMU_PRIV_H

#include <linux/io.h>

#define PMU_TABLE_END	(-1U)

extern void __iomem *pmu_base_addr;

struct exynos_pmu_conf {
	unsigned int offset;
	u8 val[NUM_SYS_POWERDOWN];
};

struct exynos_pmu_conf_extra {
	u32 offset;
	u32 val[NUM_SYS_POWERDOWN];
};

struct exynos_pmu_data {
	const struct exynos_pmu_conf *pmu_config;
	const struct exynos_pmu_conf_extra *pmu_config_extra;

	void (*pmu_init)(void);
	void (*powerdown_conf)(enum sys_powerdown);
	void (*powerdown_conf_extra)(enum sys_powerdown);
	void (*powerup_conf)(enum sys_powerdown);
};

static inline void pmu_raw_writel(u32 val, u32 offset)
{
	writel_relaxed(val, pmu_base_addr + offset);
}

static inline u32 pmu_raw_readl(u32 offset)
{
	return readl_relaxed(pmu_base_addr + offset);
}

extern u32 exynos_get_eint_wake_mask(void);

/* list of all exported SoC specific data */
extern const struct exynos_pmu_data exynos5433_pmu_data;

#define REBOOT_MODE_PREFIX	0x12345670
#define REBOOT_MODE_NONE	0
#define REBOOT_MODE_DOWNLOAD	1
#define REBOOT_MODE_UPLOAD	2
#define REBOOT_MODE_CHARGING	3
#define REBOOT_MODE_RECOVERY	4
#define REBOOT_MODE_FOTA	5
#define REBOOT_MODE_FOTA_BL	6		/* update bootloader */
#define REBOOT_MODE_SECURE	7		/* image secure check fail */

#define REBOOT_SET_PREFIX	0xabc00000
#define REBOOT_SET_DEBUG	0x000d0000
#define REBOOT_SET_SWSEL	0x000e0000
#define REBOOT_SET_SUD		0x000f0000

#endif /* __EXYNOS_PMU_PRIV_H */
