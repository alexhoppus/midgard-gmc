/*
 * Copyright (C) 2015 Samsung Electronics Co., Ltd.
 *	Inha Song <ideal.song@samsung.com>
 *
 * Low Power Audio SubSystem driver for Samsung Exynos
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#include <linux/delay.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <sound/soc.h>
#include <linux/mfd/syscon.h>
#include <linux/regmap.h>

#include "lpass.h"

#define EXYNOS5433_PAD_RETENTION_AUD_OPTION_OFFSET	0x3028
#define EXYNOS5433_INITIATE_WAKEUP_FROM_LOWPWR_MASK	BIT(28)

struct lpass_info {
	struct platform_device	*pdev;
	void __iomem		*reg_sfr;
	struct regmap		*reg_pmu;
};

static void lpass_core_sw_reset(struct lpass_info *lpass, int bit)
{
	unsigned int val;

	val = readl(lpass->reg_sfr + SFR_LPASS_CORE_SW_RESET);

	val &= ~(1 << bit);
	writel(val, lpass->reg_sfr + SFR_LPASS_CORE_SW_RESET);

	udelay(100);

	val |= 1 << bit;
	writel(val, lpass->reg_sfr + SFR_LPASS_CORE_SW_RESET);
}

static void lpass_enable(struct lpass_info *lpass)
{
	if (!lpass->reg_pmu)
		return;

	/* Unmasks SFR, DMA, I2S Interrupt */
	writel(LPASS_INTR_SFR | LPASS_INTR_DMA | LPASS_INTR_I2S,
	       lpass->reg_sfr + SFR_LPASS_INTR_CA5_MASK);

	writel(LPASS_INTR_DMA | LPASS_INTR_I2S | LPASS_INTR_SFR
			| LPASS_INTR_UART,
	       lpass->reg_sfr + SFR_LPASS_INTR_CPU_MASK);

	/* Active related PADs from retention state */
	regmap_write(lpass->reg_pmu,
		     EXYNOS5433_PAD_RETENTION_AUD_OPTION_OFFSET,
		     EXYNOS5433_INITIATE_WAKEUP_FROM_LOWPWR_MASK);

	lpass_core_sw_reset(lpass, SW_RESET_I2S);
	lpass_core_sw_reset(lpass, SW_RESET_DMA);
	lpass_core_sw_reset(lpass, SW_RESET_MEM);
}

static void lpass_disable(struct lpass_info *lpass)
{
	if (!lpass->reg_pmu)
		return;

	/* Masks SFR, DMA, I2S Interrupt */
	writel(0, lpass->reg_sfr + SFR_LPASS_INTR_CA5_MASK);

	writel(0, lpass->reg_sfr + SFR_LPASS_INTR_CPU_MASK);

	/* Inactive related PADs from retention state */
	regmap_write(lpass->reg_pmu,
		     EXYNOS5433_PAD_RETENTION_AUD_OPTION_OFFSET, 0);
}

static int lpass_probe(struct platform_device *pdev)
{
	struct lpass_info *lpass;
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;
	struct resource *res;

	if (!np) {
		dev_err(dev, "Failed to get DT node\n");
		return -ENODEV;
	}

	lpass = devm_kzalloc(dev, sizeof(*lpass), GFP_KERNEL);
	if (!lpass)
		return -ENOMEM;

	lpass->pdev = pdev;
	platform_set_drvdata(pdev, lpass);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(dev, "Failed to get SFR address\n");
		return -ENXIO;
	}

	lpass->reg_sfr = devm_ioremap_resource(dev, res);
	if (IS_ERR(lpass->reg_sfr))
		return PTR_ERR(lpass->reg_sfr);

	lpass->reg_pmu = syscon_regmap_lookup_by_phandle(np,
							 "samsung,pmu-syscon");
	if (IS_ERR(lpass->reg_pmu)) {
		dev_err(dev, "Failed to lookup PMU regmap\n");
		return PTR_ERR(lpass->reg_pmu);
	}

	lpass_enable(lpass);

	return 0;
}

static int lpass_suspend(struct device *dev)
{
	struct lpass_info *lpass = dev_get_drvdata(dev);

	lpass_disable(lpass);

	return 0;
}

static int lpass_resume(struct device *dev)
{
	struct lpass_info *lpass = dev_get_drvdata(dev);

	lpass_enable(lpass);

	return 0;
}

static const struct of_device_id lpass_of_match[] = {
	{ .compatible	= "samsung,exynos5433-lpass", },
	{ },
};
MODULE_DEVICE_TABLE(of, lpass_of_match);

static const struct dev_pm_ops lpass_pm_ops = {
	.suspend = lpass_suspend,
	.resume	= lpass_resume,
};

static struct platform_driver lpass_driver = {
	.driver = {
		.name		= "samsung-lpass",
		.owner		= THIS_MODULE,
		.pm		= &lpass_pm_ops,
		.of_match_table	= lpass_of_match,
	},
	.probe	= lpass_probe,
};

module_platform_driver(lpass_driver);

MODULE_AUTHOR("Inha Song <ideal.song@samsung.com>");
MODULE_DESCRIPTION("Samsung Low Power Audio Subsystem Interface");
MODULE_LICENSE("GPL v2");
