/*
 * Generic big.LITTLE CPUFreq Interface driver
 *
 * It provides necessary ops to arm_big_little cpufreq driver and gets
 * Frequency information from Device Tree. Freq table in DT must be in KHz.
 *
 * Copyright (C) 2013 Linaro.
 * Viresh Kumar <viresh.kumar@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cpufreq.h>
#include <linux/device.h>
#include <linux/export.h>
#include <linux/module.h>
#include <linux/of_device.h>
#include <linux/pm_opp.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/types.h>
#include "arm_big_little.h"

/* get cpu node with valid operating-points */
static struct device_node *get_cpu_node_with_valid_op(int cpu)
{
	struct device_node *np = of_cpu_device_node_get(cpu);

	if (!of_get_property(np, "operating-points", NULL)) {
		of_node_put(np);
		np = NULL;
	}

	return np;
}

static int dt_init_opp_table(struct device *cpu_dev)
{
	struct device_node *np;
	int ret;

	np = of_node_get(cpu_dev->of_node);
	if (!np) {
		pr_err("failed to find cpu%d node\n", cpu_dev->id);
		return -ENOENT;
	}

	ret = of_init_opp_table(cpu_dev);
	of_node_put(np);

	return ret;
}

static int dt_get_transition_latency(struct device *cpu_dev)
{
	struct device_node *np;
	int ret;
	u32 transition_latency = CPUFREQ_ETERNAL;

	np = of_node_get(cpu_dev->of_node);
	if (!np) {
		pr_info("Failed to find cpu node. Use CPUFREQ_ETERNAL transition latency\n");
		return CPUFREQ_ETERNAL;
	}

	ret = of_property_read_u32(np, "clock-latency", &transition_latency);
	if (ret) {
		struct device *first_cpu = topology_first_cpu(cpu_dev->id);
		if (cpu_dev != first_cpu)
			transition_latency =
				dt_get_transition_latency(first_cpu);
	}
	of_node_put(np);

	pr_debug("%s: clock-latency: %d\n", __func__, transition_latency);
	return transition_latency;
}

static void dt_free_opp_table(struct device *cpu_dev)
{
	struct device *first_cpu;

	if (of_get_property(cpu_dev->of_node, "operating-points", NULL)) {
		of_free_opp_table(cpu_dev);
		goto out;
	}

	first_cpu = topology_first_cpu(cpu_dev->id);
	if (cpu_dev != first_cpu)
		of_free_opp_table(first_cpu);
out:
	return;
}

static struct cpufreq_arm_bL_ops dt_bL_ops = {
	.name	= "dt-bl",
	.get_transition_latency = dt_get_transition_latency,
	.init_opp_table = dt_init_opp_table,
	.free_opp_table = dt_free_opp_table,
};

static inline int bL_cpufreq_get_suspend_freq(struct device *dev,
						int *suspend_freq)
{
	struct device *first_cpu;
	int ret;

	ret = of_property_read_u32(dev->of_node, "suspend-freq", suspend_freq);
	if (!ret)
		goto out;

	first_cpu = topology_first_cpu(dev->id);
	if (dev != first_cpu)
		ret = of_property_read_u32(first_cpu->of_node,
					"suspend-freq", suspend_freq);
out:
	return ret;
}

static int bL_cpufreq_add_dev(struct device *dev, struct subsys_interface *sif)
{
	int cpu = dev->id;
	u32 freq;

	if (!dev->of_node)
		return -ENODEV;

	if (!bL_cpufreq_get_suspend_freq(dev, &freq)) {
		struct cpufreq_policy *policy;

		policy = cpufreq_cpu_get(cpu);
		if (!policy)
			goto out;

		policy->suspend_freq = freq;

		cpufreq_cpu_put(policy);

		if (!dt_bL_ops.suspend)
			dt_bL_ops.suspend = cpufreq_generic_suspend;
	}
out:
	return 0;
}

static struct subsys_interface bL_cpufreq_interface = {
	.name		= "arm-bL-cpufreq",
	.subsys		= &cpu_subsys,
	.add_dev	= bL_cpufreq_add_dev,
};

static int generic_bL_probe(struct platform_device *pdev)
{
	struct device_node *np;
	int ret;

	np = get_cpu_node_with_valid_op(0);
	if (!np)
		return -ENODEV;

	of_node_put(np);

	ret = bL_cpufreq_register(&dt_bL_ops);
	if (ret)
		return ret;

	subsys_interface_register(&bL_cpufreq_interface);

	return 0;
}

static int generic_bL_remove(struct platform_device *pdev)
{
	bL_cpufreq_unregister(&dt_bL_ops);
	return 0;
}

static const struct of_device_id generic_bL_of_match[] = {
	{ .compatible = "arm-bL-cpufreq-dt", },
	{ },
};
MODULE_DEVICE_TABLE(of, generic_bL_of_match);

static struct platform_driver generic_bL_platdrv = {
	.driver = {
		.name	= "arm-bL-cpufreq-dt",
		.of_match_table = of_match_ptr(generic_bL_of_match),
	},
	.probe		= generic_bL_probe,
	.remove		= generic_bL_remove,
};
module_platform_driver(generic_bL_platdrv);

MODULE_AUTHOR("Viresh Kumar <viresh.kumar@linaro.org>");
MODULE_DESCRIPTION("Generic ARM big LITTLE cpufreq driver via DT");
MODULE_LICENSE("GPL v2");
