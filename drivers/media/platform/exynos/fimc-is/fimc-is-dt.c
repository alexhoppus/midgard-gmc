/*
 * Samsung Exynos5 SoC series FIMC-IS driver
 *
 * exynos5 fimc-is core functions
 *
 * Copyright (c) 2011 Samsung Electronics Co., Ltd
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/sched.h>
#include "exynos-fimc-is-sensor.h"
#include "exynos-fimc-is.h"
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/regmap.h>
#include <linux/mfd/syscon.h>

#include "fimc-is-core.h"
#include "fimc-is-dt.h"

int get_pin_lookup_state(struct device *dev,
	struct exynos_platform_fimc_is_sensor *pdata)
{
	int ret = 0;
	u32 i, j, k;
	char ch_name[30];
	struct exynos_sensor_pin (*pin_ctrls)[2][GPIO_CTRL_MAX];
	struct pinctrl_state *s;

	pin_ctrls = pdata->pin_ctrls;

	for (i = 0; i < SENSOR_SCENARIO_MAX; ++i) {
		for (j = 0; j < GPIO_SCENARIO_MAX; ++j) {
			for (k = 0; k < GPIO_CTRL_MAX; ++k) {
				if (pin_ctrls[i][j][k].act == PIN_FUNCTION) {
					snprintf(ch_name, sizeof(ch_name), "%s%d",
							pin_ctrls[i][j][k].name,
							pdata->csi_ch);
					s = pinctrl_lookup_state(pdata->pinctrl, ch_name);
					if (IS_ERR(s)) {
						err("cam %s, ch %d pinctrl_lookup_state failed", ch_name, pdata->csi_ch);
						ret = -EINVAL;
						goto p_err;
					} else {
						pin_ctrls[i][j][k].pin = (unsigned long)s;
						pr_info("[%d][%d][%d][%s] gpio function cfg is seted", i, j, k, ch_name);
					}
				}
			}
		}
	}

p_err:
	return ret;
}

static int parse_subip_info(struct exynos_platform_fimc_is *pdata, struct device_node *np)
{
	u32 temp;
	char *pprop;
	struct exynos_fimc_is_subip_info *subip_info;

	/* get subip of fimc-is info */
	subip_info = kzalloc(sizeof(struct exynos_fimc_is_subip_info), GFP_KERNEL);
	if (!subip_info) {
		printk(KERN_ERR "%s: no memory for fimc_is subip_info\n", __func__);
		return -EINVAL;
	}

	DT_READ_U32(np, "num_of_mcuctl", subip_info->_mcuctl.valid);
	DT_READ_U32(np, "num_of_3a0", subip_info->_3a0.valid);
	DT_READ_U32(np, "num_of_3a1", subip_info->_3a1.valid);
	DT_READ_U32(np, "num_of_isp", subip_info->_isp.valid);
	DT_READ_U32(np, "num_of_drc", subip_info->_drc.valid);
	DT_READ_U32(np, "num_of_scc", subip_info->_scc.valid);
	DT_READ_U32(np, "num_of_odc", subip_info->_odc.valid);
	DT_READ_U32(np, "num_of_dis", subip_info->_dis.valid);
	DT_READ_U32(np, "num_of_dnr", subip_info->_dnr.valid);
	DT_READ_U32(np, "num_of_scp", subip_info->_scp.valid);
	DT_READ_U32(np, "num_of_fd",  subip_info->_fd.valid);

	DT_READ_U32(np, "full_bypass_mcuctl", subip_info->_mcuctl.full_bypass);
	DT_READ_U32(np, "full_bypass_3a0", subip_info->_3a0.full_bypass);
	DT_READ_U32(np, "full_bypass_3a1", subip_info->_3a1.full_bypass);
	DT_READ_U32(np, "full_bypass_isp", subip_info->_isp.full_bypass);
	DT_READ_U32(np, "full_bypass_drc", subip_info->_drc.full_bypass);
	DT_READ_U32(np, "full_bypass_scc", subip_info->_scc.full_bypass);
	DT_READ_U32(np, "full_bypass_odc", subip_info->_odc.full_bypass);
	DT_READ_U32(np, "full_bypass_dis", subip_info->_dis.full_bypass);
	DT_READ_U32(np, "full_bypass_dnr", subip_info->_dnr.full_bypass);
	DT_READ_U32(np, "full_bypass_scp", subip_info->_scp.full_bypass);
	DT_READ_U32(np, "full_bypass_fd",  subip_info->_fd.full_bypass);

	DT_READ_U32(np, "version_mcuctl", subip_info->_mcuctl.version);
	DT_READ_U32(np, "version_3a0", subip_info->_3a0.version);
	DT_READ_U32(np, "version_3a1", subip_info->_3a1.version);
	DT_READ_U32(np, "version_isp", subip_info->_isp.version);
	DT_READ_U32(np, "version_drc", subip_info->_drc.version);
	DT_READ_U32(np, "version_scc", subip_info->_scc.version);
	DT_READ_U32(np, "version_odc", subip_info->_odc.version);
	DT_READ_U32(np, "version_dis", subip_info->_dis.version);
	DT_READ_U32(np, "version_dnr", subip_info->_dnr.version);
	DT_READ_U32(np, "version_scp", subip_info->_scp.version);
	DT_READ_U32(np, "version_fd",  subip_info->_fd.version);

	pdata->subip_info = subip_info;

	return 0;
}

int fimc_is_power_initpin(struct device *dev)
{
	struct exynos_platform_fimc_is_sensor *pdata;
	int gpio_none = 0;

	BUG_ON(!dev);
	BUG_ON(!dev->platform_data);

	pdata = dev->platform_data;

	if (!pdata->sensor_id || (pdata->sensor_id >= SENSOR_NAME_END)) {
		err("check the sensor id. sensor_id %d", pdata->sensor_id);
		return -ENODEV;
	}

	/* POWER ON */
	SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_ON, 0, gpio_none, 0, NULL, 0, PIN_END);

	/* POWER OFF */
	SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_OFF, 0, gpio_none, 0, NULL, 0, PIN_END);

	return 0;
}

int fimc_is_power_setpin(struct device *dev, int position, int sensor_id)
{
	struct fimc_is_core *core;
	struct fimc_is_device_sensor *sensor;
	int ret = 0;
	int i, pos, found;

	if (!fimc_is_dev) {
		err("fimc_is_dev is not yet probed");
		return -ENODEV;
	}

	if (!sensor_id || (sensor_id >= SENSOR_NAME_END)) {
		err("check the sensor id. sensor_id %d", sensor_id);
		return -ENODEV;
	}

	core = dev_get_drvdata(fimc_is_dev);
	if (!core) {
		err("core is NULL");
		return -EINVAL;
	}

	if (!atomic_read(&core->resourcemgr.rsccount_module))
		err("sensor driver not probed");

	sensor = &core->sensor[position];

	/* Call power_setpin and return  */
	for (i = 0; i < atomic_read(&core->resourcemgr.rsccount_module); i++) {
		if (sensor_id == sensor->module_enum[i].id) {
			info("%s: sensor found(id %d). %s\n", __func__, sensor_id,
				(position == sensor->module_enum[i].position) ? "" : "position not matched");

			if (sensor->module_enum[i].power_setpin)
				ret = sensor->module_enum[i].power_setpin(dev);

			return ret;
		}
	}

	/* Enumerate probed sensor lists if not found */
	for (pos = 0, found = 0; pos < FIMC_IS_MAX_NODES; pos++, found = 0) {
		sensor = &core->sensor[pos];
		for (i = 0; i < atomic_read(&core->resourcemgr.rsccount_module); i++) {
			if (sensor->module_enum[i].id) {
				info("Camera sensor %d: id %3d. %s\n", pos, sensor->module_enum[i].id,
					sensor->module_enum[i].setfile_name ?
					sensor->module_enum[i].setfile_name : "");
				found++;
			}
		}

		if (!found)
			info("Camera sensor %d: none\n", pos);
	}

	err("sensor not found (pos %d, id %d)", position, sensor_id);

	return 0;
}

struct exynos_platform_fimc_is *fimc_is_parse_dt(struct device *dev)
{
	void *ret = NULL;
	struct exynos_platform_fimc_is *pdata;
	struct device_node *subip_info_np;
	struct device_node *np = dev->of_node;
	int retVal = 0;

	if (!np)
		return ERR_PTR(-ENOENT);

	pdata = kzalloc(sizeof(struct exynos_platform_fimc_is), GFP_KERNEL);
	if (!pdata) {
		printk(KERN_ERR "%s: no memory for platform data\n", __func__);
		return ERR_PTR(-ENOMEM);
	}

	pdata->clk_cfg = exynos_fimc_is_cfg_clk;
	pdata->clk_on = exynos_fimc_is_clk_on;
	pdata->clk_off = exynos_fimc_is_clk_off;
	pdata->print_clk = exynos_fimc_is_print_clk;
	pdata->print_cfg = exynos_fimc_is_print_cfg;
	pdata->print_pwr = exynos_fimc_is_print_pwr;

	dev->platform_data = pdata;

	retVal = of_property_read_u32(np, "companion_spi_channel", &pdata->companion_spi_channel);
	if (retVal) {
		err("spi_channel read failed(%d)", retVal);
	}

	pdata->use_two_spi_line = of_property_read_bool(np, "use_two_spi_line");
	retVal = of_property_read_u32(np, "use_sensor_dynamic_voltage_mode", &pdata->use_sensor_dynamic_voltage_mode);
	if (retVal) {
		err("use_sensor_dynamic_voltage_mode read failed(%d)", retVal);
		pdata->use_sensor_dynamic_voltage_mode = 0;
	}
	pdata->use_ois = of_property_read_bool(np, "use_ois");
	if (!pdata->use_ois) {
		err("use_ois not use(%d)", pdata->use_ois);
	}
	pdata->use_ois_hsi2c = of_property_read_bool(np, "use_ois_hsi2c");
	if (!pdata->use_ois_hsi2c) {
		err("use_ois_hsi2c not use(%d)", pdata->use_ois_hsi2c);
	}

	pdata->use_module_check = of_property_read_bool(np, "use_module_check");
	if (!pdata->use_module_check) {
		err("use_module_check not use(%d)", pdata->use_module_check);
	}
	subip_info_np = of_find_node_by_name(np, "subip_info");
	if (!subip_info_np) {
		printk(KERN_ERR "%s: can't find fimc_is subip_info node\n", __func__);
		ret = ERR_PTR(-ENOENT);
		goto p_err;
	}
	parse_subip_info(pdata, subip_info_np);

	return pdata;
p_err:
	kfree(pdata);
	return ret;
}

int fimc_is_parse_children_dt(struct device *dev, struct fimc_is_core *core)
{
	struct device_node *np = dev->of_node;
	struct device_node *child;

	for_each_available_child_of_node(np, child) {
		int i;

		i = of_alias_get_id(child, "fimc-lite");
		if (i >= 0 && i < FIMC_IS_MAX_NODES)
			core->lite_np[i] = child;

		i = of_alias_get_id(child, "csis");
		if (i >= 0 && i < FIMC_IS_MAX_NODES)
			core->csis_np[i] = child;
	}

	core->pmu_regmap = syscon_regmap_lookup_by_phandle(np,
						"samsung,pmureg-phandle");

	return 0;
}

int fimc_is_sensor_parse_dt(struct platform_device *pdev)
{
	int ret = 0;
	u32 temp;
	char *pprop;
	struct exynos_platform_fimc_is_sensor *pdata;
	struct device_node *dnode;
	struct device *dev;
	const char *name;
	u32 id;

	BUG_ON(!pdev);
	BUG_ON(!pdev->dev.of_node);

	dev = &pdev->dev;
	dnode = dev->of_node;

	pdata = kzalloc(sizeof(struct exynos_platform_fimc_is_sensor), GFP_KERNEL);
	if (!pdata) {
		pr_err("%s: no memory for platform data\n", __func__);
		return -ENOMEM;
	}

	pdata->gpio_cfg = exynos_fimc_is_sensor_pins_cfg;
	pdata->iclk_cfg = exynos_fimc_is_sensor_iclk_cfg;
	pdata->iclk_on = exynos_fimc_is_sensor_iclk_on;
	pdata->iclk_off = exynos_fimc_is_sensor_iclk_off;
	pdata->mclk_on = exynos_fimc_is_sensor_mclk_on;
	pdata->mclk_off = exynos_fimc_is_sensor_mclk_off;

	ret = of_property_read_u32(dnode, "scenario", &pdata->scenario);
	if (ret) {
		err("scenario read failed(%d)", ret);
		goto p_err;
	}

	ret = of_property_read_u32(dnode, "mclk_ch", &pdata->mclk_ch);
	if (ret) {
		err("mclk_ch read failed(%d)", ret);
		goto p_err;
	}

	ret = of_property_read_u32(dnode, "csi_ch", &pdata->csi_ch);
	if (ret) {
		err("csi_ch read failed(%d)", ret);
		goto p_err;
	}

	ret = of_property_read_u32(dnode, "flite_ch", &pdata->flite_ch);
	if (ret) {
		err("flite_ch read failed(%d)", ret);
		goto p_err;
	}

	ret = of_property_read_u32(dnode, "i2c_ch", &pdata->i2c_ch);
	if (ret) {
		err("i2c_ch read failed(%d)", ret);
		goto p_err;
	}

	ret = of_property_read_u32(dnode, "i2c_addr", &pdata->i2c_addr);
	if (ret) {
		err("i2c_addr read failed(%d)", ret);
		goto p_err;
	}

	ret = of_property_read_u32(dnode, "is_bns", &pdata->is_bns);
	if (ret) {
		err("is_bns read failed(%d)", ret);
		goto p_err;
	}

	ret = of_property_read_u32(dnode, "id", &id);
	if (ret) {
		err("id read failed(%d)", ret);
		goto p_err;
	}

	DT_READ_U32(dnode, "flash_first_gpio", pdata->flash_first_gpio);
	DT_READ_U32(dnode, "flash_second_gpio", pdata->flash_second_gpio);

	ret = of_property_read_string(dnode, "sensor_name", &name);
	if (ret) {
		err("sensor_name read failed(%d)", ret);
		goto p_err;
	}
	strcpy(pdata->sensor_name, name);

	ret = of_property_read_u32(dnode, "sensor_id", &pdata->sensor_id);
	if (ret) {
		err("sensor_id read failed(%d)", ret);
		goto p_err;
	}

	dev->platform_data = pdata;

	ret = fimc_is_power_setpin(dev, id, pdata->sensor_id);
	if (ret)
		err("power_setpin failed(%d). id %d", ret, id);

	pdev->id = id;

	pdata->pinctrl = devm_pinctrl_get(dev);
	if (IS_ERR(pdata->pinctrl)) {
		err("devm_pinctrl_get failed");
		goto p_err;
	} else {
		ret = get_pin_lookup_state(dev, pdata);
		if (ret < 0) {
			err("fimc_is_get_pin_lookup_state failed");
			goto p_err;
		}
	}

	return ret;

p_err:
	kfree(pdata);
	return ret;
}
