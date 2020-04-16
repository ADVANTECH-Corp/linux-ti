/*
 * PRU Ethernet Driver sysfs file
 *
 * Copyright (C) 2018 Texas Instruments Incorporated - http://www.ti.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <linux/netdevice.h>
#include <linux/sysfs.h>
#include "prueth.h"

#define nsp_credit_to_emac(attr) \
	container_of(attr, struct prueth_emac, nsp_credit_attr)
#define prp_emac_mode_to_emac(attr) \
	container_of(attr, struct prueth_emac, prp_emac_mode_attr)

static ssize_t nsp_credit_store(struct device *dev,
				struct device_attribute *attr,
				const char *buffer, size_t count)
{
	struct prueth_emac *emac = nsp_credit_to_emac(attr);
	u32 val;

	if (kstrtou32(buffer, 0, &val))
		return -EINVAL;

	if (val)
		emac->nsp_credit =
			(val << PRUETH_NSP_CREDIT_SHIFT) | PRUETH_NSP_ENABLE;
	else
		emac->nsp_credit = PRUETH_NSP_DISABLE;

	return count;
}

static ssize_t nsp_credit_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buffer)
{
	struct prueth_emac *emac = nsp_credit_to_emac(attr);

	return snprintf(buffer, PAGE_SIZE, "%u\n",
			emac->nsp_credit >> PRUETH_NSP_CREDIT_SHIFT);
}
DEVICE_ATTR_RW(nsp_credit);

static ssize_t prp_emac_mode_store(struct device *dev,
				   struct device_attribute *attr,
				   const char *buffer, size_t count)
{
	struct prueth_emac *emac = prp_emac_mode_to_emac(attr);
	u32 emac_mode;
	int err;

	err = kstrtou32(buffer, 0, &emac_mode);
	if (err)
		return err;

	if (!PRUETH_HAS_PRP(emac->prueth))
		return -EINVAL;

	if (emac_mode > PRUETH_TX_PRP_EMAC_MODE)
		return -EINVAL;

	emac->prp_emac_mode = emac_mode;

	return count;
}

static ssize_t prp_emac_mode_show(struct device *dev,
				  struct device_attribute *attr,
				  char *buffer)
{
	struct prueth_emac *emac = prp_emac_mode_to_emac(attr);

	return snprintf(buffer, PAGE_SIZE, "%u\n", emac->prp_emac_mode);
}
DEVICE_ATTR_RW(prp_emac_mode);

int prueth_sysfs_init(struct prueth_emac *emac)
{
	int ret;

	emac->nsp_credit_attr = dev_attr_nsp_credit;
	sysfs_attr_init(&emac->nsp_credit_attr.attr);
	ret = device_create_file(&emac->ndev->dev, &emac->nsp_credit_attr);
	if (ret < 0)
		return ret;

	emac->prp_emac_mode_attr = dev_attr_prp_emac_mode;
	sysfs_attr_init(&emac->prp_emac_mode_attr.attr);
	ret = device_create_file(&emac->ndev->dev, &emac->prp_emac_mode_attr);
	if (ret < 0) {
		device_remove_file(&emac->ndev->dev, &emac->nsp_credit_attr);
		return ret;
	}
	return 0;
}

void prueth_remove_sysfs_entries(struct prueth_emac *emac)
{
	device_remove_file(&emac->ndev->dev, &emac->nsp_credit_attr);
	device_remove_file(&emac->ndev->dev, &emac->prp_emac_mode_attr);
}
