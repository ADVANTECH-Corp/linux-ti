/*
 * hsr_prp_debugfs code
 * Copyright (C) 2017 Texas Instruments Incorporated
 *
 * Author(s):
 *	Murali Karicheri <m-karicheri2@ti.com?
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation version 2.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/debugfs.h>
#include "hsr_prp_main.h"
#include "hsr_prp_framereg.h"

/* hsr_prp_lre_info_show - Formats and prints debug info in the device
 */
static int
hsr_prp_lre_info_show(struct seq_file *sfp, void *data)
{
	struct hsr_prp_priv *priv = (struct hsr_prp_priv *)sfp->private;
	bool prp = priv->prot_ver > HSR_V1;

	seq_puts(sfp, "LRE debug information\n");
	seq_printf(sfp, "Protocol : %s\n", prp ? "PRP" : "HSR");
	seq_printf(sfp, "net_id: %d\n", priv->net_id);
	seq_printf(sfp, "Rx Offloaded: %s\n",
		   priv->rx_offloaded ? "Yes" : "No");
	if (!prp)
		seq_printf(sfp, "L2 fw Offloaded: %s\n",
			   priv->l2_fwd_offloaded ? "Yes" : "No");
	seq_printf(sfp, "vlan tag used in sv frame : %s\n",
		   priv->use_vlan_for_sv ? "Yes" : "No");
	if (priv->use_vlan_for_sv) {
		seq_printf(sfp, "SV Frame VID : %d\n",
			   priv->sv_frame_vid);
		seq_printf(sfp, "SV Frame PCP : %d\n",
			   priv->sv_frame_pcp);
		seq_printf(sfp, "SV Frame DEI : %d\n",
			   priv->sv_frame_dei);
	}
	seq_printf(sfp, "cnt_tx_sup = %d\n", priv->dbg_stats.cnt_tx_sup);
	seq_printf(sfp, "disable SV Frame = %d\n", priv->disable_sv_frame);
	seq_puts(sfp, "\n");
	return 0;
}

/* hsr_prp_lre_info_open - open lre info file
 *
 * Description:
 * This routine opens a debugfs file lre_info of specific hsr or
 * prp device
 */
static int
hsr_prp_lre_info_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, hsr_prp_lre_info_show, inode->i_private);
}

static const struct file_operations hsr_prp_lre_info_fops = {
	.owner	= THIS_MODULE,
	.open	= hsr_prp_lre_info_open,
	.read	= seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/* hsr_prp_debugfs_init - create hsr-prp node_table file for dumping
 * the node table
 *
 * Description:
 * When debugfs is configured this routine sets up the node_table file per
 * hsr/prp device for dumping the node_table entries
 */
int hsr_prp_debugfs_init(struct hsr_prp_priv *priv,
			 struct net_device *hsr_prp_dev)
{
	int rc = -1;
	struct dentry *de = NULL;

	de = debugfs_create_dir(hsr_prp_dev->name, NULL);
	if (!de) {
		netdev_err(hsr_prp_dev, "Cannot create hsr-prp debugfs root\n");
		return rc;
	}

	priv->root_dir = de;

	de = debugfs_create_file("lre_info", S_IFREG | 0444,
				 priv->root_dir, priv,
				 &hsr_prp_lre_info_fops);
	if (!de) {
		netdev_err(hsr_prp_dev,
			   "Cannot create hsr-prp lre_info file\n");
		return rc;
	}
	priv->lre_info_file = de;

	return 0;
} /* end of hst_prp_debugfs_init */

/* hsr_prp_debugfs_term - Tear down debugfs intrastructure
 *
 * Description:
 * When Debufs is configured this routine removes debugfs file system
 * elements that are specific to hsr-prp
 */
void
hsr_prp_debugfs_term(struct hsr_prp_priv *priv)
{
	debugfs_remove(priv->lre_info_file);
	priv->lre_info_file = NULL;
	debugfs_remove(priv->root_dir);
	priv->root_dir = NULL;
}
