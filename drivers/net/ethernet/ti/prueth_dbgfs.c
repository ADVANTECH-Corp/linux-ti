/*
 * PRU Ethernet Driver
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

#include <linux/debugfs.h>
#include <linux/etherdevice.h>
#include "prueth_node_tbl.h"
#include "hsr_prp_firmware.h"

#if IS_ENABLED(CONFIG_DEBUG_FS)
/* prueth_queue_show - Formats and print prueth queue related info
 */
static int
prueth_queue_info_show(struct seq_file *sfp, void *data)
{
	struct prueth_emac *emac = (struct prueth_emac *)sfp->private;
	struct prueth *prueth = emac->prueth;
	struct prueth_mmap_port_cfg_basis *pb =
		&prueth->mmap_port_cfg_basis[emac->port_id];
	int i;

	seq_puts(sfp, "TxQ-0 TxQ-1 TxQ-2 TxQ-3\n");

	for (i = PRUETH_QUEUE1; i <= PRUETH_QUEUE4; i++)
		seq_printf(sfp, "%5d ", pb->queue_size[i]);

	seq_puts(sfp, "\n");
	pb = &prueth->mmap_port_cfg_basis[PRUETH_PORT_HOST];
	if (emac->port_id == PRUETH_PORT_MII0) {
		seq_puts(sfp, "RxQ-0 RxQ-1\n");
		for (i = PRUETH_QUEUE1; i <= PRUETH_QUEUE2; i++)
			seq_printf(sfp, "%5d ", pb->queue_size[i]);
	} else {
		seq_puts(sfp, "RxQ-2 RxQ-3\n");
		for (i = PRUETH_QUEUE3; i <= PRUETH_QUEUE4; i++)
			seq_printf(sfp, "%5d ", pb->queue_size[i]);
	}
	seq_puts(sfp, "\n");
	seq_puts(sfp, "EMAC Queue Stats\n");
	seq_puts(sfp,
		 "=====================================================\n");
	if (!PRUETH_HAS_RED(emac->prueth))
		seq_puts(sfp, "   TxQ-0    TxQ-1    TxQ-2    TxQ-3    ");
	else
		seq_puts(sfp, "   TxQ-2    TxQ-3    ");
	if (emac->port_id == PRUETH_PORT_MII0)
		seq_puts(sfp, "RxQ-0    RxQ-1\n");
	else
		seq_puts(sfp, "RxQ-2    RxQ-3\n");
	seq_printf(sfp,
		   "=====================================================\n");

	if (!PRUETH_HAS_RED(emac->prueth))
		seq_printf(sfp, "%8d %8d %8d %8d %8d %8d\n",
			   emac->tx_packet_counts[PRUETH_QUEUE1],
			   emac->tx_packet_counts[PRUETH_QUEUE2],
			   emac->tx_packet_counts[PRUETH_QUEUE3],
			   emac->tx_packet_counts[PRUETH_QUEUE4],
			   emac->rx_packet_counts[PRUETH_QUEUE1],
			   emac->rx_packet_counts[PRUETH_QUEUE2]);
	else
		seq_printf(sfp, "%8d %8d %8d %8d\n",
			   emac->tx_packet_counts[PRUETH_QUEUE3],
			   emac->tx_packet_counts[PRUETH_QUEUE4],
			   emac->rx_packet_counts[PRUETH_QUEUE1],
			   emac->rx_packet_counts[PRUETH_QUEUE2]);

	return 0;
}

/* prueth_queue_stats_fops - Open the prueth queue stats file
 *
 * Description:
 * This routine opens a debugfs file for prueth queue stats
 */
static int
prueth_queue_stats_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, prueth_queue_info_show,
			   inode->i_private);
}

static const struct file_operations prueth_emac_info_fops = {
	.owner	= THIS_MODULE,
	.open	= prueth_queue_stats_open,
	.read	= seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static void prueth_hsr_prp_node_show(struct seq_file *sfp,
				     struct prueth *prueth, int index)
{
	struct node_tbl *nt = prueth->nt;
	struct bin_tbl_t *bin = &nt->bin_array->bin_tbl[index];
	struct node_tbl_t *node;
	u8 val, is_hsr;

	if (WARN_ON(bin->node_tbl_offset >= nt->nt_array_max_entries))
		return;

	node = &nt->nt_array->node_tbl[bin->node_tbl_offset];

	seq_printf(sfp, "\nNode[%u]:\n", index);
	seq_printf(sfp, "MAC ADDR: %02x:%02x:%02x:%02x:%02x:%02x\n",
		   bin->src_mac_id[3], bin->src_mac_id[2],
		   bin->src_mac_id[1], bin->src_mac_id[0],
		   bin->src_mac_id[5], bin->src_mac_id[4]);
	seq_printf(sfp, "state: %s\n",
		   ((node->entry_state & 0x1) ? "valid" : "invalid"));

	if (PRUETH_HAS_PRP(prueth)) {
		val = (node->status & NT_REM_NODE_DUP_MASK);
		switch (val) {
		case NT_REM_NODE_DUP_DISCARD:
			seq_printf(sfp, "DupDiscard (0x%02x)\n", val);
			break;
		case NT_REM_NODE_DUP_ACCEPT:
			seq_printf(sfp, "DupAccept (0x%02x)\n", val);
			break;
		default:
			seq_printf(sfp, "Unknown Dup type (0x%02x)\n", val);
			break;
		}
	}

	is_hsr = node->status & NT_REM_NODE_HSR_BIT;
	val = (node->status & NT_REM_NODE_TYPE_MASK) >> NT_REM_NODE_TYPE_SHIFT;
	switch (val) {
	case NT_REM_NODE_TYPE_SANA:
		seq_puts(sfp, "SAN A\n");
		break;
	case NT_REM_NODE_TYPE_SANB:
		seq_puts(sfp, "SAN B\n");
		break;
	case NT_REM_NODE_TYPE_SANAB:
		seq_puts(sfp, "SAN AB\n");
		break;
	case NT_REM_NODE_TYPE_DAN:
		if (is_hsr)
			seq_puts(sfp, "DANH\n");
		else
			seq_puts(sfp, "DANP\n");
		break;
	case NT_REM_NODE_TYPE_REDBOX:
		if (is_hsr)
			seq_puts(sfp, "REDBOXH\n");
		else
			seq_puts(sfp, "REDBOXP\n");
		break;
	case NT_REM_NODE_TYPE_VDAN:
		if (is_hsr)
			seq_puts(sfp, "VDANH\n");
		else
			seq_puts(sfp, "VDANP\n");
		break;
	default:
		seq_printf(sfp, "unknown node type %u\n", val);
		break;
	}

	seq_printf(sfp, "RxA=%u SupRxA=%u\n", node->cnt_ra, node->cnt_rx_sup_a);
	seq_printf(sfp, "RxB=%u SupRxB=%u\n", node->cnt_rb, node->cnt_rx_sup_b);

	seq_printf(sfp, "Time Last Seen: Sup=%u RxA=%u RxB=%u\n",
		   node->time_last_seen_s, node->time_last_seen_a,
		   node->time_last_seen_b);

	if (prueth->eth_type == PRUSS_ETHTYPE_PRP)
		seq_printf(sfp, "PRP LineID Err: A=%u B=%u\n",
			   node->err_wla, node->err_wlb);
}

/* prueth_hsr_prp_node_table_show - Formats and prints node_table entries
 */
static int
prueth_hsr_prp_node_table_show(struct seq_file *sfp, void *data)
{
	struct prueth *prueth = (struct prueth *)sfp->private;
	struct node_tbl *nt = prueth->nt;
	int j;
	u32 nodes;

	nodes = nt->nt_lre_cnt->lre_cnt;
	seq_printf(sfp, "\nRemote nodes in network: %u\n",
		   nt->nt_lre_cnt->lre_cnt);

	for (j = 0; j < nt->bin_array_max_entries; j++) {
		if (nt->bin_array->bin_tbl[j].node_tbl_offset <
		    nt->nt_array_max_entries)
			prueth_hsr_prp_node_show(sfp, prueth, j);
	}

	seq_puts(sfp, "\n");
	return 0;
}

/* prueth_hsr_prp_node_table_open - Open the node_table file
 *
 * Description:
 * This routine opens a debugfs file node_table of specific hsr
 * or prp device
 */
static int
prueth_hsr_prp_node_table_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, prueth_hsr_prp_node_table_show,
			   inode->i_private);
}

static const struct file_operations prueth_hsr_prp_node_table_fops = {
	.owner	= THIS_MODULE,
	.open	= prueth_hsr_prp_node_table_open,
	.read	= seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/* prueth_vlan_filter_show - Formats and prints vlan_filter entries
 */
static int
prueth_vlan_filter_show(struct seq_file *sfp, void *data)
{
	struct prueth_emac *emac = (struct prueth_emac *)sfp->private;
	struct prueth *prueth = emac->prueth;
	void __iomem *ram;
	u8 val, mask;
	int i, j;
	u32 vlan_ctrl_byte = prueth->fw_offsets->vlan_ctrl_byte;
	u32 vlan_filter_tbl = prueth->fw_offsets->vlan_filter_tbl;

	if (PRUETH_IS_EMAC(prueth)) {
		ram = (emac->port_id == PRUETH_PORT_MII0) ?
				prueth->mem[PRUETH_MEM_DRAM0].va :
				prueth->mem[PRUETH_MEM_DRAM1].va;
	} else {
		ram = prueth->mem[PRUETH_MEM_SHARED_RAM].va;
	}

	val = readb(ram + vlan_ctrl_byte);
	seq_printf(sfp, "VLAN Filter : %s",
		   val & BIT(VLAN_FLTR_CTRL_SHIFT) ?
			 "enabled\n" : "disabled\n");
	if (val & BIT(VLAN_FLTR_CTRL_SHIFT)) {
		seq_printf(sfp, "VLAN Filter untagged : %s",
			   val & BIT(VLAN_FLTR_UNTAG_HOST_RCV_CTRL_SHIFT) ?
			   "not allowed to Host\n" : "allowed to Host\n");
		seq_printf(sfp, "VLAN Filter priority tagged: %s",
			   val & BIT(VLAN_FLTR_PRIOTAG_HOST_RCV_CTRL_SHIFT) ?
			   "not allowed to Host\n" : "allowed to Host\n");
	}
	if (val) {
		for (i = 0; i < VLAN_FLTR_TBL_SIZE; i++) {
			val = readb(ram + vlan_filter_tbl + i);
			if (!(i % 8))
				seq_printf(sfp, "\n%5d: ", i * 8);

			for (j = 0; j < 8; j++) {
				mask = BIT(j);
				if (mask & val)
					seq_printf(sfp, "%1x", 1);
				else
					seq_printf(sfp, "%1x", 0);
			}
		}
	}
	seq_puts(sfp, "\n");

	return 0;
}

/* prueth_vlan_filter_open - Open the vlan_filter file
 *
 * Description:
 * This routine opens a debugfs file vlan_filter
 */
static int
prueth_vlan_filter_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, prueth_vlan_filter_show,
			   inode->i_private);
}

static const struct file_operations prueth_vlan_filter_fops = {
	.owner	= THIS_MODULE,
	.open	= prueth_vlan_filter_open,
	.read	= seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/* prueth_mc_filter_show - Formats and prints mc_filter entries
 */
static int
prueth_mc_filter_show(struct seq_file *sfp, void *data)
{
	struct prueth_emac *emac = (struct prueth_emac *)sfp->private;
	struct prueth *prueth = emac->prueth;
	void __iomem *ram = (emac->port_id == PRUETH_PORT_MII0) ?
				prueth->mem[PRUETH_MEM_DRAM0].va :
				prueth->mem[PRUETH_MEM_DRAM1].va;
	u8 val;
	int i;
	u32 mc_ctrl_byte = prueth->fw_offsets->mc_ctrl_byte;
	u32 mc_filter_mask = prueth->fw_offsets->mc_filter_mask;
	u32 mc_filter_tbl = prueth->fw_offsets->mc_filter_tbl;

	val = readb(ram + mc_ctrl_byte);

	seq_printf(sfp, "MC Filter : %s", val ? "enabled\n" : "disabled\n");
	seq_puts(sfp, "MC Mask : ");
	for (i = 0; i < 6; i++) {
		val = readb(ram + mc_filter_mask + i);
		if (i == 5)
			seq_printf(sfp, "%x", val);
		else
			seq_printf(sfp, "%x:", val);
	}
	seq_puts(sfp, "\n");

	val = readb(ram + mc_ctrl_byte);
	seq_puts(sfp, "MC Filter table below 1 - Allowed, 0 - Dropped\n");

	if (val) {
		for (i = 0; i < MULTICAST_TABLE_SIZE; i++) {
			val = readb(ram + mc_filter_tbl + i);
			if (!(i % 16))
				seq_printf(sfp, "\n%3x: ", i);
			seq_printf(sfp, "%d ", val);
		}
	}
	seq_puts(sfp, "\n");

	return 0;
}

/* prueth_mc_filter_open - Open the mc_filter file
 *
 * Description:
 * This routine opens a debugfs file mc_filter
 */
static int
prueth_mc_filter_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, prueth_mc_filter_show,
			   inode->i_private);
}

static const struct file_operations prueth_mc_filter_fops = {
	.owner	= THIS_MODULE,
	.open	= prueth_mc_filter_open,
	.read	= seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/* prueth_lre_config_show - print the configuration parameters at
 * the lre device
 */
static int
prueth_lre_config_show(struct seq_file *sfp, void *data)
{
	struct prueth *prueth = (struct prueth *)sfp->private;
	void __iomem *dram0 = prueth->mem[PRUETH_MEM_DRAM0].va;
	void __iomem *dram1 = prueth->mem[PRUETH_MEM_DRAM1].va;
	void __iomem *sram = prueth->mem[PRUETH_MEM_SHARED_RAM].va;
	int hsr = 0;
	u32 val;

	if (PRUETH_HAS_HSR(prueth))
		hsr = 1;

	seq_printf(sfp, "Protocol is %s\n", hsr == 1 ? "HSR" : "PRP");
	if (hsr) {
		val = readl(dram0 + LRE_HSR_MODE);
		seq_printf(sfp, "mode %u\n", val);
	}

	val = readl(dram1 + DUPLI_FORGET_TIME);
	seq_printf(sfp, "Duplicate List Maximum reside time  %u\n", val * 10);
	val = readl(sram + LRE_DUPLICATE_DISCARD);
	seq_printf(sfp, "Duplicate Discard%u\n", val);
	if (!hsr) {
		val = readl(sram + LRE_TRANSPARENT_RECEPTION);
		seq_printf(sfp, "PRP Tranparent Reception%u\n", val);
	}
	seq_printf(sfp, "Last clear node table command%u\n",
		   prueth->node_table_clear_last_cmd);
	seq_puts(sfp, "\n");

	return 0;
}

/* prueth_lre_config_open - Open the lre config debugfs file
 *
 * Description:
 * This routine opens a debugfs file lre_config file to view
 * the configuration parameters at the offloaded lre device.
 */
static int
prueth_lre_config_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, prueth_lre_config_show,
			   inode->i_private);
}

static const struct file_operations prueth_lre_config_fops = {
	.owner	= THIS_MODULE,
	.open	= prueth_lre_config_open,
	.read	= seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/* prueth_error_stats_show - print the error stats
 */
static int
prueth_error_stats_show(struct seq_file *sfp, void *data)
{
	struct prueth *prueth = (struct prueth *)sfp->private;

	seq_printf(sfp, "tx_collisions: %u\n",
		   prueth->emac[PRUETH_PORT_MII0]->tx_collisions);
	seq_printf(sfp, "tx_collision_drops: %u\n",
		   prueth->emac[PRUETH_PORT_MII0]->tx_collision_drops);
	seq_printf(sfp, "rx_overflows: %u\n",
		   prueth->emac[PRUETH_PORT_MII0]->rx_overflows);

	return 0;
}

/* prueth_prp_erro_stats_open:- Open the error stats file
 *
 * Description:
 * This routine opens a debugfs file error_stats
 */
static int
prueth_error_stats_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, prueth_error_stats_show,
			   inode->i_private);
}

static const struct file_operations prueth_error_stats_fops = {
	.owner	= THIS_MODULE,
	.open	= prueth_error_stats_open,
	.read	= seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/* prueth_hsr_prp_debugfs_term - Tear down debugfs intrastructure
 *
 * Description:
 * When Debufs is configured this routine removes debugfs file system
 * elements that are specific to hsr-prp
 */
void
prueth_hsr_prp_debugfs_term(struct prueth *prueth)
{
	if (prueth->emac_configured)
		return;

	debugfs_remove_recursive(prueth->root_dir);
	prueth->node_tbl_file = NULL;
	prueth->mc_filter_file = NULL;
	prueth->vlan_filter_file = NULL;
	prueth->lre_cfg_file = NULL;
	prueth->error_stats_file = NULL;
	prueth->root_dir = NULL;
	prueth->nt_index = NULL;
	prueth->nt_bins = NULL;
}

/* prueth_hsr_prp_debugfs_init - create hsr-prp node_table file for dumping
 * the node table
 *
 * Description:
 * When debugfs is configured this routine sets up the node_table file per
 * hsr/prp device for dumping the node_table entries
 */
int prueth_hsr_prp_debugfs_init(struct prueth *prueth)
{
	struct device *dev = prueth->dev;
	int rc = -ENODEV;
	struct dentry *de = NULL;
	int id = prueth->pruss_id;
	char dir[32];

	memset(dir, 0, sizeof(dir));
	if (PRUETH_HAS_HSR(prueth))
		sprintf(dir, "prueth-hsr-%d", id);
	else if (PRUETH_HAS_PRP(prueth)) {
		sprintf(dir, "prueth-prp-%d", id);
	} else {
		dev_err(dev, "unknown eth_type: %u\n", prueth->eth_type);
		return -EINVAL;
	}

	de = debugfs_create_dir(dir, NULL);
	if (!de) {
		dev_err(dev, "Cannot create %s debugfs root\n", dir);
		return rc;
	}

	prueth->root_dir = de;

	de = debugfs_create_file("node_table", S_IFREG | 0444,
				 prueth->root_dir, prueth,
				 &prueth_hsr_prp_node_table_fops);
	if (!de) {
		dev_err(dev, "Cannot create hsr-prp node_table file\n");
		goto error;
	}
	prueth->node_tbl_file = de;

	de = debugfs_create_file("mc_filter", S_IFREG | 0444,
				 prueth->root_dir,
				 prueth->emac[PRUETH_PORT_MII0],
				 &prueth_mc_filter_fops);
	if (!de) {
		dev_err(dev, "Cannot create hsr-prp mc_filter file\n");
		goto error;
	}
	prueth->mc_filter_file = de;

	de = debugfs_create_file("vlan_filter", S_IFREG | 0444,
				 prueth->root_dir,
				 prueth->emac[PRUETH_PORT_MII0],
				 &prueth_vlan_filter_fops);
	if (!de) {
		dev_err(dev, "Cannot create hsr-prp vlan_filter file\n");
		goto error;
	}
	prueth->vlan_filter_file = de;

	de = debugfs_create_file("lre_config", 0444,
				 prueth->root_dir, prueth,
				 &prueth_lre_config_fops);
	if (!de) {
		dev_err(dev, "Cannot create lre_config file\n");
		goto error;
	}
	prueth->lre_cfg_file = de;

	de = debugfs_create_file("error_stats", 0444,
				 prueth->root_dir, prueth,
				 &prueth_error_stats_fops);
	if (!de) {
		dev_err(dev, "Cannot create error_stats file\n");
		goto error;
	}
	prueth->error_stats_file = de;

	de = debugfs_create_file("nt_index", S_IFREG | 0444,
				 prueth->root_dir, prueth->nt,
				 &prueth_nt_index_fops);
	if (!de) {
		dev_err(dev, "Cannot create nt_index file\n");
		goto error;
	}
	prueth->nt_index = de;

	de = debugfs_create_file("nt_bins", S_IFREG | 0444,
				 prueth->root_dir, prueth->nt,
				 &prueth_nt_bins_fops);
	if (!de) {
		dev_err(dev, "Cannot create nt_indexes file\n");
		goto error;
	}
	prueth->nt_bins = de;

	return 0;
error:
	prueth_hsr_prp_debugfs_term(prueth);
	return rc;

}

/* prueth_dualemac_debugfs_term - Tear down debugfs intrastructure for dual emac
 *
 * Description:
 * When Debufs is configured this routine removes debugfs file system
 * elements that are specific to dual emac
 */
void
prueth_dualemac_debugfs_term(struct prueth_emac *emac)
{
	debugfs_remove(emac->vlan_filter_file);
	debugfs_remove(emac->mc_filter_file);
	emac->vlan_filter_file = NULL;
	emac->mc_filter_file = NULL;
}

/* prueth_dualemac_debugfs_init - create  debugfs file for dual emac
 *
 * Description:
 * When debugfs is configured this routine creates dual emac debugfs files
 */

int prueth_dualemac_debugfs_init(struct prueth_emac *emac)
{
	int rc = -1;
	struct dentry *de;

	if (emac->root_dir && !emac->mc_filter_file &&
	    !emac->vlan_filter_file) {
		de = debugfs_create_file("mc_filter", S_IFREG | 0444,
					 emac->root_dir, emac,
					 &prueth_mc_filter_fops);
		if (!de) {
			netdev_err(emac->ndev,
				   "Cannot create mc_filter file\n");
			return rc;
		}
		emac->mc_filter_file = de;

		de = debugfs_create_file("vlan_filter", S_IFREG | 0444,
					 emac->root_dir, emac,
					 &prueth_vlan_filter_fops);
		if (!de) {
			netdev_err(emac->ndev,
				   "Cannot create vlan_filter file\n");
			goto error;
		}

		emac->vlan_filter_file = de;
	}
	return 0;
error:
	prueth_dualemac_debugfs_term(emac);
	return rc;
}

/* prueth_debugfs_term - Tear down debugfs intrastructure for emac stats
 *
 * Description:
 * When Debufs is configured this routine removes debugfs file system
 * elements that are specific to prueth queue stats
 */
void
prueth_debugfs_term(struct prueth_emac *emac)
{
	debugfs_remove_recursive(emac->root_dir);
	emac->stats_file = NULL;
	emac->root_dir = NULL;
	emac->vlan_filter_file = NULL;
	emac->mc_filter_file = NULL;
}

/* prueth_debugfs_init - create  debugfs file for displaying queue stats
 *
 * Description:
 * When debugfs is configured this routine dump the rx_packet_counts and
 * tx_packet_counts in the emac structures
 */

int prueth_debugfs_init(struct prueth_emac *emac)
{
	int rc = -1;
	struct dentry *de;
	char name[32];

	memset(name, 0, sizeof(name));
	sprintf(name, "prueth-");
	strncat(name, emac->ndev->name, sizeof(name) - 1);
	de = debugfs_create_dir(name, NULL);

	if (!de) {
		netdev_err(emac->ndev,
			   "Cannot create debugfs dir name %s\n",
			   name);
		return rc;
	}

	emac->root_dir = de;
	de = debugfs_create_file("queue-info", S_IFREG | 0444,
				 emac->root_dir, emac,
				 &prueth_emac_info_fops);
	if (!de) {
		netdev_err(emac->ndev, "Cannot create emac stats file\n");
		goto error;
	}

	emac->stats_file = de;

	if (PRUETH_IS_EMAC(emac->prueth)) {
		rc = prueth_dualemac_debugfs_init(emac);
		if (rc)
			goto error;
	}

	return 0;
error:
	prueth_debugfs_term(emac);
	return rc;
}

#endif
