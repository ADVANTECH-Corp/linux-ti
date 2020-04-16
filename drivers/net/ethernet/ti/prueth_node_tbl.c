/*
 * Copyright (C) 2017 Texas Instruments Incorporated - http://www.ti.com
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
#include <linux/string.h>
#include <linux/spinlock_types.h>
#include "prueth_node_tbl.h"
#include "hsr_prp_firmware.h"

#define IND_BINOFS(x) nt->index_array->index_tbl[x].bin_offset
#define IND_BIN_NO(x) nt->index_array->index_tbl[x].bin_no_entries
#define BIN_NODEOFS(x) nt->bin_array->bin_tbl[x].node_tbl_offset

static void pru2host_mac(u8 *mac)
{
	swap(mac[0], mac[3]);
	swap(mac[1], mac[2]);
	swap(mac[4], mac[5]);
}

static u16 get_hash(u8 *mac, u16 hash_mask)
{
	int j;
	u16 hash;

	for (j = 0, hash = 0; j < ETHER_ADDR_LEN; j++)
		hash ^= mac[j];
	hash = hash & hash_mask;

	return hash;
}

void pru_spin_lock(struct node_tbl *nt)
{
	while (1) {
		nt->nt_info->arm_lock = 1;
		if (!nt->nt_info->fw_lock)
			break;
		nt->nt_info->arm_lock = 0;
	}
}

static inline void pru_spin_unlock(struct node_tbl *nt)
{
	nt->nt_info->arm_lock = 0;
}

int node_table_insert(struct prueth *prueth, u8 *mac, int port, int sv_frame,
		      int proto, spinlock_t *lock)
{
	struct nt_queue_t *q = prueth->mac_queue;
	unsigned long flags;
	int ret = RED_OK;

	/* Will encounter a null mac_queue if we are in the middle of
	 * ndo_close. So check and return. Otherwise a kernel crash is
	 * seen when doing ifdown continuously.
	 */
	if (!q)
		return ret;

	spin_lock_irqsave(lock, flags);
	if (q->full) {
		ret = RED_ERR;
	} else {
		memcpy(q->nt_queue[q->wr_ind].mac, mac, ETHER_ADDR_LEN);
		q->nt_queue[q->wr_ind].sv_frame = sv_frame;
		q->nt_queue[q->wr_ind].port_id = port;
		q->nt_queue[q->wr_ind].proto = proto;

		q->wr_ind++;
		q->wr_ind &= (MAC_QUEUE_MAX - 1);
		if (q->wr_ind == q->rd_ind)
			q->full = true;
	}
	spin_unlock_irqrestore(lock, flags);

	return ret;
}

static inline bool node_expired(struct node_tbl *nt, u16 node, u16 forget_time)
{
	struct node_tbl_t nt_node = nt->nt_array->node_tbl[node];

	return ((nt_node.time_last_seen_s > forget_time ||
		 nt_node.status & NT_REM_NODE_TYPE_SANAB) &&
		 nt_node.time_last_seen_a > forget_time &&
		 nt_node.time_last_seen_b > forget_time);
}

void node_table_init(struct prueth *prueth)
{
	int	j;
	struct node_tbl *nt = prueth->nt;
	struct nt_queue_t *q = prueth->mac_queue;

	const struct prueth_fw_offsets *fw_offsets = prueth->fw_offsets;

	nt->nt_array = prueth->mem[fw_offsets->nt_array_loc].va +
		       fw_offsets->nt_array_offset;
	memset(nt->nt_array, 0, sizeof(struct node_tbl_t) *
				fw_offsets->nt_array_max_entries);

	nt->bin_array = prueth->mem[fw_offsets->bin_array_loc].va +
			fw_offsets->bin_array_offset;
	memset(nt->bin_array, 0, sizeof(struct bin_tbl_t) *
				 fw_offsets->bin_array_max_entries);

	nt->index_array = prueth->mem[fw_offsets->index_array_loc].va +
			  fw_offsets->index_array_offset;
	memset(nt->index_array, 0, sizeof(struct node_index_tbl_t) *
				   fw_offsets->index_array_max_entries);

	nt->nt_info = prueth->mem[fw_offsets->nt_array_loc].va +
		      fw_offsets->nt_array_offset +
		      (sizeof(struct node_tbl_t) *
		       fw_offsets->nt_array_max_entries);
	memset(nt->nt_info, 0, sizeof(struct node_tbl_info_t));

	nt->nt_lre_cnt = prueth->mem[PRUETH_MEM_SHARED_RAM].va + LRE_CNT_NODES;
	memset(nt->nt_lre_cnt, 0, sizeof(struct node_tbl_lre_cnt_t));

	nt->nt_array_max_entries = fw_offsets->nt_array_max_entries;
	nt->bin_array_max_entries = fw_offsets->bin_array_max_entries;
	nt->index_array_max_entries = fw_offsets->index_array_max_entries;
	nt->hash_mask = fw_offsets->hash_mask;

	for (j = 0; j < fw_offsets->index_array_max_entries; j++)
		IND_BINOFS(j) = fw_offsets->bin_array_max_entries;
	for (j = 0; j < fw_offsets->bin_array_max_entries; j++)
		BIN_NODEOFS(j) = fw_offsets->nt_array_max_entries;
	for (j = 0; j < fw_offsets->nt_array_max_entries; j++)
		nt->nt_array->node_tbl[j].entry_state = NODE_FREE;

	q->rd_ind = 0;
	q->wr_ind = 0;
	q->full = false;
}

static u16 find_free_bin(struct node_tbl *nt)
{
	u16 j;

	for (j = 0; j < nt->bin_array_max_entries; j++)
		if (BIN_NODEOFS(j) == nt->nt_array_max_entries)
			break;

	return j;
}

/* find first free node table slot and write it to the next_free_slot */
static u16 next_free_slot_update(struct node_tbl *nt)
{
	int j;

	nt->nt_info->next_free_slot = nt->nt_array_max_entries;
	for (j = 0; j < nt->nt_array_max_entries; j++) {
		if (nt->nt_array->node_tbl[j].entry_state == NODE_FREE) {
			nt->nt_info->next_free_slot = j;
			break;
		}
	}

	return nt->nt_info->next_free_slot;
}

static void inc_time(u16 *t)
{
	*t += 1;
	if (*t > MAX_FORGET_TIME)
		*t = MAX_FORGET_TIME;
}

void node_table_update_time(struct node_tbl *nt)
{
	int j;
	u16 ofs;
	struct nt_array_t *nt_arr = nt->nt_array;
	struct node_tbl_t *node;

	for (j = 0; j < nt->bin_array_max_entries; j++) {
		ofs = nt->bin_array->bin_tbl[j].node_tbl_offset;
		if (ofs < nt->nt_array_max_entries) {
			node = &nt_arr->node_tbl[ofs];
			inc_time(&node->time_last_seen_a);
			inc_time(&node->time_last_seen_b);
			/* increment time_last_seen_s if nod is not SAN */
			if ((node->status &
			     NT_REM_NODE_TYPE_SANAB) == 0)
				inc_time(&node->time_last_seen_s);
		}
	}
}

static void write2node_slot(struct node_tbl *nt, u16 node, int port,
			    int sv_frame, int proto)
{
	memset(&nt->nt_array->node_tbl[node], 0, sizeof(struct node_tbl_t));
	nt->nt_array->node_tbl[node].entry_state = NODE_TAKEN;

	if (port == 0x01) {
		nt->nt_array->node_tbl[node].status = NT_REM_NODE_TYPE_SANA;
		nt->nt_array->node_tbl[node].cnt_ra = 1;
		if (sv_frame)
			nt->nt_array->node_tbl[node].cnt_rx_sup_a = 1;
	} else {
		nt->nt_array->node_tbl[node].status = NT_REM_NODE_TYPE_SANB;
		nt->nt_array->node_tbl[node].cnt_rb = 1;
		if (sv_frame)
			nt->nt_array->node_tbl[node].cnt_rx_sup_b = 1;
	}

	if (sv_frame) {
		nt->nt_array->node_tbl[node].status = (proto == RED_PROTO_PRP) ?
			NT_REM_NODE_TYPE_DAN :
			NT_REM_NODE_TYPE_DAN | NT_REM_NODE_HSR_BIT;
	}
}

/* We assume that the _start_ cannot point to middle of a bin */
static void update_indexes(u16 start, u16 end, struct node_tbl *nt)
{
	u16 hash, hash_prev;

	hash_prev = 0xffff; /* invalid hash */
	for (; start <= end; start++) {
		hash = get_hash(nt->bin_array->bin_tbl[start].src_mac_id,
				nt->hash_mask);
		if (hash != hash_prev)
			IND_BINOFS(hash) = start;
		hash_prev = hash;
	}
}

/* start > end */
static void move_up(u16 start, u16 end, struct node_tbl *nt,
		    bool update)
{
	u16 j = end;

	pru_spin_lock(nt);

	for (; j < start; j++)
		memcpy(&nt->bin_array->bin_tbl[j],
		       &nt->bin_array->bin_tbl[j + 1],
		       sizeof(struct bin_tbl_t));

	BIN_NODEOFS(start) = nt->nt_array_max_entries;

	if (update)
		update_indexes(end, start + 1, nt);

	pru_spin_unlock(nt);
}

/* start < end */
static void move_down(u16 start, u16 end, struct node_tbl *nt,
		      bool update)
{
	u16 j = end;

	pru_spin_lock(nt);

	for (; j > start; j--)
		memcpy(&nt->bin_array->bin_tbl[j],
		       &nt->bin_array->bin_tbl[j - 1],
		       sizeof(struct bin_tbl_t));

	nt->bin_array->bin_tbl[start].node_tbl_offset =
					nt->nt_array_max_entries;

	if (update)
		update_indexes(start + 1, end, nt);

	pru_spin_unlock(nt);
}

static int node_table_insert_from_queue(struct node_tbl *nt,
					struct nt_queue_entry *entry)
{
	u8 macid[ETHER_ADDR_LEN];
	u16 hash;
	u16 index;
	u16 free_node;
	bool not_found;
	u16 empty_slot;

	if (!nt)
		return RED_ERR;

	memcpy(macid, entry->mac, ETHER_ADDR_LEN);
	pru2host_mac(macid);

	hash = get_hash(macid, nt->hash_mask);

	not_found = 1;
	if (IND_BIN_NO(hash) == 0) {
		/* there is no bin for this hash, create one */
		index = find_free_bin(nt);
		if (index == nt->bin_array_max_entries)
			return RED_ERR;

		IND_BINOFS(hash) = index;
	} else {
		for (index = IND_BINOFS(hash);
		     index < IND_BINOFS(hash) + IND_BIN_NO(hash); index++) {
			if ((memcmp(nt->bin_array->bin_tbl[index].src_mac_id,
				    macid, ETHER_ADDR_LEN) == 0)) {
				not_found = 0;
				break;
			}
		}
	}

	if (not_found) {
		free_node = next_free_slot_update(nt);

		/* at this point we might create a new bin and set
		 * bin_offset at the index table. It was only possible
		 * if we found a free slot in the bin table.
		 * So, it also must be a free slot in the node table
		 * and we will not exit here in this case.
		 * So, be don't have to take care about fixing IND_BINOFS()
		 * on return RED_ERR
		 */
		if (free_node >= nt->nt_array_max_entries)
			return RED_ERR;

		/* if we are here, we have at least one empty slot in the bin
		 * table and one slot at the node table
		 */

		IND_BIN_NO(hash)++;

		/* look for an empty slot downwards */
		for (empty_slot = index;
		     (BIN_NODEOFS(empty_slot) != nt->nt_array_max_entries) &&
		     (empty_slot < nt->nt_array_max_entries);
		     empty_slot++)
			;

		/* if emptySlot != maxNodes => empty slot is found,
		 * else no space available downwards, look upwards
		 */
		if (empty_slot != nt->nt_array_max_entries) {
			move_down(index, empty_slot, nt, true);
		} else {
			for (empty_slot = index - 1;
			     (BIN_NODEOFS(empty_slot) !=
			     nt->nt_array_max_entries) &&
			     (empty_slot > 0);
			     empty_slot--)
				;
			/* we're sure to get a space here as nodetable
			 * has a empty slot, so no need to check for
			 * value of emptySlot
			 */
			move_up(index, empty_slot, nt, true);
		}

		/* space created, now populate the values*/
		BIN_NODEOFS(index) = free_node;
		memcpy(nt->bin_array->bin_tbl[index].src_mac_id, macid,
		       ETHER_ADDR_LEN);
		write2node_slot(nt, free_node, entry->port_id, entry->sv_frame,
				entry->proto);

		nt->nt_lre_cnt->lre_cnt++;
	}

	return RED_OK;
}

void node_table_check_and_remove(struct node_tbl *nt, u16 forget_time)
{
	int j, end_bin;
	u16 node;
	u16 hash;

	/*loop to remove a node reaching NODE_FORGET_TIME*/
	for (j = 0; j < nt->bin_array_max_entries; j++) {
		node = BIN_NODEOFS(j);
		if (node >= nt->nt_array_max_entries)
			continue;

		if (node_expired(nt, node, forget_time)) {
			hash = get_hash(nt->bin_array->bin_tbl[j].src_mac_id,
					nt->hash_mask);

			/* remove entry from bin array */
			end_bin = IND_BINOFS(hash) + IND_BIN_NO(hash) - 1;

			move_up(end_bin, j, nt, false);
			(IND_BIN_NO(hash))--;

			if (!IND_BIN_NO(hash))
				IND_BINOFS(hash) = nt->bin_array_max_entries;

			nt->nt_array->node_tbl[node].entry_state = NODE_FREE;
			BIN_NODEOFS(end_bin) = nt->nt_array_max_entries;

			nt->nt_lre_cnt->lre_cnt--;
		}
	}
}

/****************************************************************************/
static int pop_queue(struct prueth *prueth, spinlock_t *lock)
{
	unsigned long flags;
	struct node_tbl *nt = prueth->nt;
	struct nt_queue_t *q = prueth->mac_queue;
	struct nt_queue_entry one_mac;
	int ret = 0;

	spin_lock_irqsave(lock, flags);
	if (!q->full && (q->wr_ind == q->rd_ind)) { /* queue empty */
		ret = 1;
	} else {
		memcpy(&one_mac, &q->nt_queue[q->rd_ind],
		       sizeof(struct nt_queue_entry));
		spin_unlock_irqrestore(lock, flags);
		node_table_insert_from_queue(nt, &one_mac);
		spin_lock_irqsave(lock, flags);
		q->rd_ind++;
		q->rd_ind &= (MAC_QUEUE_MAX - 1);
		q->full = false;
	}
	spin_unlock_irqrestore(lock, flags);

	return ret;
}

void pop_queue_process(struct prueth *prueth, spinlock_t *lock)
{
	while (pop_queue(prueth, lock) == 0)
		;
}

/* indexes */
static int
prueth_nt_index_show(struct seq_file *sfp, void *data)
{
	struct node_tbl *nt = (struct node_tbl *)sfp->private;
	int j;
	int cnt_i = 0;
	int cnt_b = 0;

	for (j = 0; j < nt->index_array_max_entries; j++)
		if ((IND_BINOFS(j) < nt->bin_array_max_entries) &&
		    (IND_BIN_NO(j) > 0)) {
			seq_printf(sfp, "%3d; ofs %3d; no %3d\n", j,
				   IND_BINOFS(j), IND_BIN_NO(j));
			cnt_i++;
			cnt_b += IND_BIN_NO(j);
		}

	seq_printf(sfp, "\nTotal indexes %d; bins %d;  lre_cnt %d\n",
		   cnt_i, cnt_b, nt->nt_lre_cnt->lre_cnt);

	return 0;
}

static int
prueth_nt_index_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, prueth_nt_index_show,
			   inode->i_private);
}

const struct file_operations prueth_nt_index_fops = {
	.owner	= THIS_MODULE,
	.open	= prueth_nt_index_open,
	.read	= seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/* bins */
static int
prueth_nt_bins_show(struct seq_file *sfp, void *data)
{
	struct node_tbl *nt = (struct node_tbl *)sfp->private;
	int j, o;
	int cnt = 0;

	for (j = 0; j < nt->bin_array_max_entries; j++)
		if (nt->bin_array->bin_tbl[j].node_tbl_offset <
		    nt->nt_array_max_entries) {
			o = nt->bin_array->bin_tbl[j].node_tbl_offset;
			seq_printf(sfp, "%3d; ofs %3d; %02x-%02x-%02x-%02x-%02x-%02x %02x %02x ra %4d; rb %4d; s%5d; a%5d; b%5d\n",
				   j, nt->bin_array->bin_tbl[j].node_tbl_offset,
				   nt->bin_array->bin_tbl[j].src_mac_id[3],
				   nt->bin_array->bin_tbl[j].src_mac_id[2],
				   nt->bin_array->bin_tbl[j].src_mac_id[1],
				   nt->bin_array->bin_tbl[j].src_mac_id[0],
				   nt->bin_array->bin_tbl[j].src_mac_id[5],
				   nt->bin_array->bin_tbl[j].src_mac_id[4],
				   nt->nt_array->node_tbl[o].entry_state,
				   nt->nt_array->node_tbl[o].status,
				   nt->nt_array->node_tbl[o].cnt_ra,
				   nt->nt_array->node_tbl[o].cnt_rb,
				   nt->nt_array->node_tbl[o].time_last_seen_s,
				   nt->nt_array->node_tbl[o].time_last_seen_a,
				   nt->nt_array->node_tbl[o].time_last_seen_b
				   );
			cnt++;
		}
	seq_printf(sfp, "\nTotal valid entries %d; lre_cnt %d\n",
		   cnt, nt->nt_lre_cnt->lre_cnt);

	return 0;
}

static int
prueth_nt_bins_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, prueth_nt_bins_show,
			   inode->i_private);
}

const struct file_operations prueth_nt_bins_fops = {
	.owner	= THIS_MODULE,
	.open	= prueth_nt_bins_open,
	.read	= seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
