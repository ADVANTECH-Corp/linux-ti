/*
 * PRU Ethernet Driver
 *
 * Copyright (C) 2015-2017 Texas Instruments Incorporated - http://www.ti.com
 *	Roger Quadros <rogerq@ti.com>
 *	Andrew F. Davis <afd@ti.com>
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

#include <linux/etherdevice.h>
#include <linux/genalloc.h>
#include <linux/if_vlan.h>
#include <linux/hrtimer.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#ifdef CONFIG_PREEMPT_RT_FULL
#include <linux/swork.h>
#endif
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/of_mdio.h>
#include <linux/of_net.h>
#include <linux/of_platform.h>
#include <linux/phy.h>
#include <linux/pruss.h>
#include <linux/remoteproc.h>
#include <linux/net_tstamp.h>
#include <linux/ptp_classify.h>
#include <net/lredev.h>

#include "icss_time_sync.h"
#include "prueth.h"
#include "icss_mii_rt.h"
#include "icss_switch.h"
#include "hsr_prp_firmware.h"
#include "iep.h"
#include "prueth_dbgfs.h"
#include "prueth_node_tbl.h"

#define PRUETH_MODULE_VERSION "0.2"
#define PRUETH_MODULE_DESCRIPTION "PRUSS Ethernet driver"

static int debug_level = -1;
module_param(debug_level, int, 0444);
MODULE_PARM_DESC(debug_level, "PRUETH debug level (NETIF_MSG bits)");

/* ensure that order of PRUSS mem regions is same as above */
static enum pruss_mem pruss_mem_ids[] = { PRUSS_MEM_DRAM0, PRUSS_MEM_DRAM1,
					  PRUSS_MEM_SHRD_RAM2, PRUSS_MEM_IEP,
					  PRUSS_MEM_ECAP };

static int pruss0_ethtype = PRUSS_ETHTYPE_EMAC;
module_param(pruss0_ethtype, int, 0444);
MODULE_PARM_DESC(pruss0_ethtype, "Choose PRUSS0 eth-type firmware");

static int pruss1_ethtype = PRUSS_ETHTYPE_EMAC;
module_param(pruss1_ethtype, int, 0444);
MODULE_PARM_DESC(pruss1_ethtype, "Choose PRUSS1 eth-type firmware");

static int pruss2_ethtype = PRUSS_ETHTYPE_EMAC;
module_param(pruss2_ethtype, int, 0444);
MODULE_PARM_DESC(pruss2_ethtype, "Choose PRUSS2 eth-type firmware");

#define PRUETH_DEFAULT_MC_MASK "FF:FF:FF:FF:FF:FF"
static char *pruss0_port0_mc_mask = PRUETH_DEFAULT_MC_MASK;
module_param(pruss0_port0_mc_mask, charp, 0444);
MODULE_PARM_DESC(pruss0_port0_mc_mask, "Choose pruss0 port0 MC mask");

static char *pruss0_port1_mc_mask = PRUETH_DEFAULT_MC_MASK;
module_param(pruss0_port1_mc_mask, charp, 0444);
MODULE_PARM_DESC(pruss0_port1_mc_mask, "Choose pruss0 port1 MC mask");

static char *pruss1_port0_mc_mask = PRUETH_DEFAULT_MC_MASK;
module_param(pruss1_port0_mc_mask, charp, 0444);
MODULE_PARM_DESC(pruss1_port0_mc_mask, "Choose pruss1 port0 MC mask");

static char *pruss1_port1_mc_mask = PRUETH_DEFAULT_MC_MASK;
module_param(pruss1_port1_mc_mask, charp, 0444);
MODULE_PARM_DESC(pruss1_port1_mc_mask, "Choose pruss1 port1 MC mask");

static char *pruss2_port0_mc_mask = PRUETH_DEFAULT_MC_MASK;
module_param(pruss2_port0_mc_mask, charp, 0444);
MODULE_PARM_DESC(pruss2_port0_mc_mask, "Choose pruss2 port0 MC mask");

static char *pruss2_port1_mc_mask = PRUETH_DEFAULT_MC_MASK;
module_param(pruss2_port1_mc_mask, charp, 0444);
MODULE_PARM_DESC(pruss2_port1_mc_mask, "Choose pruss2 port1 MC mask");

static int pruss0_fw_drop_untagged;
module_param(pruss0_fw_drop_untagged, int, 0444);
MODULE_PARM_DESC(pruss0_fw_drop_untagged, "Drop Untagged VLAN frames at PRU firmware");

static int pruss1_fw_drop_untagged;
module_param(pruss1_fw_drop_untagged, int, 0444);
MODULE_PARM_DESC(pruss1_fw_drop_untagged, "Drop Untagged VLAN frames at PRU firmware");

static int pruss2_fw_drop_untagged;
module_param(pruss2_fw_drop_untagged, int, 0444);
MODULE_PARM_DESC(pruss2_fw_drop_untagged, "Drop Untagged VLAN frames at PRU firmware");

struct prueth_fw_offsets fw_offsets_v1_0 = {
	.hash_mask = V1_0_HASH_MASK,
	.index_array_offset = V1_0_INDEX_ARRAY_NT,
	.bin_array_offset = V1_0_BIN_ARRAY,
	.nt_array_offset = V1_0_NODE_TABLE_NEW,
	.index_array_loc = V1_0_INDEX_ARRAY_LOC,
	.bin_array_loc = V1_0_BIN_ARRAY_LOC,
	.nt_array_loc = V1_0_NODE_TABLE_LOC,
	.index_array_max_entries = V1_0_INDEX_TBL_MAX_ENTRIES,
	.bin_array_max_entries = V1_0_BIN_TBL_MAX_ENTRIES,
	.nt_array_max_entries = V1_0_NODE_TBL_MAX_ENTRIES,
	/* Set on emac_ndo_open depending on eth_type */
	.vlan_ctrl_byte = 0,
	.vlan_filter_tbl = 0,
	.mc_ctrl_byte = 0,
	.mc_filter_mask = 0,
	.mc_filter_tbl = 0
};

struct prueth_fw_offsets fw_offsets_v2_1 = {
	.hash_mask = V2_1_HASH_MASK,
	.index_array_offset = V2_1_INDEX_ARRAY_NT,
	.bin_array_offset = V2_1_BIN_ARRAY,
	.nt_array_offset = V2_1_NODE_TABLE_NEW,
	.index_array_loc = V2_1_INDEX_ARRAY_LOC,
	.bin_array_loc = V2_1_BIN_ARRAY_LOC,
	.nt_array_loc = V2_1_NODE_TABLE_LOC,
	.index_array_max_entries = V2_1_INDEX_TBL_MAX_ENTRIES,
	.bin_array_max_entries = V2_1_BIN_TBL_MAX_ENTRIES,
	.nt_array_max_entries = V2_1_NODE_TBL_MAX_ENTRIES,
	/* Set on emac_ndo_open depending on eth_type */
	.vlan_ctrl_byte = 0,
	.vlan_filter_tbl = 0,
	.mc_ctrl_byte = 0,
	.mc_filter_mask = 0,
	.mc_filter_tbl = 0
};

#define IEP_GLOBAL_CFG_REG_MASK      0xfffff
#define IEP_GLOBAL_CFG_REG_PTP_VAL      0x111
#define IEP_GLOBAL_CFG_REG_DEF_VAL      0x551

/* ECAP registers */
#define ECAP_TSCTR                      0
#define ECAP_CAP1                       8
#define ECAP_CAP2                       0xC
#define ECAP_ECCTL1                     0x28
#define ECAP_ECCTL2                     0x2A
#define ECAP_ECEINT                     0x2C
#define ECAP_ECCLR                      0x30

#define ECAP_ECCTL2_TSCTRSTOP_MASK      0x10
#define ECAP_ECCTL2_CAP_APWM_MASK       0x200
#define ECAP_ECCLR_INT_MASK             1
#define ECAP_ECCLR_CEVT1_MASK           2
#define ECAP_ECCLR_CEVT2_MASK           4
#define ECAP_ECCLR_CEVT3_MASK           8
#define ECAP_ECCLR_CEVT4_MASK           0x10
#define ECAP_ECCLR_CNTOVF_MASK          0x20
#define ECAP_ECCLR_PRDEQ_MASK           0x40
#define ECAP_ECCLR_CMPEQ_MASK           0x80
#define ECAP_ECEINT_PRDEQ_MASK          0x40

#define ECAP_ECCTL2_INIT_VAL           (ECAP_ECCTL2_TSCTRSTOP_MASK | \
					ECAP_ECCTL2_CAP_APWM_MASK)
#define ECAP_CAP2_MAX_COUNT            0xFFFFFFFF
#define ECAP_ECCLR_CLR_VAL             0xFF

/* in usec */
#define DEFAULT_RX_TIMEOUT_USEC       123
/* Duration of 3 frames of 1528 bytes each. If we go beyond this,
 * receive buffer overflow may happen assuming 4 MTU buffer. So
 * set this as the limit
 */
#define MAX_RX_TIMEOUT_USEC            (123 * 3)
/* ECAP has 200Mhz clock. So each tick is 5 nsec. i.e 1000/200 */
#define ECAP_TICK_NSEC                  5

#define PRUETH_ETH_TYPE_OFFSET           12
#define PRUETH_ETH_TYPE_UPPER_SHIFT      8

static int prueth_ecap_initialization(struct prueth_emac *emac,
				      u32 new_timeout_val,
				      u32 use_adaptive,
				      unsigned int *curr_timeout_val)
{
	struct prueth *prueth = emac->prueth;
	void __iomem *ecap = prueth->mem[PRUETH_MEM_ECAP].va;
	void __iomem *sram = prueth->mem[PRUETH_MEM_SHARED_RAM].va;
	u8 val = INTR_PAC_DIS_ADP_LGC_DIS;

	/* Not all platform uses ecap. So check and return */
	if (!ecap)
		return -ENOTSUPP;

	if (!new_timeout_val) {
		/* disable pacing */
		writeb_relaxed(val, sram + emac->rx_int_pacing_offset);
		if (PRUETH_HAS_RED(prueth)) {
			prueth->emac[PRUETH_MAC0]->rx_pacing_timeout =
				new_timeout_val;
			prueth->emac[PRUETH_MAC1]->rx_pacing_timeout =
				new_timeout_val;
		} else {
			emac->rx_pacing_timeout = new_timeout_val;
		}
		return 0;
	}

	if (use_adaptive)
		val = INTR_PAC_ENA_ADP_LGC_ENA;
	else
		val = INTR_PAC_ENA_ADP_LGC_DIS;

	if (!*curr_timeout_val) {
		writew_relaxed(ECAP_ECCTL2_INIT_VAL, ecap + ECAP_ECCTL2);
		writel_relaxed(ECAP_CAP2_MAX_COUNT, ecap + ECAP_CAP1);
		writel_relaxed(ECAP_CAP2_MAX_COUNT, ecap + ECAP_CAP2);

		writeb_relaxed(INTR_PAC_DIS_ADP_LGC_DIS,
			       sram + emac->rx_int_pacing_offset);
		if (PRUETH_HAS_RED(prueth) ||
		    (PRUETH_IS_EMAC(prueth) &&
			 emac->port_id == PRUETH_PORT_MII0)) {
			writel_relaxed(new_timeout_val *
				       NSEC_PER_USEC / ECAP_TICK_NSEC,
				       sram + INTR_PAC_TMR_EXP_OFFSET_PRU0);
			writel_relaxed(INTR_PAC_PREV_TS_RESET_VAL,
				       sram + INTR_PAC_PREV_TS_OFFSET_PRU0);
		}
		if (PRUETH_HAS_RED(prueth) ||
		    (PRUETH_IS_EMAC(prueth) &&
		     emac->port_id == PRUETH_PORT_MII1)) {
			writel_relaxed(new_timeout_val *
				       NSEC_PER_USEC / ECAP_TICK_NSEC,
				       sram + INTR_PAC_TMR_EXP_OFFSET_PRU1);
			writel_relaxed(INTR_PAC_PREV_TS_RESET_VAL,
				       sram + INTR_PAC_PREV_TS_OFFSET_PRU1);
		}
	} else {
		if (PRUETH_HAS_RED(prueth) ||
		    (PRUETH_IS_EMAC(prueth) &&
		     emac->port_id == PRUETH_PORT_MII0)) {
			writel_relaxed(new_timeout_val *
				       NSEC_PER_USEC / ECAP_TICK_NSEC,
				       sram + INTR_PAC_TMR_EXP_OFFSET_PRU0);
		}
		if (PRUETH_HAS_RED(prueth) ||
		    (PRUETH_IS_EMAC(prueth) &&
		     emac->port_id == PRUETH_PORT_MII1)) {
			writel_relaxed(new_timeout_val *
				       NSEC_PER_USEC / ECAP_TICK_NSEC,
				       sram + INTR_PAC_TMR_EXP_OFFSET_PRU1);
		}
	}
	writeb_relaxed(val, sram + emac->rx_int_pacing_offset);

	if (PRUETH_HAS_RED(prueth)) {
		prueth->emac[PRUETH_MAC0]->rx_pacing_timeout = new_timeout_val;
		prueth->emac[PRUETH_MAC1]->rx_pacing_timeout = new_timeout_val;
	} else {
		emac->rx_pacing_timeout = new_timeout_val;
	}
	return 0;
}

static inline enum prueth_port other_port_id(enum prueth_port port_id)
{
	enum prueth_port other_port_id =
		(port_id == PRUETH_PORT_MII0) ? PRUETH_PORT_MII1 :
						PRUETH_PORT_MII0;
	return other_port_id;
}

static inline bool is_ptp_cut_through_event(u8 ts_msgtype)
{
	return (ts_msgtype == PTP_SYNC_MSG_ID) ||
	       (ts_msgtype == PTP_DLY_REQ_MSG_ID);
}

static inline int is_hsr_skb(struct sk_buff *skb)
{
	unsigned char *p;

	if (!skb->data)
		return 0;

	p = skb->data;

	/* FIXME: should use macros to access header fields */
	return (*(p + 12) == 0x89 && *(p + 13) == 0x2f);
}

static inline u32 prueth_read_reg(struct prueth *prueth,
				  enum prueth_mem region,
				  unsigned int reg)
{
	return readl_relaxed(prueth->mem[region].va + reg);
}

static inline void prueth_write_reg(struct prueth *prueth,
				    enum prueth_mem region,
				    unsigned int reg, u32 val)
{
	writel_relaxed(val, prueth->mem[region].va + reg);
}

static inline
void prueth_set_reg(struct prueth *prueth, enum prueth_mem region,
		    unsigned int reg, u32 mask, u32 set)
{
	u32 val;

	val = prueth_read_reg(prueth, region, reg);
	val &= ~mask;
	val |= (set & mask);
	prueth_write_reg(prueth, region, reg, val);
}

static inline bool pruptp_is_tx_enabled(struct prueth *prueth)
{
	return !!prueth->iep->ptp_tx_enable;
}

static inline void emac_ptp_rx_enable(struct prueth_emac *emac, int enable)
{
	emac->ptp_rx_enable = enable;
}

static inline bool emac_is_ptp_rx_enabled(struct prueth_emac *emac)
{
	return !!emac->ptp_rx_enable;
}

static inline void emac_ptp_tx_enable(struct prueth_emac *emac, int enable)
{
	emac->ptp_tx_enable = enable;
}

static inline bool emac_is_ptp_tx_enabled(struct prueth_emac *emac)
{
	return !!emac->ptp_tx_enable;
}

static u8 pruptp_ts_msgtype(struct sk_buff *skb)
{
	unsigned int ptp_class = ptp_classify_raw(skb);
	u16 *seqid;
	unsigned int offset = 0;
	u8 *msgtype, *data = skb->data;

	if (ptp_class == PTP_CLASS_NONE)
		return 0xff;

	if (ptp_class & PTP_CLASS_VLAN)
		offset += VLAN_HLEN;

	switch (ptp_class & PTP_CLASS_PMASK) {
	case PTP_CLASS_IPV4:
		offset += ETH_HLEN + IPV4_HLEN(data + offset) + UDP_HLEN;
		break;
	case PTP_CLASS_IPV6:
		offset += ETH_HLEN + IP6_HLEN + UDP_HLEN;
		break;
	case PTP_CLASS_L2:
		offset += ETH_HLEN;
		break;
	default:
		return 0xff;
	}

	if (skb->len + ETH_HLEN < offset + OFF_PTP_SEQUENCE_ID + sizeof(*seqid))
		return 0xff;

	if (unlikely(ptp_class & PTP_CLASS_V1))
		msgtype = data + offset + OFF_PTP_CONTROL;
	else
		msgtype = data + offset;

	return (*msgtype & 0xf);
}

#define TS_NOTIFY_SIZE	1
#define TS_FIELD_SIZE	12
#define NUM_TS_EVENTS	3

static void pruptp_reset_tx_ts_reg(struct prueth_emac *emac,
				   u32 ts_notify_ofs, u32 ts_ofs)
{
	struct prueth *prueth = emac->prueth;
	void __iomem *sram = prueth->mem[PRUETH_MEM_SHARED_RAM].va;

	writeb(0, sram + ts_notify_ofs);
	iep_reset_timestamp(prueth->iep, ts_ofs);
}

static void pruptp_reset_tx_msg_ts(struct prueth_emac *emac, u8 msg_t)
{
	u32 ts_notify_ofs, ts_ofs;

	/* SYNC notify */
	ts_ofs = TX_SYNC_TIMESTAMP_OFFSET_P1 +
		 (emac->port_id - 1) * NUM_TS_EVENTS * TS_FIELD_SIZE;
	ts_notify_ofs = TX_TS_NOTIFICATION_OFFSET_SYNC_P1 +
			NUM_TS_EVENTS * TS_NOTIFY_SIZE *
			(emac->port_id - 1);

	if (msg_t == PTP_PDLY_REQ_MSG_ID) {
		ts_ofs += TS_FIELD_SIZE;
		ts_notify_ofs += TS_NOTIFY_SIZE;
	} else if (msg_t == PTP_PDLY_RSP_MSG_ID) {
		ts_ofs += (2 * TS_FIELD_SIZE);
		ts_notify_ofs += (2 * TS_NOTIFY_SIZE);
	} else if (msg_t != PTP_SYNC_MSG_ID) {
		netdev_err(emac->ndev,
			   "Can't reset tx ts: unknown msg_t %u\n", msg_t);
		return;
	}

	pruptp_reset_tx_ts_reg(emac, ts_notify_ofs, ts_ofs);
}

static void pruptp_reset_tx_ts(struct prueth_emac *emac)
{
	pruptp_reset_tx_msg_ts(emac, PTP_SYNC_MSG_ID);
	pruptp_reset_tx_msg_ts(emac, PTP_PDLY_REQ_MSG_ID);
	pruptp_reset_tx_msg_ts(emac, PTP_PDLY_RSP_MSG_ID);
}

static int pruptp_proc_tx_ts(struct prueth_emac *emac,
			     u8 ts_msgtype, u16 ts_ofs, u32 ts_notify_mask)
{
	struct prueth *prueth = emac->prueth;
	struct sk_buff *skb;
	int ret;
	unsigned long flags, tmo;
	struct tx_ev_cb_data *cb = &emac->tx_ev_cb[ts_msgtype];

	/* get the msg from list */
	spin_lock_irqsave(&emac->ev_msg_lock, flags);
	skb = cb->skb;
	tmo = cb->tmo;
	cb->skb = NULL;
	cb->tmo = 0;
	spin_unlock_irqrestore(&emac->ev_msg_lock, flags);
	if (!skb) {
		/* In case of HSR, tx timestamp may be generated by
		 * cut-through packets such as SYNC, which does not
		 * have a corresponding queued tx packet. Such a tx
		 * timestamp is consumed by the rx port when processing
		 * the rx timestamp.
		 */
		if (PRUETH_HAS_HSR(prueth))
			return 0;

		netdev_err(emac->ndev,
			   "no tx msg %u found waiting for ts\n", ts_msgtype);
		return -ENOMSG;
	}

	/* get the timestamp */
	ret = iep_tx_timestamp(prueth->iep, ts_ofs, skb, tmo);
	if (ret == -ETIME) {
		netdev_err(emac->ndev,
			   "invalid timestamp for tx msg %u: EXPIRED\n",
			   ts_msgtype);
	} else if (ret < 0) {
		netdev_err(emac->ndev,
			   "invalid timestamp for tx msg %u: err %d\n",
			   ts_msgtype, ret);
	}

	dev_consume_skb_any(skb);

	return 0;
}

static void _pruptp_tx_ts_work(struct prueth_emac *emac)
{
	struct prueth *prueth = emac->prueth;
	void __iomem *sram = prueth->mem[PRUETH_MEM_SHARED_RAM].va;
	u32 ts_notify_ofs, ts_ofs, ts_notify_mask = 0;

	/* Assumes timestamps for a port are in consecutive mem loc
	 * and port2's timestamps are right after port1's
	 */

	/* Find out what ptp event message(s) raise(s) the intr
	 * and process the timestamp
	 */
	/* SYNC notify */
	ts_ofs = TX_SYNC_TIMESTAMP_OFFSET_P1 +
		 (emac->port_id - 1) * NUM_TS_EVENTS * TS_FIELD_SIZE;
	ts_notify_ofs = TX_TS_NOTIFICATION_OFFSET_SYNC_P1 +
			NUM_TS_EVENTS * TS_NOTIFY_SIZE *
			(emac->port_id - 1);

	/* get and reset the ts notifications */
	memcpy_fromio(&ts_notify_mask, sram + ts_notify_ofs, 3);
	memset_io(sram + ts_notify_ofs, 0, 3);

	if (ts_notify_mask & 0x000000ff) {
		pruptp_proc_tx_ts(emac, PTP_SYNC_MSG_ID, ts_ofs,
				  ts_notify_mask);
	}

	/* PDELAY_REQ */
	ts_ofs += TS_FIELD_SIZE;
	if (ts_notify_mask & 0x0000ff00) {
		pruptp_proc_tx_ts(emac, PTP_PDLY_REQ_MSG_ID, ts_ofs,
				  ts_notify_mask);
	}

	/* PDELAY_RSP */
	ts_ofs += TS_FIELD_SIZE;
	if (ts_notify_mask & 0x00ff0000) {
		pruptp_proc_tx_ts(emac, PTP_PDLY_RSP_MSG_ID, ts_ofs,
				  ts_notify_mask);
	}
}

#ifdef CONFIG_PREEMPT_RT_FULL
static void pruptp_tx_ts_work(struct swork_event *event)
{
	struct prueth_emac *emac =
		container_of(event, struct prueth_emac, ptp_tx_work_event);

	_pruptp_tx_ts_work(emac);
}

static void prueth_queue_ptp_tx_work(struct prueth_emac *emac)
{
	swork_queue(&emac->ptp_tx_work_event);
}

static void prueth_init_ptp_tx_work(struct prueth_emac *emac)
{
	WARN_ON(swork_get());
	INIT_SWORK(&emac->ptp_tx_work_event, pruptp_tx_ts_work);
}

static void prueth_cancel_ptp_tx_work(struct prueth_emac *emac) { }

static void prueth_clean_ptp_tx_work(void)
{
	swork_put();
}

#else /* !CONFIG_PREEMPT_RT_FULL */

static void pruptp_tx_ts_work(struct work_struct *event)
{
	struct prueth_emac *emac =
		container_of(event, struct prueth_emac, ptp_tx_work_event);

	_pruptp_tx_ts_work(emac);
}

static void prueth_queue_ptp_tx_work(struct prueth_emac *emac)
{
	schedule_work(&emac->ptp_tx_work_event);
}

static void prueth_init_ptp_tx_work(struct prueth_emac *emac)
{
	INIT_WORK(&emac->ptp_tx_work_event, pruptp_tx_ts_work);
}

static void prueth_cancel_ptp_tx_work(struct prueth_emac *emac)
{
	cancel_work_sync(&emac->ptp_tx_work_event);
}

static void prueth_clean_ptp_tx_work(void) { }

#endif /* !CONFIG_PREEMPT_RT_FULL */

static int pruptp_hsr_cut_through_tx_ts(struct prueth_emac *emac,
					struct sk_buff *skb,
					u8 ts_msgtype)
{
	struct prueth *prueth = emac->prueth;
	enum prueth_port pair_port_id = other_port_id(emac->port_id);
	u32 ts_ofs;
	struct skb_shared_hwtstamps *red_ssh;
	struct prueth_emac *other_emac = prueth->emac[pair_port_id - 1];
	u64 ns = 0;

	ts_ofs = TX_SYNC_TIMESTAMP_OFFSET_P1 +
		 (pair_port_id - 1) * NUM_TS_EVENTS * TS_FIELD_SIZE;

	if (ts_msgtype == PTP_DLY_REQ_MSG_ID)
		ts_ofs += TS_FIELD_SIZE;

	iep_get_timestamp(prueth->iep, ts_ofs, &ns);

	if (!ns && other_emac->link) {
		/* Paired port link is up. That means there will be ct ts.
		 * Come back to get it laster.
		 */
		return -EAGAIN;
	}

	/* Save the cut-through tx ts in skb redinfo. */
	red_ssh = skb_redinfo_hwtstamps(skb);
	memset(red_ssh, 0, sizeof(*red_ssh));
	red_ssh->hwtstamp = ns_to_ktime(ns);
	return 0;
}

static void pruptp_hsr_cut_thru_ts_work(struct kthread_work *work)
{
	struct prueth_emac *emac = container_of(work, struct prueth_emac,
						ct_work.work);
	struct net_device *ndev = emac->ndev;
	unsigned long flags;
	struct sk_buff *skb;
	int i, ret, schedule = PTP_DLY_REQ_MSG_ID + 1;

	spin_lock_irqsave(&emac->ct_lock, flags);
	for (i = 0; i <= PTP_DLY_REQ_MSG_ID; i++) {
		skb = emac->ct_evt_cb[i].skb;
		if (!skb) {
			--schedule;
			continue;
		}

		++emac->ct_evt_cb[i].tmo;
		ret = pruptp_hsr_cut_through_tx_ts(emac, skb, i);
		if (ret)
			/* Ct tx ts is still not available. Come back later.
			 * We continue to wait for ct ts until either it
			 * is available (even it may be too late) or kicked
			 * out by another msg of the same type. This is to
			 * make sure ts returned by fw are for the matching
			 * msg.
			 */
			continue;

		/* Got the ct tx ts but too late (> 3usec). We don't
		 * want to forward ct ts up for otherwise the delayed
		 * rx and ct ts may be mis-used by user space app.
		 */
		if (emac->ct_evt_cb[i].tmo > 3) {
			dev_kfree_skb_any(emac->ct_evt_cb[i].skb);
			emac->ct_evt_cb[i].skb = NULL;
			emac->ct_evt_cb[i].tmo = 0;
			--schedule;
			netdev_warn(emac->ndev,
				    "Dropped ct msg %u. EXPIRED\n", i);
			continue;
		}

		/* Got the ct tx ts. Send packet up the stack. */
		skb->protocol = eth_type_trans(skb, ndev);
		netif_rx(skb);

		emac->ct_evt_cb[i].skb = NULL;
		emac->ct_evt_cb[i].tmo = 0;
		--schedule;
	}
	spin_unlock_irqrestore(&emac->ct_lock, flags);

	if (schedule) {
		kthread_queue_delayed_work(emac->ct_kworker,
					   &emac->ct_work,
					   usecs_to_jiffies(1));
	}
}

static int pruptp_hsr_cut_thru_ts_work_stop(struct prueth_emac *emac)
{
	kthread_cancel_delayed_work_sync(&emac->ct_work);
	kthread_destroy_worker(emac->ct_kworker);
	return 0;
}

static int pruptp_hsr_cut_thru_ts_work_init(struct prueth_emac *emac)
{
	spin_lock_init(&emac->ct_lock);

	kthread_init_delayed_work(&emac->ct_work, pruptp_hsr_cut_thru_ts_work);

	if (emac->port_id == PRUETH_PORT_MII0)
		emac->ct_kworker = kthread_create_worker(0, "emac1_ct");
	else
		emac->ct_kworker = kthread_create_worker(0, "emac2_ct");

	return 0;
}

static int pruptp_rx_timestamp(struct prueth_emac *emac, struct sk_buff *skb)
{
	struct prueth *prueth = emac->prueth;
	bool changed = false;
	u32 ts_ofs;
	u8 ts_msgtype;
	int ret;
	unsigned long flags;
	int i, schedule = 1;

	if (!emac_is_ptp_rx_enabled(emac))
		return -EPERM;

	if (PRUETH_HAS_HSR(prueth) && is_hsr_skb(skb)) {
		/* This 6-byte shift is just a trick to skip
		 * the size of a hsr tag so that the same
		 * pruptp_ts_msgtype can be re-used to parse
		 * hsr tagged skbs
		 */
		skb->data += 6;
		changed = true;
	}

	ts_msgtype = pruptp_ts_msgtype(skb);

	if (changed)
		skb->data -= 6;

	if ((ts_msgtype != PTP_SYNC_MSG_ID) &&
	    (ts_msgtype != PTP_PDLY_REQ_MSG_ID) &&
	    (ts_msgtype != PTP_PDLY_RSP_MSG_ID))
		return -ENOENT;

	/* get the ts location for this port */
	ts_ofs = RX_SYNC_TIMESTAMP_OFFSET_P1 +
		 (emac->port_id - 1) * NUM_TS_EVENTS * TS_FIELD_SIZE;

	if (ts_msgtype == PTP_PDLY_REQ_MSG_ID)
		ts_ofs += TS_FIELD_SIZE;
	else if (ts_msgtype == PTP_PDLY_RSP_MSG_ID)
		ts_ofs += (2 * TS_FIELD_SIZE);

	ret = iep_rx_timestamp(prueth->iep, ts_ofs, skb);
	if (ret < 0) {
		netdev_err(emac->ndev, "invalid timestamp for rx msg %u\n",
			   ts_msgtype);
		return ret;
	}

	if (PRUETH_HAS_HSR(prueth) && is_ptp_cut_through_event(ts_msgtype)) {
		/* Received SYNC in HSR mode. That means a copy of it is
		 * cut-through by fw and a tx ts is available on the other
		 * port. So save the tx ts in skb's shared redinfo
		 */
		ret = pruptp_hsr_cut_through_tx_ts(emac, skb, ts_msgtype);
		if (ret != -EAGAIN)
			return ret;

		spin_lock_irqsave(&emac->ct_lock, flags);

		for (i = 0; i <= PTP_DLY_REQ_MSG_ID; i++) {
			/* If a msg is already waiting, then work is
			 * already scheduled
			 */
			if (emac->ct_evt_cb[i].skb) {
				schedule = 0;
				break;
			}
		}

		if (emac->ct_evt_cb[ts_msgtype].skb) {
			/* Old msg has not gotten a cut-thru ts yet.
			 * Drop it to make room.
			 */
			dev_kfree_skb_any(emac->ct_evt_cb[ts_msgtype].skb);
			netdev_dbg(emac->ndev,
				   "Dropped stale ct evt msg %d.\n",
				   ts_msgtype);
		}
		emac->ct_evt_cb[ts_msgtype].skb = skb;
		emac->ct_evt_cb[ts_msgtype].tmo = 1;

		spin_unlock_irqrestore(&emac->ct_lock, flags);

		if (schedule) {
			kthread_queue_delayed_work(emac->ct_kworker,
						   &emac->ct_work,
						   usecs_to_jiffies(1));
		}
	}

	return ret;
}

static struct prueth_queue_info queue_infos[PRUETH_PORT_QUEUE_MAX][NUM_QUEUES];
static struct prueth_queue_info tx_colq_infos[PRUETH_PORT_MAX];
static struct prueth_col_tx_context_info col_tx_context_infos[PRUETH_PORT_MAX];
static struct prueth_col_rx_context_info col_rx_context_infos[PRUETH_PORT_MAX];
static struct prueth_queue_desc queue_descs[PRUETH_PORT_MAX][NUM_QUEUES + 1];

/* VLAN-tag PCP to priority queue map for EMAC used by driver. Should be
 * in sync with fw_pcp_default_priority_queue_map[]
 * Index is PCP val.
 *   low  - pcp 0..1 maps to Q4
 *              2..3 maps to Q3
 *              4..5 maps to Q2
 *   high - pcp 6..7 maps to Q1.
 *
 * VLAN-tag PCP to priority queue map for Switch/HSR/PRP used by driver
 * Index is PCP val / 2.
 *   low  - pcp 0..3 maps to Q4 for Host
 *   high - pcp 4..7 maps to Q3 for Host
 *   low  - pcp 0..3 maps to Q2 for PRU-x where x = 1 for PRUETH_PORT_MII0
 *          0 for PRUETH_PORT_MII1
 *   high - pcp 4..7 maps to Q1 for PRU-x
 */
static const unsigned short emac_pcp_tx_priority_queue_map[] = {
	PRUETH_QUEUE4, PRUETH_QUEUE4,
	PRUETH_QUEUE3, PRUETH_QUEUE3,
	PRUETH_QUEUE2, PRUETH_QUEUE2,
	PRUETH_QUEUE1, PRUETH_QUEUE1,
};

/* Scan order of Priority queues for Switch/HSR/PRP/Dual EMAC at each ingress
 * port. Should be in sync with fw_pcp_default_priority_queue_map[].
 * Lower queue value has higher priority. i.e Q3 is higher priority
 * than Q4. Decides the scanning order by driver. Index is port/queue id.
 *   low  - pcp 0..3 maps to Q4 for Host from PRU-0
 *   high - pcp 4..7 maps to Q3 for Host from PRU-0
 *   low  - pcp 0..3 maps to Q2 for Host from PRU-1
 *   high - pcp 4..7 maps to Q1 for Host from PRU-1
 */
static const unsigned int emac_port_rx_priority_queue_ids[][2] = {
	[PRUETH_PORT_HOST] = {
		0, 0
	},
	[PRUETH_PORT_MII0] = {
		PRUETH_QUEUE1,
		PRUETH_QUEUE2,
	},
	[PRUETH_PORT_MII1] = {
		PRUETH_QUEUE3,
		PRUETH_QUEUE4
	},
};

static int prueth_sw_hostconfig(struct prueth *prueth)
{
	void __iomem *dram1_base = prueth->mem[PRUETH_MEM_DRAM1].va;
	struct prueth_mmap_port_cfg_basis *pb;
	struct prueth_mmap_ocmc_cfg *oc = &prueth->mmap_ocmc_cfg;
	struct prueth_mmap_sram_cfg *s = &prueth->mmap_sram_cfg;
	void __iomem *dram;

	/* queue information table */
	dram = dram1_base + P0_Q1_RX_CONTEXT_OFFSET;
	memcpy_toio(dram, queue_infos[PRUETH_PORT_QUEUE_HOST],
		    sizeof(queue_infos[PRUETH_PORT_QUEUE_HOST]));

	dram = dram1_base + COL_RX_CONTEXT_P0_OFFSET_ADDR;
	memcpy_toio(dram, &col_rx_context_infos[PRUETH_PORT_QUEUE_HOST],
		    sizeof(col_rx_context_infos[PRUETH_PORT_QUEUE_HOST]));

	/* buffer descriptor offset table*/
	dram = dram1_base + QUEUE_DESCRIPTOR_OFFSET_ADDR;
	writew(s->bd_offset[PRUETH_PORT_HOST][PRUETH_QUEUE1], dram);
	writew(s->bd_offset[PRUETH_PORT_HOST][PRUETH_QUEUE2], dram + 2);
	writew(s->bd_offset[PRUETH_PORT_HOST][PRUETH_QUEUE3], dram + 4);
	writew(s->bd_offset[PRUETH_PORT_HOST][PRUETH_QUEUE4], dram + 6);

	/* buffer offset table */
	dram = dram1_base + QUEUE_OFFSET_ADDR;
	writew(oc->buffer_offset[PRUETH_PORT_HOST][PRUETH_QUEUE1], dram);
	writew(oc->buffer_offset[PRUETH_PORT_HOST][PRUETH_QUEUE2], dram + 2);
	writew(oc->buffer_offset[PRUETH_PORT_HOST][PRUETH_QUEUE3], dram + 4);
	writew(oc->buffer_offset[PRUETH_PORT_HOST][PRUETH_QUEUE4], dram + 6);

	/* queue size lookup table */
	pb = &prueth->mmap_port_cfg_basis[PRUETH_PORT_HOST];
	dram = dram1_base + QUEUE_SIZE_ADDR;
	writew(pb->queue_size[PRUETH_QUEUE1], dram);
	writew(pb->queue_size[PRUETH_QUEUE2], dram + 2);
	writew(pb->queue_size[PRUETH_QUEUE3], dram + 4);
	writew(pb->queue_size[PRUETH_QUEUE4], dram + 6);

	/* queue table */
	dram = dram1_base + pb->queue1_desc_offset;
	memcpy_toio(dram, &queue_descs[PRUETH_PORT_QUEUE_HOST][0],
		    4 * sizeof(queue_descs[PRUETH_PORT_QUEUE_HOST][0]));

	return 0;
}

static int prueth_hostconfig(struct prueth *prueth)
{
	void __iomem *sram_base = prueth->mem[PRUETH_MEM_SHARED_RAM].va;
	struct prueth_mmap_port_cfg_basis *pb;
	struct prueth_mmap_ocmc_cfg *oc = &prueth->mmap_ocmc_cfg;
	struct prueth_mmap_sram_cfg *s = &prueth->mmap_sram_cfg;
	struct prueth_mmap_sram_emac *emac_sram = &s->mmap_sram_emac;
	void __iomem *sram;

	/* queue size lookup table */
	pb = &prueth->mmap_port_cfg_basis[PRUETH_PORT_HOST];
	sram = sram_base + emac_sram->host_queue_size_addr;
	writew(pb->queue_size[PRUETH_QUEUE1], sram);
	writew(pb->queue_size[PRUETH_QUEUE2], sram + 2);
	writew(pb->queue_size[PRUETH_QUEUE3], sram + 4);
	writew(pb->queue_size[PRUETH_QUEUE4], sram + 6);

	/* queue information table */
	sram = sram_base + emac_sram->host_q1_rx_context_offset;
	memcpy_toio(sram, queue_infos[PRUETH_PORT_QUEUE_HOST],
		    sizeof(queue_infos[PRUETH_PORT_QUEUE_HOST]));

	/* buffer offset table */
	sram = sram_base + emac_sram->host_queue_offset_addr;
	writew(oc->buffer_offset[PRUETH_PORT_HOST][PRUETH_QUEUE1], sram);
	writew(oc->buffer_offset[PRUETH_PORT_HOST][PRUETH_QUEUE2], sram + 2);
	writew(oc->buffer_offset[PRUETH_PORT_HOST][PRUETH_QUEUE3], sram + 4);
	writew(oc->buffer_offset[PRUETH_PORT_HOST][PRUETH_QUEUE4], sram + 6);

	/* buffer descriptor offset table*/
	sram = sram_base + emac_sram->host_queue_descriptor_offset_addr;
	writew(s->bd_offset[PRUETH_PORT_HOST][PRUETH_QUEUE1], sram);
	writew(s->bd_offset[PRUETH_PORT_HOST][PRUETH_QUEUE2], sram + 2);
	writew(s->bd_offset[PRUETH_PORT_HOST][PRUETH_QUEUE3], sram + 4);
	writew(s->bd_offset[PRUETH_PORT_HOST][PRUETH_QUEUE4], sram + 6);

	/* queue table */
	sram = sram_base + emac_sram->host_queue_desc_offset;
	memcpy_toio(sram, &queue_descs[PRUETH_PORT_QUEUE_HOST][0],
		    4 * sizeof(queue_descs[PRUETH_PORT_QUEUE_HOST][0]));

	return 0;
}

#define prueth_mii_set(dir, port, mask, set) \
	pruss_regmap_update(prueth->pruss, PRUSS_SYSCON_MII_RT, \
			    PRUSS_MII_RT_##dir##CFG##port, \
			    PRUSS_MII_RT_##dir##CFG_##dir##_##mask, set)

static void prueth_mii_init(struct prueth *prueth)
{
	/* Configuration of Port 0 Rx */
	prueth_mii_set(RX, 0, ENABLE, PRUSS_MII_RT_RXCFG_RX_ENABLE);
	prueth_mii_set(RX, 0, DATA_RDY_MODE_DIS,
		       PRUSS_MII_RT_RXCFG_RX_DATA_RDY_MODE_DIS);
	prueth_mii_set(RX, 0, MUX_SEL, 0x0);
	prueth_mii_set(RX, 0, L2_EN, PRUSS_MII_RT_RXCFG_RX_L2_EN);
	prueth_mii_set(RX, 0, CUT_PREAMBLE, PRUSS_MII_RT_RXCFG_RX_CUT_PREAMBLE);
	prueth_mii_set(RX, 0, L2_EOF_SCLR_DIS,
		       PRUSS_MII_RT_RXCFG_RX_L2_EOF_SCLR_DIS);

	/* Configuration of Port 0 Tx */
	pruss_regmap_update(prueth->pruss, PRUSS_SYSCON_MII_RT,
			    PRUSS_MII_RT_TX_IPG0, PRUSS_MII_RT_TX_IPG_IPG_MASK,
			    TX_MIN_IPG);

	prueth_mii_set(TX, 0, ENABLE, PRUSS_MII_RT_TXCFG_TX_ENABLE);
	prueth_mii_set(TX, 0, AUTO_PREAMBLE,
		       PRUSS_MII_RT_TXCFG_TX_AUTO_PREAMBLE);
	prueth_mii_set(TX, 0, 32_MODE_EN, PRUSS_MII_RT_TXCFG_TX_32_MODE_EN);

	if (PRUETH_HAS_SWITCH(prueth))
		prueth_mii_set(TX, 0, MUX_SEL, PRUSS_MII_RT_TXCFG_TX_MUX_SEL);
	else
		prueth_mii_set(TX, 0, MUX_SEL, 0x0);

	prueth_mii_set(TX, 0, START_DELAY_MASK,
		       TX_START_DELAY << PRUSS_MII_RT_TXCFG_TX_START_DELAY_SHIFT);
	prueth_mii_set(TX, 0, CLK_DELAY_MASK,
		       TX_CLK_DELAY << PRUSS_MII_RT_TXCFG_TX_CLK_DELAY_SHIFT);

	/* Configuration of Port 1 Rx */
	prueth_mii_set(RX, 1, ENABLE, PRUSS_MII_RT_RXCFG_RX_ENABLE);
	prueth_mii_set(RX, 1,
		       DATA_RDY_MODE_DIS, PRUSS_MII_RT_RXCFG_RX_DATA_RDY_MODE_DIS);
	prueth_mii_set(RX, 1, MUX_SEL, PRUSS_MII_RT_RXCFG_RX_MUX_SEL);
	prueth_mii_set(RX, 1, L2_EN, PRUSS_MII_RT_RXCFG_RX_L2_EN);
	prueth_mii_set(RX, 1, CUT_PREAMBLE, PRUSS_MII_RT_RXCFG_RX_CUT_PREAMBLE);
	prueth_mii_set(RX, 1, L2_EOF_SCLR_DIS,
		       PRUSS_MII_RT_RXCFG_RX_L2_EOF_SCLR_DIS);

	/* Configuration of Port 1 Tx */
	pruss_regmap_update(prueth->pruss, PRUSS_SYSCON_MII_RT,
			    PRUSS_MII_RT_TX_IPG1, PRUSS_MII_RT_TX_IPG_IPG_MASK,
			    TX_MIN_IPG);
	prueth_mii_set(TX, 1, ENABLE, PRUSS_MII_RT_TXCFG_TX_ENABLE);
	prueth_mii_set(TX, 1, AUTO_PREAMBLE,
		       PRUSS_MII_RT_TXCFG_TX_AUTO_PREAMBLE);
	prueth_mii_set(TX, 1, 32_MODE_EN, PRUSS_MII_RT_TXCFG_TX_32_MODE_EN);

	if (PRUETH_HAS_SWITCH(prueth))
		prueth_mii_set(TX, 1, MUX_SEL, 0x0);
	else
		prueth_mii_set(TX, 1, MUX_SEL, PRUSS_MII_RT_TXCFG_TX_MUX_SEL);

	prueth_mii_set(TX, 1, START_DELAY_MASK,
		       TX_START_DELAY << PRUSS_MII_RT_TXCFG_TX_START_DELAY_SHIFT);
	prueth_mii_set(TX, 1, CLK_DELAY_MASK,
		       TX_CLK_DELAY << PRUSS_MII_RT_TXCFG_TX_CLK_DELAY_SHIFT);

	/* Min frame length should be set to 64 to allow receive of standard
	 * Ethernet frames such as PTP, LLDP that will not have the tag/rct.
	 * Actual size written to register is size - 1 per TRM. This also
	 * includes CRC/FCS.
	 */
	pruss_regmap_update(prueth->pruss, PRUSS_SYSCON_MII_RT,
			    PRUSS_MII_RT_RX_FRMS0,
			    PRUSS_MII_RT_RX_FRMS_MIN_FRM_MASK,
			    (EMAC_MIN_PKTLEN - 1) <<
			    PRUSS_MII_RT_RX_FRMS_MIN_FRM_SHIFT);

	pruss_regmap_update(prueth->pruss, PRUSS_SYSCON_MII_RT,
			    PRUSS_MII_RT_RX_FRMS1,
			    PRUSS_MII_RT_RX_FRMS_MIN_FRM_MASK,
			    (EMAC_MIN_PKTLEN - 1) <<
			    PRUSS_MII_RT_RX_FRMS_MIN_FRM_SHIFT);

	/* For EMAC, set Max frame size to 1522 i.e size with VLAN and for
	 * HSR/PRP set it to 1528 i.e size with tag or rct. Actual size
	 * written to register is size - 1 as per TRM. Since driver
	 * support run time change of protocol, driver must overwrite
	 * the values for EMAC case where the max size is 1522.
	 */
	if (PRUETH_HAS_RED(prueth)) {
		pruss_regmap_update(prueth->pruss, PRUSS_SYSCON_MII_RT,
				    PRUSS_MII_RT_RX_FRMS0,
				    PRUSS_MII_RT_RX_FRMS_MAX_FRM_MASK,
				    (PRUETH_MAX_PKTLEN_RED - 1) <<
				    PRUSS_MII_RT_RX_FRMS_MAX_FRM_SHIFT);

		pruss_regmap_update(prueth->pruss, PRUSS_SYSCON_MII_RT,
				    PRUSS_MII_RT_RX_FRMS1,
				    PRUSS_MII_RT_RX_FRMS_MAX_FRM_MASK,
				    (PRUETH_MAX_PKTLEN_RED - 1) <<
				    PRUSS_MII_RT_RX_FRMS_MAX_FRM_SHIFT);
	} else {
		pruss_regmap_update(prueth->pruss, PRUSS_SYSCON_MII_RT,
				    PRUSS_MII_RT_RX_FRMS0,
				    PRUSS_MII_RT_RX_FRMS_MAX_FRM_MASK,
				    (PRUETH_MAX_PKTLEN_EMAC - 1) <<
				    PRUSS_MII_RT_RX_FRMS_MAX_FRM_SHIFT);

		pruss_regmap_update(prueth->pruss, PRUSS_SYSCON_MII_RT,
				    PRUSS_MII_RT_RX_FRMS1,
				    PRUSS_MII_RT_RX_FRMS_MAX_FRM_MASK,
				    (PRUETH_MAX_PKTLEN_EMAC - 1) <<
				    PRUSS_MII_RT_RX_FRMS_MAX_FRM_SHIFT);
	}
}

static void prueth_clearmem(struct prueth *prueth, enum prueth_mem region)
{
	memset_io(prueth->mem[region].va, 0, prueth->mem[region].size);
}

static void prueth_init_mem(struct prueth *prueth)
{
	/* Clear shared RAM */
	prueth_clearmem(prueth, PRUETH_MEM_SHARED_RAM);

	/* Clear OCMC RAM */
	prueth_clearmem(prueth, PRUETH_MEM_OCMC);

	/* Clear data RAMs */
	prueth_clearmem(prueth, PRUETH_MEM_DRAM0);
	prueth_clearmem(prueth, PRUETH_MEM_DRAM1);


	prueth_clearmem(prueth, PRUETH_MEM_IEP);
}

static int prueth_hostinit(struct prueth *prueth)
{
	prueth_init_mem(prueth);

	/* Initialize host queues in shared RAM */
	if (PRUETH_HAS_SWITCH(prueth))
		prueth_sw_hostconfig(prueth);
	else
		prueth_hostconfig(prueth);

	/* Configure MII_RT */
	prueth_mii_init(prueth);

	return 0;
}

static int prueth_port_enable(struct prueth *prueth, enum prueth_port port,
			      bool enable)
{
	void __iomem *port_ctrl;

	if (port == PRUETH_PORT_MII0)
		port_ctrl = (prueth->mem[PRUETH_MEM_DRAM0].va +
			     PORT_CONTROL_ADDR);
	else if (port == PRUETH_PORT_MII1)
		port_ctrl = (prueth->mem[PRUETH_MEM_DRAM1].va +
			     PORT_CONTROL_ADDR);
	else
		return -EINVAL;

	if (enable)
		writeb(0x1, port_ctrl);
	else
		writeb(0x0, port_ctrl);

	return 0;
}

static int prueth_sw_port_config(struct prueth *prueth,
				 enum prueth_port port_id)
{
	struct prueth_mmap_port_cfg_basis *pb;
	struct prueth_mmap_ocmc_cfg *oc = &prueth->mmap_ocmc_cfg;
	struct prueth_mmap_sram_cfg *s = &prueth->mmap_sram_cfg;
	unsigned int tx_context_ofs_addr, col_tx_context_ofs_addr,
		     rx_context_ofs, col_rx_context_ofs_addr,
		     queue_desc_ofs, col_queue_desc_ofs;
	void __iomem *dram, *dram_base, *dram_mac;
	struct prueth_emac *emac;
	int port_id_rx;

	pb = &prueth->mmap_port_cfg_basis[port_id];
	emac = prueth->emac[port_id - 1];
	switch (port_id) {
	case PRUETH_PORT_MII0:
		port_id_rx = PRUETH_PORT_QUEUE_MII0_RX;

		tx_context_ofs_addr     = TX_CONTEXT_P1_Q1_OFFSET_ADDR;
		col_tx_context_ofs_addr = COL_TX_CONTEXT_P1_Q1_OFFSET_ADDR;
		rx_context_ofs          = P1_Q1_RX_CONTEXT_OFFSET;
		col_rx_context_ofs_addr = COL_RX_CONTEXT_P1_OFFSET_ADDR;
		queue_desc_ofs          = pb->queue1_desc_offset;
		col_queue_desc_ofs      = pb->col_queue_desc_offset;

		/* for switch PORT MII0 mac addr is in DRAM0. */
		dram_mac = prueth->mem[PRUETH_MEM_DRAM0].va;
		break;
	case PRUETH_PORT_MII1:
		port_id_rx = PRUETH_PORT_QUEUE_MII1_RX;

		tx_context_ofs_addr     = TX_CONTEXT_P2_Q1_OFFSET_ADDR;
		col_tx_context_ofs_addr = COL_TX_CONTEXT_P2_Q1_OFFSET_ADDR;
		rx_context_ofs          = P2_Q1_RX_CONTEXT_OFFSET;
		col_rx_context_ofs_addr = COL_RX_CONTEXT_P2_OFFSET_ADDR;
		queue_desc_ofs          = pb->queue1_desc_offset;
		col_queue_desc_ofs      = pb->col_queue_desc_offset;

		/* for switch PORT MII1 mac addr is in DRAM1. */
		dram_mac = prueth->mem[PRUETH_MEM_DRAM1].va;
		break;
	default:
		netdev_err(emac->ndev, "invalid port\n");
		return -EINVAL;
	}

	/* setup mac address */
	memcpy_toio(dram_mac + PORT_MAC_ADDR, emac->mac_addr, 6);

	/* Remaining switch port configs are in DRAM1 */
	dram_base = prueth->mem[PRUETH_MEM_DRAM1].va;

	/* queue information table */
	memcpy_toio(dram_base + tx_context_ofs_addr,
		    queue_infos[port_id],
		    sizeof(queue_infos[port_id]));

	memcpy_toio(dram_base + col_tx_context_ofs_addr,
		    &col_tx_context_infos[port_id],
		    sizeof(col_tx_context_infos[port_id]));

	memcpy_toio(dram_base + rx_context_ofs,
		    queue_infos[port_id_rx],
		    sizeof(queue_infos[port_id_rx]));

	memcpy_toio(dram_base + col_rx_context_ofs_addr,
		    &col_rx_context_infos[port_id],
		    sizeof(col_rx_context_infos[port_id]));

	/* buffer descriptor offset table*/
	dram = dram_base + QUEUE_DESCRIPTOR_OFFSET_ADDR +
	       (port_id * NUM_QUEUES * sizeof(u16));
	writew(s->bd_offset[port_id][PRUETH_QUEUE1], dram);
	writew(s->bd_offset[port_id][PRUETH_QUEUE2], dram + 2);
	writew(s->bd_offset[port_id][PRUETH_QUEUE3], dram + 4);
	writew(s->bd_offset[port_id][PRUETH_QUEUE4], dram + 6);

	/* buffer offset table */
	dram = dram_base + QUEUE_OFFSET_ADDR +
	       port_id * NUM_QUEUES * sizeof(u16);
	writew(oc->buffer_offset[port_id][PRUETH_QUEUE1], dram);
	writew(oc->buffer_offset[port_id][PRUETH_QUEUE2], dram + 2);
	writew(oc->buffer_offset[port_id][PRUETH_QUEUE3], dram + 4);
	writew(oc->buffer_offset[port_id][PRUETH_QUEUE4], dram + 6);

	/* queue size lookup table */
	dram = dram_base + QUEUE_SIZE_ADDR +
	       port_id * NUM_QUEUES * sizeof(u16);
	writew(pb->queue_size[PRUETH_QUEUE1], dram);
	writew(pb->queue_size[PRUETH_QUEUE2], dram + 2);
	writew(pb->queue_size[PRUETH_QUEUE3], dram + 4);
	writew(pb->queue_size[PRUETH_QUEUE4], dram + 6);

	/* collision queue table */
	memcpy_toio(dram_base + col_queue_desc_ofs,
		    &queue_descs[port_id][PRUETH_COLQ],
		    sizeof(queue_descs[port_id][PRUETH_COLQ]));

	/* queue table */
	memcpy_toio(dram_base + queue_desc_ofs,
		    &queue_descs[port_id][0],
		    4 * sizeof(queue_descs[port_id][0]));

	return 0;
}

static int prueth_sw_emac_config(struct prueth *prueth,
				 struct prueth_emac *emac)
{
	/* PRU needs local shared RAM address for C28 */
	u32 sharedramaddr = ICSS_LOCAL_SHARED_RAM;
	/* PRU needs real global OCMC address for C30*/
	u32 ocmcaddr = (u32)prueth->mem[PRUETH_MEM_OCMC].pa;
	int ret;

	if (prueth->emac_configured & BIT(emac->port_id))
		return 0;

	ret = prueth_sw_port_config(prueth, emac->port_id);
	if (ret)
		return ret;

	if (!prueth->emac_configured) {
		/* Set in constant table C28 of PRUn to ICSS Shared memory */
		pru_rproc_set_ctable(prueth->pru0, PRU_C28, sharedramaddr);
		pru_rproc_set_ctable(prueth->pru1, PRU_C28, sharedramaddr);

		/* Set in constant table C30 of PRUn to OCMC memory */
		pru_rproc_set_ctable(prueth->pru0, PRU_C30, ocmcaddr);
		pru_rproc_set_ctable(prueth->pru1, PRU_C30, ocmcaddr);
	}
	return 0;
}

static int prueth_emac_config(struct prueth *prueth, struct prueth_emac *emac)
{
	/* PRU needs local shared RAM address for C28 */
	u32 sharedramaddr = ICSS_LOCAL_SHARED_RAM;
	/* PRU needs real global OCMC address for C30*/
	u32 ocmcaddr = (u32)prueth->mem[PRUETH_MEM_OCMC].pa;
	void __iomem *dram_base;
	void __iomem *mac_addr;
	void __iomem *dram;

	switch (emac->port_id) {
	case PRUETH_PORT_MII0:
		/* Clear data RAM */
		prueth_clearmem(prueth, PRUETH_MEM_DRAM0);

		/* PORT MII0 mac addr is in DRAM0 for switch also. */
		dram_base = prueth->mem[PRUETH_MEM_DRAM0].va;
		/* setup mac address */
		mac_addr = dram_base + PORT_MAC_ADDR;
		memcpy_toio(mac_addr, emac->mac_addr, 6);

		/* queue information table */
		dram = dram_base + TX_CONTEXT_Q1_OFFSET_ADDR;
		memcpy_toio(dram, queue_infos[emac->port_id],
			    sizeof(queue_infos[emac->port_id]));

		/* queue table */
		dram = dram_base + PORT_QUEUE_DESC_OFFSET;
		memcpy_toio(dram, &queue_descs[emac->port_id][0],
			    4 * sizeof(queue_descs[emac->port_id][0]));

		/* Set in constant table C28 of PRU0 to ICSS Shared memory */
		pru_rproc_set_ctable(prueth->pru0, PRU_C28, sharedramaddr);
		/* Set in constant table C30 of PRU0 to OCMC memory */
		pru_rproc_set_ctable(prueth->pru0, PRU_C30, ocmcaddr);
		break;
	case PRUETH_PORT_MII1:
		/* Clear data RAM */
		prueth_clearmem(prueth, PRUETH_MEM_DRAM1);

		dram_base = prueth->mem[PRUETH_MEM_DRAM1].va;

		/* setup mac address */
		mac_addr = dram_base + PORT_MAC_ADDR;
		memcpy_toio(mac_addr, emac->mac_addr, 6);

		/* queue information table */
		dram = dram_base + TX_CONTEXT_Q1_OFFSET_ADDR;
		memcpy_toio(dram, &queue_infos[emac->port_id][0],
			    4 * sizeof(queue_infos[emac->port_id][0]));

		/* queue table */
		dram = dram_base + PORT_QUEUE_DESC_OFFSET;
		memcpy_toio(dram, &queue_descs[emac->port_id][0],
			    4 * sizeof(queue_descs[emac->port_id][0]));

		/* Set in constant table C28 of PRU1 to ICSS Shared memory */
		pru_rproc_set_ctable(prueth->pru1, PRU_C28, sharedramaddr);
		/* Set in constant table C30 of PRU1 to OCMC memory */
		pru_rproc_set_ctable(prueth->pru1, PRU_C30, ocmcaddr);
		break;
	default:
		netdev_err(emac->ndev, "invalid port\n");
		return -EINVAL;
	}

	return 0;
}

/* PRU firmware default PCP to priority Queue map for ingress & egress
 *
 * At ingress to Host
 * ==================
 * byte 0 => PRU 1, PCP 0-3 => Q3
 * byte 1 => PRU 1, PCP 4-7 => Q2
 * byte 2 => PRU 0, PCP 0-3 => Q1
 * byte 3 => PRU 0, PCP 4-7 => Q0
 *
 * At egress to wire/network on PRU-0 and PRU-1
 * ============================================
 * byte 0 => Host, PCP 0-3 => Q3
 * byte 1 => Host, PCP 4-7 => Q2
 *
 * PRU-0
 * -----
 * byte 2 => PRU-1, PCP 0-3 => Q1
 * byte 3 => PRU-1, PCP 4-7 => Q0
 *
 * PRU-1
 * -----
 * byte 2 => PRU-0, PCP 0-3 => Q1
 * byte 3 => PRU-0, PCP 4-7 => Q0
 *
 * queue names below are named 1 based. i.e PRUETH_QUEUE1 is Q0,
 * PRUETH_QUEUE2 is Q1 and so forth. Current assumption in
 * the driver code is that lower the queue number higher the
 * priority of the queue.
 */
static u8 fw_pcp_default_priority_queue_map[PCP_GROUP_TO_QUEUE_MAP_SIZE] = {
	/* port 2 or PRU 1 */
	PRUETH_QUEUE4, PRUETH_QUEUE3,
	/* port 1 or PRU 0 */
	PRUETH_QUEUE2, PRUETH_QUEUE1,
};

static int prueth_hsr_prp_pcp_queue_map_config(struct prueth *prueth)
{
	void __iomem *sram  = prueth->mem[PRUETH_MEM_SHARED_RAM].va;

	memcpy_toio(sram + QUEUE_2_PCP_MAP_OFFSET,
		    &fw_pcp_default_priority_queue_map[0],
		    PCP_GROUP_TO_QUEUE_MAP_SIZE);
	return 0;
}

static int prueth_hsr_prp_host_table_init(struct prueth *prueth)
{
	void __iomem *dram0 = prueth->mem[PRUETH_MEM_DRAM0].va;
	void __iomem *dram1 = prueth->mem[PRUETH_MEM_DRAM1].va;

	memset_io(dram0 + DUPLICATE_HOST_TABLE, 0,
		  DUPLICATE_HOST_TABLE_DMEM_SIZE);

	writel(DUPLICATE_HOST_TABLE_SIZE_INIT,
	       dram1 + DUPLICATE_HOST_TABLE_SIZE);

	writel(TABLE_CHECK_RESOLUTION_10_MS,
	       dram1 + DUPLI_HOST_CHECK_RESO);

	writel(MASTER_SLAVE_BUSY_BITS_CLEAR,
	       dram1 + HOST_DUPLICATE_ARBITRATION);

	return 0;
}

static void nt_updater(struct kthread_work *work)
{
	struct prueth *prueth = container_of(work, struct prueth, nt_work);

	pop_queue_process(prueth, &prueth->nt_lock);

	node_table_update_time(prueth->nt);
	if (++prueth->rem_cnt >= 100) {
		node_table_check_and_remove(prueth->nt,
					    NODE_FORGET_TIME_60000_MS);
		prueth->rem_cnt = 0;
	}
}

static int prueth_hsr_prp_node_table_init(struct prueth *prueth)
{
	node_table_init(prueth);
	spin_lock_init(&prueth->nt_lock);
	kthread_init_work(&prueth->nt_work, nt_updater);
	prueth->nt_kworker = kthread_create_worker(0, "prueth_nt");

	return 0;
}

static int prueth_hsr_prp_port_table_init(struct prueth *prueth)
{
	void __iomem *dram1 = prueth->mem[PRUETH_MEM_DRAM1].va;

	if (PRUETH_HAS_HSR(prueth)) {
		memset_io(dram1 + DUPLICATE_PORT_TABLE_PRU0, 0,
			  DUPLICATE_PORT_TABLE_DMEM_SIZE);
		memset_io(dram1 + DUPLICATE_PORT_TABLE_PRU1, 0,
			  DUPLICATE_PORT_TABLE_DMEM_SIZE);

		writel(DUPLICATE_PORT_TABLE_SIZE_INIT,
		       dram1 + DUPLICATE_PORT_TABLE_SIZE);
	} else {
		writel(0, dram1 + DUPLICATE_PORT_TABLE_SIZE);
	}

	writel(TABLE_CHECK_RESOLUTION_10_MS, dram1 + DUPLI_PORT_CHECK_RESO);
	return 0;
}

static int prueth_hsr_prp_lre_init(struct prueth *prueth)
{
	void __iomem *sram = prueth->mem[PRUETH_MEM_SHARED_RAM].va;

	memset_io(sram + LRE_START, 0, LRE_STATS_DMEM_SIZE);

	writel(IEC62439_CONST_DUPLICATE_DISCARD,
	       sram + LRE_DUPLICATE_DISCARD);
	writel(IEC62439_CONST_TRANSPARENT_RECEPTION_REMOVE_RCT,
	       sram + LRE_TRANSPARENT_RECEPTION);
	prueth->prp_tr_mode = IEC62439_3_TR_REMOVE_RCT;
	return 0;
}

static int prueth_hsr_prp_dbg_init(struct prueth *prueth)
{
	void __iomem *dram0 = prueth->mem[PRUETH_MEM_DRAM0].va;

	memset_io(dram0 + DBG_START, 0, DEBUG_COUNTER_DMEM_SIZE);
	return 0;
}
/* TODO: Clean up, many of these init functions could return void instead */
static int prueth_config_priority_timestamping(struct prueth *prueth)
{
	void __iomem *sram = prueth->mem[PRUETH_MEM_SHARED_RAM].va;

	writeb(1, sram + PRIORITY_INTRS_STATUS_OFFSET);
	writeb(1, sram + TIMESTAMP_PKTS_STATUS_OFFSET);
	return 0;
}

static int prueth_hsr_prp_protocol_init(struct prueth *prueth)
{
	void __iomem *dram0 = prueth->mem[PRUETH_MEM_DRAM0].va;
	void __iomem *dram1 = prueth->mem[PRUETH_MEM_DRAM1].va;

	if (PRUETH_HAS_HSR(prueth))
		writew(prueth->hsr_mode, dram0 + LRE_HSR_MODE);

	writel(DUPLICATE_FORGET_TIME_400_MS, dram1 + DUPLI_FORGET_TIME);
	writel(SUP_ADDRESS_INIT_OCTETS_HIGH, dram1 + SUP_ADDR);
	writel(SUP_ADDRESS_INIT_OCTETS_LOW,  dram1 + SUP_ADDR_LOW);
	return 0;
}

/* Handles node table update (if HSR/PRP) and storm prevention */
static enum hrtimer_restart prueth_timer(struct hrtimer *timer)
{
	struct prueth *prueth = container_of(timer, struct prueth,
					     tbl_check_timer);
	void __iomem *dram;
	struct prueth_emac *emac;
	unsigned long flags;
	enum prueth_mac mac;


	hrtimer_forward_now(timer, ktime_set(0, prueth->tbl_check_period));
	if (prueth->emac_configured !=
		(BIT(PRUETH_PORT_MII0) | BIT(PRUETH_PORT_MII1)))
		return HRTIMER_RESTART;

	for (mac = PRUETH_MAC0; mac <= PRUETH_MAC1; mac++) {
		emac = prueth->emac[mac];
		if (emac->port_id == PRUETH_PORT_MII0)
			dram = prueth->mem[PRUETH_MEM_DRAM0].va;
		else
			dram = prueth->mem[PRUETH_MEM_DRAM1].va;

		if ((prueth->emac_configured & BIT(emac->port_id)) &&
		    (emac->nsp_credit & PRUETH_NSP_EN_MASK)) {
			if (!--emac->nsp_timer_count) {
				writel(emac->nsp_credit,
				       dram + STORM_PREVENTION_OFFSET);
				emac->nsp_timer_count =
				       PRUETH_DEFAULT_NSP_TIMER_COUNT;
			}
		}
	}

	if (PRUETH_HAS_RED(prueth)) {
		if (prueth->node_table_clear) {
			pru_spin_lock(prueth->nt);
			spin_lock_irqsave(&prueth->nt_lock, flags);
			node_table_init(prueth);
			spin_unlock_irqrestore(&prueth->nt_lock, flags);
			/* we don't have to release the prueth lock
			 * the note_table_init() cleares it anyway
			 */
			prueth->node_table_clear = 0;
		} else {
			prueth->tbl_check_mask &=
				~HOST_TIMER_NODE_TABLE_CLEAR_BIT;
		}

		/* schedule work here */
		kthread_queue_work(prueth->nt_kworker, &prueth->nt_work);

		dram =  prueth->mem[PRUETH_MEM_DRAM1].va;
		writel(prueth->tbl_check_mask, dram + HOST_TIMER_CHECK_FLAGS);
	}
	return HRTIMER_RESTART;
}

static int prueth_init_timer(struct prueth *prueth)
{
	if (prueth->emac_configured)
		return 0;

	hrtimer_init(&prueth->tbl_check_timer, CLOCK_MONOTONIC,
		     HRTIMER_MODE_REL);
	prueth->tbl_check_period = MS_TO_NS(PRUETH_RED_TABLE_CHECK_PERIOD_MS);
	prueth->tbl_check_timer.function = prueth_timer;
	prueth->tbl_check_mask = (HOST_TIMER_NODE_TABLE_CHECK_BIT |
				  HOST_TIMER_HOST_TABLE_CHECK_BIT);

	if (PRUETH_HAS_HSR(prueth))
		prueth->tbl_check_mask |= HOST_TIMER_PORT_TABLE_CHECK_BITS;

	return 0;
}

static int prueth_start_timer(struct prueth *prueth)
{
	void __iomem *dram1 = prueth->mem[PRUETH_MEM_DRAM1].va;

	if (prueth->emac_configured)
		return 0;

	if (PRUETH_HAS_RED(prueth))
		writel(prueth->tbl_check_mask, dram1 + HOST_TIMER_CHECK_FLAGS);

	hrtimer_start(&prueth->tbl_check_timer,
		      ktime_set(0, prueth->tbl_check_period),
		      HRTIMER_MODE_REL);
	return 0;
}

static int prueth_hsr_prp_config(struct prueth *prueth)
{
	if (prueth->emac_configured)
		return 0;

	prueth_hsr_prp_pcp_queue_map_config(prueth);
	prueth_hsr_prp_host_table_init(prueth);
	prueth_hsr_prp_node_table_init(prueth);
	prueth_hsr_prp_port_table_init(prueth);
	prueth_hsr_prp_lre_init(prueth);
	prueth_hsr_prp_dbg_init(prueth);
	prueth_hsr_prp_protocol_init(prueth);

	return 0;
}

/* update phy/port status information for firmware */
static void emac_update_phystatus(struct prueth_emac *emac)
{
	struct prueth *prueth = emac->prueth;
	enum prueth_mem region;
	u32 phy_speed, port_status = 0;

	switch (emac->port_id) {
	case PRUETH_PORT_MII0:
		region = PRUETH_MEM_DRAM0;
		break;
	case PRUETH_PORT_MII1:
		region = PRUETH_MEM_DRAM1;
		break;
	default:
		netdev_err(emac->ndev, "phy %s, invalid port\n",
			   phydev_name(emac->phydev));
		return;
	}

	phy_speed = emac->speed;
	prueth_write_reg(prueth, region, PHY_SPEED_OFFSET, phy_speed);

	if (emac->duplex == DUPLEX_HALF)
		port_status |= PORT_IS_HD_MASK;
	if (emac->link)
		port_status |= PORT_LINK_MASK;
	writeb(port_status, prueth->mem[region].va + PORT_STATUS_OFFSET);
}

/* called back by PHY layer if there is change in link state of hw port*/
static void emac_adjust_link(struct net_device *ndev)
{
	struct prueth_emac *emac = netdev_priv(ndev);
	struct phy_device *phydev = emac->phydev;
	unsigned long flags;
	bool new_state = false;

	spin_lock_irqsave(&emac->lock, flags);

	if (phydev->link) {
		/* check the mode of operation - full/half duplex */
		if (phydev->duplex != emac->duplex) {
			new_state = true;
			emac->duplex = phydev->duplex;
		}
		if (phydev->speed != emac->speed) {
			new_state = true;
			emac->speed = phydev->speed;
		}
		if (!emac->link) {
			new_state = true;
			emac->link = 1;
		}
	} else if (emac->link) {
		new_state = true;
		emac->link = 0;
		/* defaults for no link */

		/* f/w only support 10 or 100 */
		emac->speed = SPEED_100;

		/* half duplex may not be supported by f/w */
		emac->duplex = DUPLEX_FULL;
	}

	emac_update_phystatus(emac);

	if (new_state)
		phy_print_status(phydev);

	if (emac->link) {
		/* link ON */
		if (!netif_carrier_ok(ndev))
			netif_carrier_on(ndev);
		/* reactivate the transmit queue if it is stopped */
		if (netif_running(ndev) && netif_queue_stopped(ndev))
			netif_wake_queue(ndev);
	} else {
		/* link OFF */
		if (netif_carrier_ok(ndev))
			netif_carrier_off(ndev);
		if (!netif_queue_stopped(ndev))
			netif_stop_queue(ndev);
	}

	spin_unlock_irqrestore(&emac->lock, flags);
}

/**
 * emac_tx_hardirq - EMAC Tx interrupt handler
 * @irq: interrupt number
 * @dev_id: pointer to net_device
 *
 * This is called whenever a packet has finished being transmitted, this clears
 * up hardware buffer space, our only task is to re-enable the transmit queue
 * if it was previously disabled due to hardware queue being full
 *
 * Returns interrupt handled condition
 */
static irqreturn_t emac_tx_hardirq(int irq, void *dev_id)
{
	struct net_device *ndev = (struct net_device *)dev_id;

	if (unlikely(netif_queue_stopped(ndev)))
		netif_wake_queue(ndev);

	return IRQ_HANDLED;
}

static irqreturn_t emac_tx_hardirq_ptp(int irq, void *dev_id)
{
	struct net_device *ndev = (struct net_device *)dev_id;
	struct prueth_emac *emac = netdev_priv(ndev);

	if (unlikely(netif_queue_stopped(ndev)))
		netif_wake_queue(ndev);
	if (PRUETH_HAS_PTP(emac->prueth) && emac_is_ptp_tx_enabled(emac))
		prueth_queue_ptp_tx_work(emac);

	return IRQ_HANDLED;
}

static inline int emac_tx_ts_enqueue(struct prueth_emac *emac,
				     struct sk_buff *skb)
{
	unsigned long flags;
	struct prueth *prueth = emac->prueth;
	bool changed = false;
	u8 msg_t;
	struct tx_ev_cb_data *cb;

	if (PRUETH_HAS_HSR(prueth) && is_hsr_skb(skb)) {
		/* This 6-byte shift is just a trick to skip
		 * the size of a hsr tag so that the same
		 * pruptp_ts_msgtype can be re-used to parse
		 * hsr tagged skbs
		 */
		skb->data += 6;
		changed = true;
	}

	msg_t = pruptp_ts_msgtype(skb);

	if (changed)
		skb->data -= 6;

	if (msg_t > PTP_PDLY_RSP_MSG_ID) {
		netdev_err(emac->ndev, "invalid msg_t %u\n", msg_t);
		return -EINVAL;
	}

	cb = &emac->tx_ev_cb[msg_t];
	spin_lock_irqsave(&emac->ev_msg_lock, flags);
	if (cb->skb) {
		dev_consume_skb_any(cb->skb);
		pruptp_reset_tx_msg_ts(emac, msg_t);
		netdev_warn(emac->ndev,
			    "Dropped msg %u waiting for tx ts.\n", msg_t);
	}

	skb_get(skb);
	cb->skb = skb;
	cb->tmo = jiffies + msecs_to_jiffies(100);
	spin_unlock_irqrestore(&emac->ev_msg_lock, flags);

	return 0;
}

/**
 * prueth_tx_enqueue - queue a packet to firmware for transmission
 *
 * @emac: EMAC data structure
 * @skb: packet data buffer
 * @txport: which port to send MII0 or MII1
 * @queue_id: priority queue id
 */
static int prueth_tx_enqueue(struct prueth_emac *emac, struct sk_buff *skb,
			     int txport, enum prueth_queue_id queue_id)
{
	struct net_device *ndev = emac->ndev;
	struct prueth *prueth = emac->prueth;
	int pktlen;
	struct prueth_queue_desc __iomem *queue_desc;
	const struct prueth_queue_info *txqueue;
	u16 bd_rd_ptr, bd_wr_ptr, update_wr_ptr;
	int write_block, read_block, free_blocks, update_block, pkt_block_size;
	unsigned int buffer_desc_count;
	bool buffer_wrapped = false;
	void *src_addr;
	void *dst_addr;
	/* OCMC RAM is not cached and write order is not important */
	void *ocmc_ram = (__force void *)emac->prueth->mem[PRUETH_MEM_OCMC].va;
	void __iomem *dram;
	u32 wr_buf_desc;
	int ret;
	void __iomem *sram = NULL;

	switch (emac->port_id) {
	case PRUETH_PORT_MII0:
		dram = prueth->mem[PRUETH_MEM_DRAM0].va;
		break;
	case PRUETH_PORT_MII1:
		dram = prueth->mem[PRUETH_MEM_DRAM1].va;
		break;
	default:
		netdev_err(emac->ndev, "invalid port\n");
		return -EINVAL;
	}

	if (PRUETH_HAS_SWITCH(prueth)) {
		sram = prueth->mem[PRUETH_MEM_SHARED_RAM].va;
		dram = prueth->mem[PRUETH_MEM_DRAM1].va;
	}

	/* For padding don't include CRC. So use ETH_ZLEN */
	ret = skb_padto(skb, ETH_ZLEN);
	if (ret) {
		if (netif_msg_tx_err(emac) && net_ratelimit())
			netdev_err(ndev, "packet pad failed");
		return ret;
	}
	src_addr = skb->data;

	/* pad packet if needed */
	pktlen = skb->len;
	if (pktlen < ETH_ZLEN)
		pktlen = ETH_ZLEN;

	/* Get the tx queue */
	queue_desc = emac->tx_queue_descs + queue_id;
	txqueue = &queue_infos[txport][queue_id];
	buffer_desc_count = txqueue->buffer_desc_end -
			    txqueue->buffer_desc_offset;
	buffer_desc_count /= BD_SIZE;
	buffer_desc_count++;

	bd_rd_ptr = readw(&queue_desc->rd_ptr);
	bd_wr_ptr = readw(&queue_desc->wr_ptr);

	/* the PRU firmware deals mostly in pointers already
	 * offset into ram, we would like to deal in indexes
	 * within the queue we are working with for code
	 * simplicity, calculate this here
	 */
	write_block = (bd_wr_ptr - txqueue->buffer_desc_offset) / BD_SIZE;
	read_block = (bd_rd_ptr - txqueue->buffer_desc_offset) / BD_SIZE;
	if (write_block > read_block) {
		free_blocks = buffer_desc_count - write_block;
		free_blocks += read_block;
	} else if (write_block < read_block) {
		free_blocks = read_block - write_block;
	} else { /* they are all free */
		free_blocks = buffer_desc_count;
	}
	pkt_block_size = DIV_ROUND_UP(pktlen, ICSS_BLOCK_SIZE);
	if (pkt_block_size > free_blocks) { /* out of queue space */
		/* Release the queue clear busy_s bit.
		 * This has no harm even in emac case.
		 */
		return -ENOBUFS;
	}
	/* calculate end BD address post write */
	update_block = write_block + pkt_block_size;
	/* Check for wrap around */
	if (update_block >= buffer_desc_count) {
		update_block %= buffer_desc_count;
		buffer_wrapped = true;
	}

	dst_addr = ocmc_ram + txqueue->buffer_offset +
		   (write_block * ICSS_BLOCK_SIZE);

	/* Copy the data from socket buffer(DRAM) to PRU buffers(OCMC) */
	if (buffer_wrapped) { /* wrapped around buffer */
		int bytes = (buffer_desc_count - write_block) * ICSS_BLOCK_SIZE;
		int remaining;
		/* bytes is integral multiple of ICSS_BLOCK_SIZE but
		 * entire packet may have fit within the last BD
		 * if pkt_info.length is not integral multiple of
		 * ICSS_BLOCK_SIZE
		 */
		if (pktlen < bytes)
			bytes = pktlen;

		/* copy non-wrapped part */
		memcpy(dst_addr, src_addr, bytes);

		/* copy wrapped part */
		src_addr += bytes;
		remaining = pktlen - bytes;
		dst_addr = ocmc_ram + txqueue->buffer_offset;
		memcpy(dst_addr, src_addr, remaining);
	} else {
		memcpy(dst_addr, src_addr, pktlen);
	}

	/* queue the skb to wait for tx ts before it is passed
	 * to firmware
	 */
	if (skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP &&
	    PRUETH_HAS_PTP(prueth) && emac_is_ptp_tx_enabled(emac)) {
		skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
		emac_tx_ts_enqueue(emac, skb);
	}

	/* update first buffer descriptor */
	wr_buf_desc = (pktlen << PRUETH_BD_LENGTH_SHIFT) & PRUETH_BD_LENGTH_MASK;

	if (PRUETH_HAS_HSR(prueth))
		wr_buf_desc |= BIT(PRUETH_BD_HSR_FRAME_SHIFT);

	/* Set bit0 to indicate EMAC mode when using PRP firmware */
	if (PRUETH_HAS_PRP(prueth)) {
		if (emac->prp_emac_mode)
			wr_buf_desc |= PRUETH_TX_PRP_EMAC_MODE;
		else
			wr_buf_desc &= ~PRUETH_TX_PRP_EMAC_MODE;
	}

	if (PRUETH_HAS_SWITCH(prueth))
		writel(wr_buf_desc, sram + bd_wr_ptr);
	else
		writel(wr_buf_desc, dram + bd_wr_ptr);

	/* update the write pointer in this queue descriptor, the firmware
	 * polls for this change so this will signal the start of transmission
	 */
	update_wr_ptr = txqueue->buffer_desc_offset + (update_block * BD_SIZE);
	writew(update_wr_ptr, &queue_desc->wr_ptr);

	return 0;
}

static void parse_packet_info(struct prueth *prueth, u32 buffer_descriptor,
			      struct prueth_packet_info *pkt_info)
{
	/* For HSR, start_offset indicates Tag is stripped and actual
	 * data starts at an offset of 6 bytes from start of the buffer.
	 * For PRP, it just mean RCT is present in the data. i.e in
	 * this case, depending upon LRE_TRANSPARENT_RECEPTION state
	 * RCT is to be stripped or not before passing data to upper
	 * layer. Software adjust the skb->len accordingly. TODO Support for
	 * LRE_TRANSPARENT_RECEPTION set to passRCT is TBD.
	 */
	if (PRUETH_HAS_RED(prueth))
		pkt_info->start_offset = !!(buffer_descriptor &
					    PRUETH_BD_START_FLAG_MASK);
	else
		pkt_info->start_offset = false;

	pkt_info->shadow = !!(buffer_descriptor & PRUETH_BD_SHADOW_MASK);
	pkt_info->port = (buffer_descriptor & PRUETH_BD_PORT_MASK) >>
			 PRUETH_BD_PORT_SHIFT;
	pkt_info->length = (buffer_descriptor & PRUETH_BD_LENGTH_MASK) >>
			   PRUETH_BD_LENGTH_SHIFT;
	pkt_info->broadcast = !!(buffer_descriptor & PRUETH_BD_BROADCAST_MASK);
	pkt_info->error = !!(buffer_descriptor & PRUETH_BD_ERROR_MASK);
	pkt_info->sv_frame = !!(buffer_descriptor &
				PRUETH_BD_SUP_HSR_FRAME_MASK);
	pkt_info->lookup_success = !!(buffer_descriptor &
				      PRUETH_BD_LOOKUP_SUCCESS_MASK);
}

/* get packet from queue
 * negative for error
 */
static int emac_rx_packet(struct prueth_emac *emac, u16 *bd_rd_ptr,
			  struct prueth_packet_info pkt_info,
			  const struct prueth_queue_info *rxqueue)
{
	struct prueth_mmap_port_cfg_basis *pb;
	struct net_device *ndev = emac->ndev;
	struct prueth *prueth = emac->prueth;
	const struct prueth_private_data *fw_data = prueth->fw_data;
	int read_block, update_block, pkt_block_size;
	unsigned int buffer_desc_count;
	bool buffer_wrapped = false;
	struct sk_buff *skb;
	void *src_addr;
	void *dst_addr;
	void *nt_dst_addr;
	u8 macid[6];
	/* OCMC RAM is not cached and read order is not important */
	void *ocmc_ram = (__force void *)emac->prueth->mem[PRUETH_MEM_OCMC].va;
	unsigned int actual_pkt_len;
	u16 start_offset = 0, type;
	u8 offset = 0, *ptr;
	int ret;

	if (PRUETH_HAS_HSR(prueth))
		start_offset = (pkt_info.start_offset ? RED_TAG_RCT_SIZE : 0);

	/* the PRU firmware deals mostly in pointers already
	 * offset into ram, we would like to deal in indexes
	 * within the queue we are working with for code
	 * simplicity, calculate this here
	 */
	buffer_desc_count = rxqueue->buffer_desc_end -
			    rxqueue->buffer_desc_offset;
	buffer_desc_count /= BD_SIZE;
	buffer_desc_count++;
	read_block = (*bd_rd_ptr - rxqueue->buffer_desc_offset) / BD_SIZE;
	pkt_block_size = DIV_ROUND_UP(pkt_info.length, ICSS_BLOCK_SIZE);
	/* calculate end BD address post read */
	update_block = read_block + pkt_block_size;
	/* Check for wrap around */
	if (update_block >= buffer_desc_count) {
		update_block %= buffer_desc_count;
		buffer_wrapped = true;
	}

	/* calculate new pointer in ram */
	*bd_rd_ptr = rxqueue->buffer_desc_offset + (update_block * BD_SIZE);

	/* Allocate a socket buffer for this packet */
	skb = netdev_alloc_skb_ip_align(ndev, pkt_info.length);
	if (!skb) {
		if (netif_msg_rx_err(emac) && net_ratelimit())
			netdev_err(ndev, "failed rx buffer alloc\n");
		return -ENOMEM;
	}
	dst_addr = skb->data;
	nt_dst_addr = dst_addr;

	/* Get the start address of the first buffer from
	 * the read buffer description
	 */
	if (pkt_info.shadow) {
		pb = &emac->prueth->mmap_port_cfg_basis[PRUETH_PORT_HOST];
		src_addr = ocmc_ram + pb->col_buff_offset + start_offset;
	} else {
		src_addr = ocmc_ram +
			   rxqueue->buffer_offset +
			   (read_block * ICSS_BLOCK_SIZE) +
			   start_offset;
	}

	/* Pkt len w/ HSR tag removed, If applicable */
	actual_pkt_len = pkt_info.length - start_offset;

	/* Copy the data from PRU buffers(OCMC) to socket buffer(DRAM) */
	if (buffer_wrapped) { /* wrapped around buffer */
		int bytes = (buffer_desc_count - read_block) * ICSS_BLOCK_SIZE;
		int remaining;

		/* bytes is integral multiple of ICSS_BLOCK_SIZE but
		 * entire packet may have fit within the last BD
		 * if pkt_info.length is not integral multiple of
		 * ICSS_BLOCK_SIZE
		 */
		if (pkt_info.length < bytes)
			bytes = pkt_info.length;

		/* If applicable, account for the HSR tag removed */
		bytes -= start_offset;

		/* copy non-wrapped part */
		memcpy(dst_addr, src_addr, bytes);
		/* copy wrapped part */
		dst_addr += bytes;
		remaining = actual_pkt_len - bytes;
		if (pkt_info.shadow)
			src_addr += bytes;
		else
			src_addr = ocmc_ram + rxqueue->buffer_offset;
		memcpy(dst_addr, src_addr, remaining);
	} else {
		memcpy(dst_addr, src_addr, actual_pkt_len);
	}

	/* Check if VLAN tag is present since SV payload location will change
	 * based on that
	 */
	if (PRUETH_HAS_RED(prueth)) {
		ptr = nt_dst_addr + PRUETH_ETH_TYPE_OFFSET;
		type = (*ptr++) << PRUETH_ETH_TYPE_UPPER_SHIFT;
		type |= *ptr++;
		if (type == ETH_P_8021Q)
			offset = 4;
	}

	/* TODO. The check for FW_REV_V1_0 is a workaround since
	 * lookup of MAC address in Node table by this version of firmware
	 * is not reliable. Once this issue is fixed in firmware, this driver
	 * check has to be removed.
	 */
	if (PRUETH_HAS_RED(prueth) &&
	    (!pkt_info.lookup_success || fw_data->fw_rev == FW_REV_V1_0)) {
		if (PRUETH_HAS_PRP(prueth) && !emac->prp_emac_mode) {
			memcpy(macid,
			       ((pkt_info.sv_frame) ?
				nt_dst_addr + 20 + offset :
				nt_dst_addr + 6), 6);

			node_table_insert(prueth, macid, emac->port_id,
					  pkt_info.sv_frame, RED_PROTO_PRP,
					  &prueth->nt_lock);

		} else if (pkt_info.sv_frame) {
			memcpy(macid, nt_dst_addr + 20 + offset, 6);
			node_table_insert(prueth, macid, emac->port_id,
					  pkt_info.sv_frame, RED_PROTO_HSR,
					  &prueth->nt_lock);
		}
	}

	if (pkt_info.start_offset) {
		if ((PRUETH_HAS_PRP(prueth) &&
		     prueth->prp_tr_mode == IEC62439_3_TR_REMOVE_RCT) ||
		     (PRUETH_HAS_HSR(prueth)))
			pkt_info.length -= RED_TAG_RCT_SIZE;
	}

	if (!pkt_info.sv_frame) {
		skb_put(skb, pkt_info.length);

		if (PRUETH_HAS_PTP(emac->prueth)) {
			ret = pruptp_rx_timestamp(emac, skb);
			if (ret == -EAGAIN)
				/* wait for cut-thru ts */
				goto out;
		}

		/* send packet up the stack */
		skb->protocol = eth_type_trans(skb, ndev);
		netif_rx(skb);
	} else {
		dev_kfree_skb_any(skb);
	}

out:
	/* update stats */
	ndev->stats.rx_bytes += pkt_info.length;
	ndev->stats.rx_packets++;

	return 0;
}

static irqreturn_t emac_rx_thread(int irq, void *dev_id)
{
	struct net_device *ndev = (struct net_device *)dev_id;
	struct prueth_emac *emac = netdev_priv(ndev);
	struct prueth_queue_desc __iomem *queue_desc;
	const struct prueth_queue_info *rxqueue;
	struct prueth *prueth;
	u8 overflow_cnt;
	u8 status;
	u16 bd_rd_ptr, bd_wr_ptr, update_rd_ptr;
	u32 rd_buf_desc;
	void __iomem *shared_ram = emac->prueth->mem[PRUETH_MEM_SHARED_RAM].va;
	struct prueth_packet_info pkt_info;
	struct net_device_stats *ndevstats = &emac->ndev->stats;
	int i, j, ret;
	struct prueth_emac *other_emac;
	const unsigned int *prio_q_ids;
	unsigned int q_cnt;
	unsigned int emac_max_pktlen = PRUETH_MAX_PKTLEN_EMAC;

	prueth = emac->prueth;

	prio_q_ids = emac_port_rx_priority_queue_ids[emac->port_id];
	q_cnt = NUM_RX_QUEUES;

	if (PRUETH_HAS_RED(prueth))
		emac_max_pktlen = PRUETH_MAX_PKTLEN_RED;

	/* search host queues for packets */
	for (j = 0; j < q_cnt; j++) {
		i = prio_q_ids[j];
		queue_desc = emac->rx_queue_descs + i;
		rxqueue = &queue_infos[PRUETH_PORT_HOST][i];

		status = readb(&queue_desc->status);
		/* check overflow status */
		if (status & PRUETH_PACKET_DISCARD_OVFL) {
			emac->rx_overflows++;
			if (PRUETH_HAS_SWITCH(prueth)) {
				other_emac =
					prueth->emac[(emac->port_id ^ 0x3) - 1];
				other_emac->rx_overflows++;
			}
		}

		overflow_cnt = readb(&queue_desc->overflow_cnt);
		if (overflow_cnt > 0) {
			emac->ndev->stats.rx_over_errors += overflow_cnt;

			/* reset to zero */
			writeb(0, &queue_desc->overflow_cnt);
		}

		bd_rd_ptr = readw(&queue_desc->rd_ptr);
		bd_wr_ptr = readw(&queue_desc->wr_ptr);

		/* while packets are available in this queue */
		while (bd_rd_ptr != bd_wr_ptr) {
			/* get packet info from the read buffer descriptor */
			rd_buf_desc = readl(shared_ram + bd_rd_ptr);
			parse_packet_info(prueth, rd_buf_desc, &pkt_info);

			if (pkt_info.length <= 0) {
				/* a packet length of zero will cause us to
				 * never move the read pointer ahead, locking
				 * the driver, so we manually have to move it
				 * to the write pointer, discarding all
				 * remaining packets in this queue. This should
				 * never happen.
				 */
				update_rd_ptr = bd_wr_ptr;
				ndevstats->rx_length_errors++;
			} else if (pkt_info.length > emac_max_pktlen) {
				/* if the packet is too large we skip it but we
				 * still need to move the read pointer ahead
				 * and assume something is wrong with the read
				 * pointer as the firmware should be filtering
				 * these packets
				 */
				update_rd_ptr = bd_wr_ptr;
				ndevstats->rx_length_errors++;
			} else {
				update_rd_ptr = bd_rd_ptr;
				ret = emac_rx_packet(emac, &update_rd_ptr,
						     pkt_info, rxqueue);
				if (ret)
					return IRQ_HANDLED;
				emac->rx_packet_counts[i & 1]++;
			}

			/* after reading the buffer descriptor we clear it
			 * to prevent improperly moved read pointer errors
			 * from simply looking like old packets.
			 */
			writel(0, shared_ram + bd_rd_ptr);

			/* update read pointer in queue descriptor */
			writew(update_rd_ptr, &queue_desc->rd_ptr);
			bd_rd_ptr = update_rd_ptr;
		}
	}
	return IRQ_HANDLED;
}

static irqreturn_t red_emac_rx_thread(int irq, void *dev_id)
{
	struct prueth_ndev_priority *ndev_prio =
		(struct prueth_ndev_priority *)dev_id;
	struct net_device *ndev = ndev_prio->ndev;
	struct prueth_emac *emac = netdev_priv(ndev);
	struct prueth_queue_desc __iomem *queue_desc, *queue_desc_o;
	const struct prueth_queue_info *rxqueue, *rxqueue_o;
	struct prueth *prueth;
	u8 overflow_cnt, overflow_cnt_o;
	u8 status, status_o;
	u16 bd_rd_ptr, bd_wr_ptr, update_rd_ptr, bd_rd_ptr_o, bd_wr_ptr_o;
	u32 rd_buf_desc, rd_buf_desc_o;
	void __iomem *shared_ram = emac->prueth->mem[PRUETH_MEM_SHARED_RAM].va;
	struct prueth_packet_info pkt_info, pkt_info_o;
	struct net_device_stats *ndevstats = &emac->ndev->stats;
	int i, ret;
	struct prueth_emac *other_emac;
	unsigned int emac_max_pktlen = PRUETH_MAX_PKTLEN_EMAC;

	int i_o, port;
	int port0_q_empty, port1_q_empty;
	struct net_device_stats *ndevstats_o;

	struct prueth_queue_desc __iomem *queue_desc_p;
	u16 *bd_rd_ptr_p, *bd_wr_ptr_p;
	struct prueth_packet_info *pkt_info_p;
	struct net_device_stats *ndevstats_p;
	struct prueth_emac *emac_p;
	const struct prueth_queue_info *rxqueue_p;

	void *ocmc_ram = (__force void *)emac->prueth->mem[PRUETH_MEM_OCMC].va;
	int read_block, read_block_o;
	u32 pkt_ts, pkt_ts_o;
	u32 iep_wrap, iep_cmp_cfg;

	prueth = emac->prueth;

	other_emac = prueth->emac[(emac->port_id ^ 0x3) - 1];
	ndevstats_o = &other_emac->ndev->stats;

	iep_wrap = 0xFFFFFFFF;
	/* Note: possibly could move this read to happen elsewhere and store
	 * the value so we dont do it every single time here...
	 */
	iep_cmp_cfg = readl_relaxed(prueth->iep->iep_reg +
				    prueth->iep->reg_ofs.cmp_cfg_reg);
	if (iep_cmp_cfg & BIT(1))
		iep_wrap = NSEC_PER_SEC;

	if (PRUETH_HAS_RED(prueth))
		emac_max_pktlen = PRUETH_MAX_PKTLEN_RED;

	if (ndev_prio->priority == 1) {
		i = PRUETH_QUEUE2;
		i_o = PRUETH_QUEUE4;
	} else {
		i = PRUETH_QUEUE1;
		i_o = PRUETH_QUEUE3;
	}

	/* search host queues for packets */
	queue_desc = emac->rx_queue_descs + i;
	queue_desc_o = other_emac->rx_queue_descs + i_o;

	rxqueue = &queue_infos[PRUETH_PORT_HOST][i];
	rxqueue_o = &queue_infos[PRUETH_PORT_HOST][i_o];

	status = readb(&queue_desc->status);
	status_o = readb(&queue_desc_o->status);
	/* check overflow status */
	if ((status & PRUETH_PACKET_DISCARD_OVFL) ||
	    (status_o & PRUETH_PACKET_DISCARD_OVFL)) {
		emac->rx_overflows++;
		if (PRUETH_HAS_SWITCH(prueth))
			other_emac->rx_overflows++;
	}

	overflow_cnt = readb(&queue_desc->overflow_cnt);
	overflow_cnt_o = readb(&queue_desc_o->overflow_cnt);

	if (overflow_cnt > 0) {
		emac->ndev->stats.rx_over_errors += overflow_cnt;

		/* reset to zero */
		writeb(0, &queue_desc->overflow_cnt);
	}
	if (overflow_cnt_o > 0) {
		other_emac->ndev->stats.rx_over_errors += overflow_cnt_o;

		/* reset to zero */
		writeb(0, &queue_desc_o->overflow_cnt);
	}

	bd_rd_ptr = readw(&queue_desc->rd_ptr);
	bd_wr_ptr = readw(&queue_desc->wr_ptr);

	bd_rd_ptr_o = readw(&queue_desc_o->rd_ptr);
	bd_wr_ptr_o = readw(&queue_desc_o->wr_ptr);

	port0_q_empty = (bd_rd_ptr == bd_wr_ptr) ? 1 : 0;
	port1_q_empty = (bd_rd_ptr_o == bd_wr_ptr_o) ? 1 : 0;

	/* while packets are available in this queue */
	while (!port0_q_empty || !port1_q_empty) {
		/* get packet info from the read buffer descriptor */
		rd_buf_desc = readl(shared_ram + bd_rd_ptr);
		rd_buf_desc_o = readl(shared_ram + bd_rd_ptr_o);

		parse_packet_info(prueth, rd_buf_desc, &pkt_info);
		parse_packet_info(prueth, rd_buf_desc_o, &pkt_info_o);

		read_block = (bd_rd_ptr - rxqueue->buffer_desc_offset) /
			     BD_SIZE;
		read_block_o = (bd_rd_ptr_o - rxqueue_o->buffer_desc_offset) /
			       BD_SIZE;

		pkt_ts = readl(ocmc_ram + TIMESTAMP_ARRAY_OFFSET +
			       (read_block * BD_SIZE));
		pkt_ts_o = readl(ocmc_ram + TIMESTAMP_ARRAY_OFFSET +
				 (read_block_o * BD_SIZE));

		if (!port0_q_empty && !port1_q_empty) {
			/* Packets in both port queues */
			/* Calculate diff b/n timestamps and account for
			 * wraparound
			 */
			if (pkt_ts > pkt_ts_o)
				port = (pkt_ts - pkt_ts_o) > (iep_wrap / 2) ?
					0 : 1;
			else
				port = (pkt_ts_o - pkt_ts) > (iep_wrap / 2) ?
					1 : 0;

		} else if (!port0_q_empty) {
			/* Packet(s) in port0 queue only */
			port = 0;
		} else {
			/* Packet(s) in port1 queue only */
			port = 1;
		}

		/* Select correct data structures for queue/packet selected */
		if (port == 0) {
			pkt_info_p = &pkt_info;
			bd_wr_ptr_p = &bd_wr_ptr;
			bd_rd_ptr_p = &bd_rd_ptr;
			emac_p = emac;
			ndevstats_p = ndevstats;
			rxqueue_p = rxqueue;
			queue_desc_p = queue_desc;
		} else {
			pkt_info_p = &pkt_info_o;
			bd_wr_ptr_p = &bd_wr_ptr_o;
			bd_rd_ptr_p = &bd_rd_ptr_o;
			emac_p = other_emac;
			ndevstats_p = ndevstats_o;
			rxqueue_p = rxqueue_o;
			queue_desc_p = queue_desc_o;
		}

		if ((*pkt_info_p).length <= 0) {
			/* a packet length of zero will cause us to
			 * never move the read pointer ahead, locking
			 * the driver, so we manually have to move it
			 * to the write pointer, discarding all
			 * remaining packets in this queue. This should
			 * never happen.
			 */
			update_rd_ptr = *bd_wr_ptr_p;
			ndevstats_p->rx_length_errors++;
		} else if ((*pkt_info_p).length > emac_max_pktlen) {
			/* if the packet is too large we skip it but we
			 * still need to move the read pointer ahead
			 * and assume something is wrong with the read
			 * pointer as the firmware should be filtering
			 * these packets
			 */
			update_rd_ptr = *bd_wr_ptr_p;
			ndevstats_p->rx_length_errors++;
		} else {
			update_rd_ptr = *bd_rd_ptr_p;
			ret = emac_rx_packet(emac_p, &update_rd_ptr,
					     *pkt_info_p, rxqueue_p);
			if (ret)
				return IRQ_HANDLED;
			emac_p->rx_packet_counts[i & 1]++;
		}

		/* after reading the buffer descriptor we clear it
		 * to prevent improperly moved read pointer errors
		 * from simply looking like old packets.
		 */

		/* update read pointer in queue descriptor */
		if (port == 0) {
			writel(0, shared_ram + bd_rd_ptr);
			writew(update_rd_ptr, &queue_desc->rd_ptr);
			bd_rd_ptr = update_rd_ptr;
		} else {
			writel(0, shared_ram + bd_rd_ptr_o);
			writew(update_rd_ptr, &queue_desc_o->rd_ptr);
			bd_rd_ptr_o = update_rd_ptr;
		}

		port0_q_empty = (bd_rd_ptr == bd_wr_ptr) ? 1 : 0;
		port1_q_empty = (bd_rd_ptr_o == bd_wr_ptr_o) ? 1 : 0;
	}
	return IRQ_HANDLED;
}

/* get statistics maintained by the PRU firmware into @pstats */
static void emac_get_stats(struct prueth_emac *emac,
			   struct port_statistics *pstats)
{
	void __iomem *dram;

	if (emac->port_id == PRUETH_PORT_MII0)
		dram = emac->prueth->mem[PRUETH_MEM_DRAM0].va;
	else
		dram = emac->prueth->mem[PRUETH_MEM_DRAM1].va;

	memcpy_fromio(pstats, dram + STATISTICS_OFFSET, sizeof(*pstats));
}

/* set PRU firmware statistics */
static void emac_set_stats(struct prueth_emac *emac,
			   struct port_statistics *pstats)
{
	void __iomem *dram;

	if (emac->port_id == PRUETH_PORT_MII0)
		dram = emac->prueth->mem[PRUETH_MEM_DRAM0].va;
	else
		dram = emac->prueth->mem[PRUETH_MEM_DRAM1].va;

	memcpy_fromio(dram + STATISTICS_OFFSET, pstats, sizeof(*pstats));
}

static void emac_dualemac_get_stats(struct prueth_emac *emac,
				    struct emac_statistics *pstats)
{
	void __iomem *ram = (emac->port_id == PRUETH_PORT_MII0) ?
				emac->prueth->mem[PRUETH_MEM_DRAM0].va :
				emac->prueth->mem[PRUETH_MEM_DRAM1].va;

	memcpy_fromio(&pstats->vlan_dropped,
		      ram + ICSS_EMAC_FW_VLAN_FILTER_DROP_CNT_OFFSET,
		      sizeof(pstats->vlan_dropped));
	memcpy_fromio(&pstats->multicast_dropped,
		      ram + ICSS_EMAC_FW_MULTICAST_FILTER_DROP_CNT_OFFSET,
		      sizeof(pstats->multicast_dropped));
}

static void emac_dualemac_set_stats(struct prueth_emac *emac,
				    struct emac_statistics *pstats)
{
	void __iomem *ram = (emac->port_id == PRUETH_PORT_MII0) ?
				emac->prueth->mem[PRUETH_MEM_DRAM0].va :
				emac->prueth->mem[PRUETH_MEM_DRAM1].va;

	memcpy_fromio(ram + ICSS_EMAC_FW_VLAN_FILTER_DROP_CNT_OFFSET,
		      &pstats->vlan_dropped,
		      sizeof(pstats->vlan_dropped));
	memcpy_fromio(ram + ICSS_EMAC_FW_MULTICAST_FILTER_DROP_CNT_OFFSET,
		      &pstats->multicast_dropped,
		      sizeof(pstats->multicast_dropped));
}

static void emac_lre_get_stats(struct prueth_emac *emac,
			       struct lre_statistics *pstats)
{
	void __iomem *sram = emac->prueth->mem[PRUETH_MEM_SHARED_RAM].va;

	memcpy_fromio(pstats, sram + LRE_CNT_TX_A, sizeof(*pstats));
}

static void emac_lre_set_stats(struct prueth_emac *emac,
			       struct lre_statistics *pstats)
{
	void __iomem *sram = emac->prueth->mem[PRUETH_MEM_SHARED_RAM].va;

	/* These two are actually not statistics, so keep roiginal */
	pstats->duplicate_discard = readl(sram + LRE_DUPLICATE_DISCARD);
	pstats->transparent_reception = readl(sram + LRE_TRANSPARENT_RECEPTION);
	memcpy_fromio(sram + LRE_START + 4, pstats, sizeof(*pstats));
}

static int sw_emac_set_boot_pru(struct prueth_emac *emac,
				struct net_device *ndev)
{
	const struct prueth_firmwares *pru_firmwares;
	struct prueth *prueth = emac->prueth;
	const char *fw_name;
	int ret = 0;

	if (prueth->emac_configured)
		return 0;

	/* opening first intf, boot up both PRUs:
	 *   Rx is done by local PRU
	 *   Tx is done by the other PRU
	 */
	emac_lre_set_stats(emac, &prueth->lre_stats);

	/* PRU0: set firmware and boot */
	pru_firmwares = &prueth->fw_data->fw_pru[0];
	fw_name = pru_firmwares->fw_name[prueth->eth_type];
	ret = rproc_set_firmware(prueth->pru0, fw_name);
	if (ret) {
		netdev_err(ndev, "failed to set PRU0 firmware %s: %d\n",
			   fw_name, ret);
		goto out;
	}
	ret = rproc_boot(prueth->pru0);
	if (ret) {
		netdev_err(ndev, "failed to boot PRU0: %d\n", ret);
		goto out;
	}

	/* PRU1: set firmware and boot */
	pru_firmwares = &prueth->fw_data->fw_pru[1];
	fw_name = pru_firmwares->fw_name[prueth->eth_type];
	ret = rproc_set_firmware(prueth->pru1, fw_name);
	if (ret) {
		netdev_err(ndev, "failed to set PRU1 firmware %s: %d\n",
			   fw_name, ret);
		goto out;
	}
	ret = rproc_boot(prueth->pru1);
	if (ret)
		netdev_err(ndev, "failed to boot PRU1: %d\n", ret);

out:
	return ret;
}

static int emac_set_boot_pru(struct prueth_emac *emac, struct net_device *ndev)
{
	const struct prueth_firmwares *pru_firmwares;
	struct prueth *prueth = emac->prueth;
	const char *fw_name;
	int ret = 0;

	pru_firmwares = &prueth->fw_data->fw_pru[emac->port_id - 1];
	fw_name = pru_firmwares->fw_name[prueth->eth_type];

	emac_dualemac_set_stats(emac, &prueth->emac_stats);

	switch (emac->port_id) {
	case PRUETH_PORT_MII0:
		ret = rproc_set_firmware(prueth->pru0, fw_name);
		if (ret) {
			netdev_err(ndev, "failed to set PRU0 firmware %s: %d\n",
				   fw_name, ret);
			break;
		}

		ret = rproc_boot(prueth->pru0);
		if (ret)
			netdev_err(ndev, "failed to boot PRU0: %d\n", ret);

		break;
	case PRUETH_PORT_MII1:
		ret = rproc_set_firmware(prueth->pru1, fw_name);
		if (ret) {
			netdev_err(ndev, "failed to set PRU1 firmware %s: %d\n",
				   fw_name, ret);
			break;
		}

		ret = rproc_boot(prueth->pru1);
		if (ret)
			netdev_err(ndev, "failed to boot PRU1: %d\n", ret);

		break;
	default:
		/* switch mode not supported yet */
		netdev_err(ndev, "invalid port\n");
		ret = -EINVAL;
		break;
	}

	return ret;
}

/* get emac_port corresponding to eth_node name */
static int prueth_node_port(struct device_node *eth_node)
{
	if (!strcmp(eth_node->name, "ethernet-mii0"))
		return PRUETH_PORT_MII0;
	else if (!strcmp(eth_node->name, "ethernet-mii1"))
		return PRUETH_PORT_MII1;
	else
		return -EINVAL;
}

/* get MAC instance corresponding to eth_node name */
static int prueth_node_mac(struct device_node *eth_node)
{
	if (!strcmp(eth_node->name, "ethernet-mii0"))
		return PRUETH_MAC0;
	else if (!strcmp(eth_node->name, "ethernet-mii1"))
		return PRUETH_MAC1;
	else
		return -EINVAL;
}

static int emac_calculate_queue_offsets(struct prueth *prueth,
					struct device_node *eth_node,
					struct prueth_emac *emac)
{
	struct prueth_mmap_sram_cfg *s = &prueth->mmap_sram_cfg;
	struct prueth_mmap_sram_emac *emac_sram = &s->mmap_sram_emac;
	void __iomem *sram = prueth->mem[PRUETH_MEM_SHARED_RAM].va;
	void __iomem *dram0 = prueth->mem[PRUETH_MEM_DRAM0].va;
	void __iomem *dram1 = prueth->mem[PRUETH_MEM_DRAM1].va;
	struct prueth_mmap_port_cfg_basis *pb0, *pb;
	enum prueth_port port;
	int ret = 0;

	port = prueth_node_port(eth_node);

	pb0 = &prueth->mmap_port_cfg_basis[PRUETH_PORT_HOST];
	pb  = &prueth->mmap_port_cfg_basis[port];
	switch (port) {
	case PRUETH_PORT_MII0:
		if (PRUETH_HAS_SWITCH(prueth)) {
			emac->rx_queue_descs =
				dram1 + pb0->queue1_desc_offset;
			emac->tx_queue_descs =
				dram1 + pb->queue1_desc_offset;
			emac->tx_colq_descs  =
				dram1 + pb->col_queue_desc_offset;
		} else {
			emac->rx_queue_descs =
				sram + emac_sram->host_queue_desc_offset;
			emac->tx_queue_descs = dram0 + PORT_QUEUE_DESC_OFFSET;
		}
		break;
	case PRUETH_PORT_MII1:
		if (PRUETH_HAS_SWITCH(prueth)) {
			emac->rx_queue_descs =
				dram1 + pb0->queue1_desc_offset;
			emac->tx_queue_descs =
				dram1 + pb->queue1_desc_offset;
			emac->tx_colq_descs  =
				dram1 + pb->col_queue_desc_offset;
		} else {
			emac->rx_queue_descs =
				sram + emac_sram->host_queue_desc_offset;
			emac->tx_queue_descs = dram1 + PORT_QUEUE_DESC_OFFSET;
		}
		break;
	default:
		dev_err(prueth->dev, "invalid port ID\n");
		ret = -EINVAL;
	}

	return ret;
}

/* EMAC/Switch/HSR/PRP defaults.
 *
 * Change the below values only if memory map of BD and OCMC buffers
 * adjusted to expand the buffers used for Queues. Both BD and OCMC
 * buffer sizes needs to be in sync.
 */
#define PRUETH_TX_QUEUE_SIZE 97
#define PRUETH_RX_QUEUE_SIZE 194
static u16 txq_size_defaults[NUM_QUEUES] = {PRUETH_TX_QUEUE_SIZE,
					    PRUETH_TX_QUEUE_SIZE,
					    PRUETH_TX_QUEUE_SIZE,
					    PRUETH_TX_QUEUE_SIZE};
static u16 rxq_size_defaults[NUM_QUEUES] = {PRUETH_RX_QUEUE_SIZE,
					    PRUETH_RX_QUEUE_SIZE,
					    PRUETH_RX_QUEUE_SIZE,
					    PRUETH_RX_QUEUE_SIZE};
#define PRUETH_MAX_QUEUE_SIZE ((NUM_QUEUES * PRUETH_TX_QUEUE_SIZE * 2) + \
			       (NUM_QUEUES * PRUETH_RX_QUEUE_SIZE))

static void prueth_copy_queue_sizes(u16 *to_queue_size, u16 *from_queue_size)
{
	int i;

	for (i = PRUETH_QUEUE1; i <= PRUETH_QUEUE4; i++)
		to_queue_size[i] = from_queue_size[i];
}

/* Get queue sizes from DT and if not available, use default values. Return
 * true if sizes are obtained from DT. Otherwise return false.
 */
static bool prueth_of_get_queue_sizes(struct prueth *prueth,
				      struct device_node *np,
				      enum prueth_port port,
				      struct net_device *ndev)
{
	struct prueth_mmap_port_cfg_basis *pb;
	u16 queue_sizes[NUM_QUEUES];
	char *propname;
	bool updated = false;
	int ret;

	if (port == PRUETH_PORT_HOST)
		propname = "rx-queue-size";
	else
		propname = "tx-queue-size";

	pb = &prueth->mmap_port_cfg_basis[port];
	/* Even the read fails, default values will be retained.
	 * Hence don't check return value and continue to move
	 * queue sizes (default or new) to port_cfg_basis
	 */
	ret = of_property_read_u16_array(np, propname, queue_sizes,
					 NUM_QUEUES);
	if (ret) {
		/* use defaults */
		prueth_copy_queue_sizes(pb->queue_size,
					port == PRUETH_PORT_HOST ?
					rxq_size_defaults : txq_size_defaults);
	} else {
		prueth_copy_queue_sizes(pb->queue_size, queue_sizes);
		updated = true;
		dev_dbg(&ndev->dev, "Queue sizes for port %d :- %d:%d:%d:%d\n",
			port,
			queue_sizes[PRUETH_QUEUE1], queue_sizes[PRUETH_QUEUE2],
			queue_sizes[PRUETH_QUEUE3], queue_sizes[PRUETH_QUEUE4]);
	}

	return updated;
}

/* Review the queue sizes in each port and if the total is more than the limit
 * revert to default values of sizes
 */
static void prueth_sanitize_queue_sizes(struct prueth *prueth,
					struct net_device *ndev)
{
	struct prueth_mmap_port_cfg_basis *pb;
	int i, j, total_size = 0;

	/* validate the queue sizes since total can't go above a limit.
	 * Since buffer descriptor range is bound to this limit as well
	 * and there is a 1 to 1 relation between number of blocks in
	 * OCMC RAM and number of buffer descriptors. Number of buffers
	 * are decided by defaults which are based on maximum memory
	 * available. So do a sanity check if user changes the sizes
	 * through DTS update. Use defaults values to find the upper
	 * bound. Queue sizes can change as long as BDs are within the
	 * bound.
	 */
	for (i = PRUETH_PORT_HOST; i <= PRUETH_PORT_MII1; i++) {
		pb = &prueth->mmap_port_cfg_basis[i];
		for (j = PRUETH_QUEUE1; j <= PRUETH_QUEUE4; j++) {
			/* can't be zero. At least one buffer needed */
			if (!pb->queue_size[j])
				goto err;

			total_size += pb->queue_size[j];
		}
	}

	dev_warn(&ndev->dev,
		 "total_size %d. total_size_allowed %d\n",
		 total_size, PRUETH_MAX_QUEUE_SIZE);

	if (total_size <= PRUETH_MAX_QUEUE_SIZE)
		return;

	dev_warn(&ndev->dev,
		 "Invalid DT Q sizes. Revert to default..\n");

err:
	for (i = PRUETH_PORT_HOST; i <= PRUETH_PORT_MII1; i++) {
		pb = &prueth->mmap_port_cfg_basis[i];
		if (i == PRUETH_PORT_HOST)
			prueth_copy_queue_sizes(pb->queue_size,
						rxq_size_defaults);
		else
			prueth_copy_queue_sizes(pb->queue_size,
						txq_size_defaults);
	}
}

/* Get queue sizes from DT and validate. Use defaults if config is invalid */
static void prueth_configure_queue_sizes(struct prueth_emac *emac,
					 struct device_node *np,
					 struct device_node *eth_node,
					 struct prueth_emac *other_emac,
					 struct device_node *other_eth_node)
{
	struct prueth *prueth = emac->prueth;
	bool dt_updated = false;
	struct prueth_mmap_port_cfg_basis *pb;

	dt_updated = prueth_of_get_queue_sizes(prueth, np, PRUETH_PORT_HOST,
					       emac->ndev);
	dt_updated |= prueth_of_get_queue_sizes(prueth, eth_node, emac->port_id,
						emac->ndev);
	/* If other port exists, get sizes from DT */
	if (other_emac) {
		dt_updated |= prueth_of_get_queue_sizes(prueth, other_eth_node,
							other_emac->port_id,
							emac->ndev);
	/* If other port doesn't exist, init default offsets so that offsets for
	 * first port are accessed correctly
	 */
	} else {
		pb = &prueth->mmap_port_cfg_basis[other_port_id(emac->port_id)];
		prueth_copy_queue_sizes(pb->queue_size, txq_size_defaults);
	}
	if (dt_updated)
		prueth_sanitize_queue_sizes(prueth, emac->ndev);
}

static u16 port_queue_size(struct prueth *prueth, int p, int q)
{
	if (p < PRUETH_PORT_HOST || p > PRUETH_PORT_MII1 ||
	    q < PRUETH_QUEUE1    || q > PRUETH_QUEUE4)
		return 0xffff;

	return prueth->mmap_port_cfg_basis[p].queue_size[q];
}

/**
 * For both Switch and EMAC, all Px Qy BDs are in SRAM
 * Regular BD offsets depends on P0_Q1_BD_OFFSET and Q sizes.
 * Thus all can be calculated based on P0_Q1_BD_OFFSET defined and
 * Q sizes chosen.
 *
 * This recurrsive function assumes BDs for 1 port is in
 * one continuous block of mem and BDs for 2 consecutive ports
 * are in one continuous block of mem also.
 *
 * If BDs for 2 consecutive ports are not in one continuous block,
 * just modify the case where q == PRUETH_QUEUE1. But keep in mind
 * that non-continuity may have impact on fw performance.
 */
static u16 port_queue_bd_offset(struct prueth *prueth, int p, int q)
{
	if (p < PRUETH_PORT_HOST || p > PRUETH_PORT_MII1 ||
	    q < PRUETH_QUEUE1    || q > PRUETH_QUEUE4)
		return 0xffff;

	if (p == PRUETH_PORT_HOST && q == PRUETH_QUEUE1)
		return prueth->mmap_port_cfg_basis[p].queue1_bd_offset;

	/* continuous BDs between ports
	 */
	if (p > PRUETH_PORT_HOST   &&
	    p <= PRUETH_PORT_MII1  &&
	    q == PRUETH_QUEUE1)
		return port_queue_bd_offset(prueth, p - 1, PRUETH_QUEUE4) +
		       port_queue_size(prueth, p - 1, PRUETH_QUEUE4) *
		       BD_SIZE;

	/* (0 <= p <= 2) and (QUEUE1 < q <= QUEUE4)
	 * continuous BDs within 1 port
	 */
	return port_queue_bd_offset(prueth, p, q - 1) +
	       port_queue_size(prueth, p, q - 1) * BD_SIZE;
}

/**
 * For both EMAC and Switch, all Px Qy buffers are in OCMC RAM
 * Regular Q buffer offsets depends only on P0_Q1_BUFFER_OFFSET
 * and Q sizes. Thus all such offsets can be derived from the
 * P0_Q1_BUFFER_OFFSET defined and Q sizes chosen.
 *
 * For Switch, COLQ buffers are treated differently:
 * based on P0_COL_BUFFER_OFFSET defined.
 *
 * This recurrsive function assumes buffers for 1 port is in
 * one continuous block of mem and buffers for 2 consecutive ports
 * are in one continuous block of mem as well.
 *
 * If buffers for 2 consecutive ports are not in one continuous block,
 * just modify the case where q == PRUETH_QUEUE1. But keep in mind
 * that non-continuous may have impact on fw performance.
 */
static u16 port_queue_buffer_offset(struct prueth *prueth, int p, int q)
{
	if (p < PRUETH_PORT_HOST || p > PRUETH_PORT_MII1 ||
	    q < PRUETH_QUEUE1    || q > PRUETH_QUEUE4)
		return 0xffff;

	if (p == PRUETH_PORT_HOST && q == PRUETH_QUEUE1)
		return prueth->mmap_port_cfg_basis[p].queue1_buff_offset;

	if (p > PRUETH_PORT_HOST   &&
	    p <= PRUETH_PORT_MII1  &&
	    q == PRUETH_QUEUE1)
		return port_queue_buffer_offset(prueth, p - 1, PRUETH_QUEUE4) +
		       port_queue_size(prueth, p - 1, PRUETH_QUEUE4) *
		       ICSS_BLOCK_SIZE;

	/* case (0 <= p <= 2) and (QUEUE1 < q <= QUEUE4) */
	return port_queue_buffer_offset(prueth, p, q - 1) +
	       port_queue_size(prueth, p, q - 1) * ICSS_BLOCK_SIZE;
}

static void prueth_sw_mmap_port_cfg_basis_fixup(struct prueth *prueth)
{
	struct prueth_mmap_port_cfg_basis *pb, *prev_pb;
	u16 eof_48k_buffer_bd;

	/** HOST port **/
	pb = &prueth->mmap_port_cfg_basis[PRUETH_PORT_HOST];
	pb->queue1_buff_offset    = P0_Q1_BUFFER_OFFSET,
	pb->queue1_bd_offset      = P0_Q1_BD_OFFSET;
	pb->queue1_desc_offset    = P0_QUEUE_DESC_OFFSET,
	/* Collision queues */
	pb->col_buff_offset       = P0_COL_BUFFER_OFFSET,
	pb->col_queue_desc_offset = P0_COL_QUEUE_DESC_OFFSET;

	/* This calculation recurrsively depends on
	 * [PRUETH_PORT_HOST].queue1_bd_offset.
	 * So can only be done after
	 * [PRUETH_PORT_HOST].queue1_bd_offset is set
	 */
	eof_48k_buffer_bd =
		port_queue_bd_offset(prueth, PRUETH_PORT_MII1, PRUETH_QUEUE4) +
		port_queue_size(prueth, PRUETH_PORT_MII1, PRUETH_QUEUE4) *
		BD_SIZE;

	pb->col_bd_offset = eof_48k_buffer_bd;

	/** PORT_MII0 **/
	prev_pb = pb;
	pb = &prueth->mmap_port_cfg_basis[PRUETH_PORT_MII0];

	pb->queue1_buff_offset =
		port_queue_buffer_offset(prueth, PRUETH_PORT_MII0,
					 PRUETH_QUEUE1);

	pb->queue1_bd_offset =
		port_queue_bd_offset(prueth, PRUETH_PORT_MII0, PRUETH_QUEUE1);

	pb->queue1_desc_offset =
		prev_pb->queue1_desc_offset +
		NUM_QUEUES * QDESC_SIZE;

	pb->col_buff_offset =
		prev_pb->col_buff_offset +
		prev_pb->col_queue_size * ICSS_BLOCK_SIZE;

	pb->col_bd_offset =
		prev_pb->col_bd_offset +
		prev_pb->col_queue_size * BD_SIZE;

	pb->col_queue_desc_offset =
		prev_pb->col_queue_desc_offset + QDESC_SIZE;

	/** PORT_MII1 **/
	prev_pb = pb;
	pb = &prueth->mmap_port_cfg_basis[PRUETH_PORT_MII1];

	pb->queue1_buff_offset =
		port_queue_buffer_offset(prueth, PRUETH_PORT_MII1,
					 PRUETH_QUEUE1);

	pb->queue1_bd_offset =
		port_queue_bd_offset(prueth, PRUETH_PORT_MII1, PRUETH_QUEUE1);

	pb->queue1_desc_offset =
		prev_pb->queue1_desc_offset + NUM_QUEUES * QDESC_SIZE;

	pb->col_buff_offset =
		prev_pb->col_buff_offset +
		prev_pb->col_queue_size * ICSS_BLOCK_SIZE;

	pb->col_bd_offset =
		prev_pb->col_bd_offset +
		prev_pb->col_queue_size * BD_SIZE;

	pb->col_queue_desc_offset =
		prev_pb->col_queue_desc_offset + QDESC_SIZE;
}

static u16 port_queue1_desc_offset(struct prueth *prueth, int p)
{
	if (p < PRUETH_PORT_HOST || p > PRUETH_PORT_MII1)
		return 0xffff;

	return prueth->mmap_port_cfg_basis[p].queue1_desc_offset;
}

static void prueth_init_host_port_queue_info(
	struct prueth *prueth,
	struct prueth_queue_info queue_infos[][NUM_QUEUES],
	struct prueth_mmap_port_cfg_basis *basis
)
{
	int p = PRUETH_PORT_HOST, q;
	struct prueth_queue_info *qi = queue_infos[p];

	/* PRUETH_QUEUE1 = 0, PRUETH_QUEUE2 = 1, ... */
	for (q = PRUETH_QUEUE1; q < NUM_QUEUES; q++) {
		qi[q].buffer_offset =
			port_queue_buffer_offset(prueth, p, q);

		qi[q].queue_desc_offset =
			port_queue1_desc_offset(prueth, p) +
			q * QDESC_SIZE;

		qi[q].buffer_desc_offset =
			port_queue_bd_offset(prueth, p, q);

		qi[q].buffer_desc_end =
			qi[q].buffer_desc_offset +
			(port_queue_size(prueth, p, q) - 1) * BD_SIZE;
	}
}

static void prueth_init_port_tx_queue_info(
	struct prueth *prueth,
	struct prueth_queue_info queue_infos[][NUM_QUEUES],
	struct prueth_mmap_port_cfg_basis *basis,
	int p
)
{
	struct prueth_queue_info *qi = queue_infos[p];
	int q;

	if (p < PRUETH_PORT_QUEUE_MII0 || p > PRUETH_PORT_QUEUE_MII1)
		return;

	/* PRUETH_QUEUE1 = 0, PRUETH_QUEUE2 = 1, ... */
	for (q = PRUETH_QUEUE1; q < NUM_QUEUES; q++) {
		qi[q].buffer_offset =
			port_queue_buffer_offset(prueth, p, q);

		/* this is actually buffer offset end for tx ports */
		qi[q].queue_desc_offset =
			qi[q].buffer_offset +
			(port_queue_size(prueth, p, q) - 1) * ICSS_BLOCK_SIZE;

		qi[q].buffer_desc_offset =
			port_queue_bd_offset(prueth, p, q);

		qi[q].buffer_desc_end =
			qi[q].buffer_desc_offset +
			(port_queue_size(prueth, p, q) - 1) * BD_SIZE;
	}
}

static void prueth_init_port_rx_queue_info(
	struct prueth *prueth,
	struct prueth_queue_info queue_infos[][NUM_QUEUES],
	struct prueth_mmap_port_cfg_basis *basis,
	int p_rx
)
{
	struct prueth_queue_info *qi = queue_infos[p_rx];
	int basisp, q;

	if (p_rx == PRUETH_PORT_QUEUE_MII0_RX)
		basisp = PRUETH_PORT_QUEUE_MII0;
	else if (p_rx == PRUETH_PORT_QUEUE_MII1_RX)
		basisp = PRUETH_PORT_QUEUE_MII1;
	else
		return;

	/* PRUETH_QUEUE1 = 0, PRUETH_QUEUE2 = 1, ... */
	for (q = PRUETH_QUEUE1; q < NUM_QUEUES; q++) {
		qi[q].buffer_offset =
			port_queue_buffer_offset(prueth, basisp, q);

		qi[q].queue_desc_offset =
			port_queue1_desc_offset(prueth, basisp) +
			q * QDESC_SIZE;

		qi[q].buffer_desc_offset =
			port_queue_bd_offset(prueth, basisp, q);

		qi[q].buffer_desc_end =
			qi[q].buffer_desc_offset +
			(port_queue_size(prueth, basisp, q) - 1) * BD_SIZE;
	}
}

static void
prueth_init_tx_colq_info(struct prueth *prueth,
			 struct prueth_queue_info *tx_colq_infos,
			 struct prueth_mmap_port_cfg_basis *sw_basis)
{
	struct prueth_mmap_port_cfg_basis *pb;
	struct prueth_queue_info *cqi;
	int p;

	for (p = PRUETH_PORT_QUEUE_MII0; p <= PRUETH_PORT_QUEUE_MII1; p++) {
		pb = &sw_basis[p];
		cqi = &tx_colq_infos[p];

		cqi->buffer_offset      = pb->col_buff_offset;
		cqi->queue_desc_offset  = pb->col_queue_desc_offset;
		cqi->buffer_desc_offset = pb->col_bd_offset;
		cqi->buffer_desc_end    =
			pb->col_bd_offset + (pb->col_queue_size - 1) * BD_SIZE;
	}
}

static void
prueth_init_col_tx_context_info(struct prueth *prueth,
				struct prueth_col_tx_context_info *ctx_infos,
				struct prueth_mmap_port_cfg_basis *sw_basis)
{
	struct prueth_mmap_port_cfg_basis *pb;
	struct prueth_col_tx_context_info *cti;
	int p;

	for (p = PRUETH_PORT_QUEUE_MII0; p <= PRUETH_PORT_QUEUE_MII1; p++) {
		pb = &sw_basis[p];
		cti = &ctx_infos[p];

		cti->buffer_offset      = pb->col_buff_offset;
		cti->buffer_offset2     = pb->col_buff_offset;
		cti->buffer_offset_end  =
			pb->col_buff_offset +
			(pb->col_queue_size - 1) * ICSS_BLOCK_SIZE;
	}
}

static void
prueth_init_col_rx_context_info(struct prueth *prueth,
				struct prueth_col_rx_context_info *ctx_infos,
				struct prueth_mmap_port_cfg_basis *sw_basis)
{
	struct prueth_mmap_port_cfg_basis *pb;
	struct prueth_col_rx_context_info *cti;
	int p;

	for (p = PRUETH_PORT_QUEUE_HOST; p <= PRUETH_PORT_QUEUE_MII1; p++) {
		cti = &ctx_infos[p];
		pb = &sw_basis[p];

		cti->buffer_offset      = pb->col_buff_offset;
		cti->buffer_offset2     = pb->col_buff_offset;
		cti->queue_desc_offset  = pb->col_queue_desc_offset;
		cti->buffer_desc_offset = pb->col_bd_offset;
		cti->buffer_desc_end    =
			pb->col_bd_offset +
			(pb->col_queue_size - 1) * BD_SIZE;
	}
}

static void
prueth_init_queue_descs(struct prueth *prueth,
			struct prueth_queue_desc queue_descs[][NUM_QUEUES + 1],
			struct prueth_mmap_port_cfg_basis *basis)
{
	struct prueth_queue_desc *d;
	int p, q;

	for (p = PRUETH_PORT_QUEUE_HOST; p <= PRUETH_PORT_QUEUE_MII1; p++) {
		for (q = PRUETH_QUEUE1; q <= PRUETH_QUEUE4; q++) {
			d = &queue_descs[p][q];
			d->rd_ptr = port_queue_bd_offset(prueth, p, q);
			d->wr_ptr = d->rd_ptr;
		}

		/* EMAC does not have colq and this will
		 * just set the rd_ptr and wr_ptr to 0
		 */
		d = &queue_descs[p][q];
		d->rd_ptr = basis[p].col_bd_offset;
		d->wr_ptr = d->rd_ptr;
	}
}

static int prueth_sw_init_mmap_port_cfg(struct prueth *prueth)
{
	struct prueth_mmap_port_cfg_basis *b = &prueth->mmap_port_cfg_basis[0];

	prueth_init_host_port_queue_info(prueth, queue_infos, b);
	prueth_init_port_tx_queue_info(prueth, queue_infos, b,
				       PRUETH_PORT_QUEUE_MII0);
	prueth_init_port_tx_queue_info(prueth, queue_infos, b,
				       PRUETH_PORT_QUEUE_MII1);
	prueth_init_port_rx_queue_info(prueth, queue_infos, b,
				       PRUETH_PORT_QUEUE_MII0_RX);
	prueth_init_port_rx_queue_info(prueth, queue_infos, b,
				       PRUETH_PORT_QUEUE_MII1_RX);
	prueth_init_tx_colq_info(prueth, &tx_colq_infos[0], b);
	prueth_init_col_tx_context_info(prueth, &col_tx_context_infos[0], b);
	prueth_init_col_rx_context_info(prueth, &col_rx_context_infos[0], b);
	prueth_init_queue_descs(prueth, queue_descs, b);
	return 0;
}

static void prueth_emac_mmap_port_cfg_basis_fixup(struct prueth *prueth)
{
	struct prueth_mmap_port_cfg_basis *pb, *prev_pb;
	u16 eof_48k_buffer_bd;

	/** HOST port **/
	pb = &prueth->mmap_port_cfg_basis[PRUETH_PORT_HOST];
	pb->queue1_buff_offset    = P0_Q1_BUFFER_OFFSET,
	pb->queue1_bd_offset      = P0_Q1_BD_OFFSET;

	/* this calculation recurrsively depends on queue1_bd_offset,
	 * so can only be done after queue1_bd_offset is set
	 */
	eof_48k_buffer_bd =
		port_queue_bd_offset(prueth, PRUETH_PORT_MII1, PRUETH_QUEUE4) +
		port_queue_size(prueth, PRUETH_PORT_MII1, PRUETH_QUEUE4) *
		BD_SIZE;

	pb->queue1_desc_offset = eof_48k_buffer_bd +
					EMAC_P0_Q1_DESC_OFFSET_AFTER_BD;

	/** PORT_MII0 **/
	prev_pb = pb;
	pb = &prueth->mmap_port_cfg_basis[PRUETH_PORT_MII0];

	pb->queue1_buff_offset =
		port_queue_buffer_offset(prueth, PRUETH_PORT_MII0,
					 PRUETH_QUEUE1);

	pb->queue1_bd_offset =
		port_queue_bd_offset(prueth, PRUETH_PORT_MII0, PRUETH_QUEUE1);

	pb->queue1_desc_offset = PORT_QUEUE_DESC_OFFSET;

	/** PORT_MII1 **/
	prev_pb = pb;
	pb = &prueth->mmap_port_cfg_basis[PRUETH_PORT_MII1];

	pb->queue1_buff_offset =
		port_queue_buffer_offset(prueth, PRUETH_PORT_MII1,
					 PRUETH_QUEUE1);

	pb->queue1_bd_offset =
		port_queue_bd_offset(prueth, PRUETH_PORT_MII1, PRUETH_QUEUE1);

	pb->queue1_desc_offset = PORT_QUEUE_DESC_OFFSET;
}

static int prueth_emac_init_mmap_port_cfg(struct prueth *prueth)
{
	struct prueth_mmap_port_cfg_basis *b = &prueth->mmap_port_cfg_basis[0];

	prueth_init_host_port_queue_info(prueth, queue_infos, b);
	prueth_init_port_tx_queue_info(prueth, queue_infos, b,
				       PRUETH_PORT_QUEUE_MII0);
	prueth_init_port_tx_queue_info(prueth, queue_infos, b,
				       PRUETH_PORT_QUEUE_MII1);
	prueth_init_queue_descs(prueth, queue_descs, b);
	return 0;
}

static void prueth_init_mmap_sram_cfg(struct prueth *prueth)
{
	struct prueth_mmap_sram_cfg *s = &prueth->mmap_sram_cfg;
	struct prueth_mmap_sram_emac *emac;
	int p, q;
	u16 loc;

	/* SRAM common for both EMAC and SWITCH */
	for (p = PRUETH_PORT_HOST; p <= PRUETH_PORT_MII1; p++) {
		for (q = PRUETH_QUEUE1; q <= PRUETH_QUEUE4; q++)
			s->bd_offset[p][q] = port_queue_bd_offset(prueth, p, q);
	}

	/* A MARKER in SRAM */
	s->eof_48k_buffer_bd =
		s->bd_offset[PRUETH_PORT_MII1][PRUETH_QUEUE4] +
		port_queue_size(prueth, PRUETH_PORT_MII1, PRUETH_QUEUE4) *
		BD_SIZE;

	if (PRUETH_HAS_SWITCH(prueth)) {
		/* SRAM SWITCH specific */
		for (p = PRUETH_PORT_HOST; p <= PRUETH_PORT_MII1; p++) {
			s->mmap_sram_sw.col_bd_offset[p] =
				prueth->mmap_port_cfg_basis[p].col_bd_offset;
		}
		return;
	}

	/* SRAM EMAC specific */
	emac = &s->mmap_sram_emac;

	loc = s->eof_48k_buffer_bd;
	emac->icss_emac_firmware_release_1_offset = loc;

	loc += 4;
	emac->icss_emac_firmware_release_2_offset = loc;

	loc += 4;
	emac->host_q1_rx_context_offset = loc;
	loc += 8;
	emac->host_q2_rx_context_offset = loc;
	loc += 8;
	emac->host_q3_rx_context_offset = loc;
	loc += 8;
	emac->host_q4_rx_context_offset = loc;

	loc += 8;
	emac->host_queue_descriptor_offset_addr = loc;
	loc += 8;
	emac->host_queue_offset_addr = loc;
	loc += 8;
	emac->host_queue_size_addr = loc;
	loc += 16;
	emac->host_queue_desc_offset = loc;
}

static void prueth_init_mmap_ocmc_cfg(struct prueth *prueth)
{
	struct prueth_mmap_ocmc_cfg *oc = &prueth->mmap_ocmc_cfg;
	int p, q;

	for (p = PRUETH_PORT_HOST; p <= PRUETH_PORT_MII1; p++) {
		for (q = PRUETH_QUEUE1; q <= PRUETH_QUEUE4; q++) {
			oc->buffer_offset[p][q] =
				port_queue_buffer_offset(prueth, p, q);
		}
	}
}

static int prueth_init_mmap_configs(struct prueth *prueth)
{
	if (PRUETH_HAS_SWITCH(prueth)) {
		prueth_sw_mmap_port_cfg_basis_fixup(prueth);
		prueth_sw_init_mmap_port_cfg(prueth);
	} else {
		prueth_emac_mmap_port_cfg_basis_fixup(prueth);
		prueth_emac_init_mmap_port_cfg(prueth);
	}

	prueth_init_mmap_sram_cfg(prueth);
	prueth_init_mmap_ocmc_cfg(prueth);
	return 0;
}

/**
 * emac_ndo_open - EMAC device open
 * @ndev: network adapter device
 *
 * Called when system wants to start the interface.
 *
 * Returns 0 for a successful open, or appropriate error code
 */
static int emac_ndo_open(struct net_device *ndev)
{
	struct prueth_emac *emac = netdev_priv(ndev), *other_emac, *red_emac;
	struct prueth *prueth = emac->prueth;
	unsigned long flags = (IRQF_TRIGGER_HIGH | IRQF_ONESHOT);
	struct device_node *np = prueth->prueth_np, *eth_node,
			   *other_eth_node;
	enum prueth_port port_id = emac->port_id, other_port;
	int ret = 0, i, lp_int, hp_int;
	const char *lp_int_name = "eth_lp_int";
	const char *hp_int_name = "eth_hp_int";

	red_emac = prueth->emac[PRUETH_MAC0];
	eth_node = prueth->eth_node[port_id - 1];
	/* Check for sanity of feature flag */
	if (PRUETH_HAS_HSR(prueth) &&
	    !(ndev->features & NETIF_F_HW_HSR_RX_OFFLOAD)) {
		netdev_err(ndev, "Error: Turn ON HSR offload\n");
		return -EINVAL;
	}

	if (PRUETH_HAS_PRP(prueth) &&
	    !(ndev->features & NETIF_F_HW_PRP_RX_OFFLOAD)) {
		netdev_err(ndev, "Error: Turn ON PRP offload\n");
		return -EINVAL;
	}

	if ((PRUETH_IS_EMAC(prueth) || PRUETH_IS_SWITCH(prueth)) &&
	    (ndev->features & (NETIF_F_HW_PRP_RX_OFFLOAD |
	     NETIF_F_HW_HSR_RX_OFFLOAD))) {
		netdev_err(ndev, "Error: Turn OFF %s offload\n",
			   (ndev->features &
			   NETIF_F_HW_HSR_RX_OFFLOAD) ? "HSR" : "PRP");
		return -EINVAL;
	}

	if ((PRUETH_HAS_RED(prueth) && !prueth->emac_configured) &&
	    prueth->priority_ts) {
		lp_int = emac->rx_lp_irq;
		hp_int = emac->rx_hp_irq;
		prueth->hp->ndev = red_emac->ndev;
		prueth->hp->priority = 0;
		prueth->lp->ndev = red_emac->ndev;
		prueth->lp->priority = 1;

		ret = request_threaded_irq(hp_int, NULL, red_emac_rx_thread,
					   flags, hp_int_name, prueth->hp);
		ret = request_threaded_irq(lp_int, NULL, red_emac_rx_thread,
					   flags, lp_int_name, prueth->lp);
	}

	if (PRUETH_IS_EMAC(prueth) ||
	    (PRUETH_HAS_RED(prueth) && !prueth->priority_ts))
		ret = request_threaded_irq(emac->rx_irq, NULL, emac_rx_thread,
					   flags, ndev->name, ndev);

	if (ret) {
		netdev_err(ndev, "unable to request RX IRQ\n");
		return ret;
	}

	/* Currently switch firmware doesn't implement tx irq. So make it
	 * conditional to non switch case
	 */
	if (!PRUETH_HAS_SWITCH(prueth)) {
		ret = request_irq(emac->tx_irq, emac_tx_hardirq,
				  flags, ndev->name, ndev);
		if (ret) {
			netdev_err(ndev, "unable to request TX IRQ\n");
			goto free_rx_irq;
		}
	}

	if (PRUETH_HAS_PTP(prueth) && PRUETH_HAS_RED(prueth) &&
	    emac->hsrprp_ptp_tx_irq > 0) {
		ret = request_irq(emac->hsrprp_ptp_tx_irq,
				  emac_tx_hardirq_ptp, flags,
				  ndev->name, ndev);
		if (ret) {
			netdev_err(ndev, "unable to request HSRPRP PTP TX IRQ\n");
			goto free_irq;
		}
	}

	if (PRUETH_HAS_PTP(prueth) && PRUETH_IS_EMAC(prueth) &&
	    emac->emac_ptp_tx_irq > 0) {
		ret = request_irq(emac->emac_ptp_tx_irq,
				  emac_tx_hardirq_ptp, flags,
				  ndev->name, ndev);
		if (ret) {
			netdev_err(ndev, "unable to request EMAC PTP TX IRQ\n");
			goto free_hsrprp_ptp_irq;
		}
	}

	/* set h/w MAC as user might have re-configured */
	ether_addr_copy(emac->mac_addr, ndev->dev_addr);

	netif_carrier_off(ndev);

	mutex_lock(&prueth->mlock);
	/* Once the ethtype is known, init mmap cfg structs.
	 * But need to get the queue sizes first. The queue
	 * sizes are fundamental to the remaining configuration
	 * calculations.
	 */

	if (!prueth->emac_configured) {
		if (PRUETH_HAS_HSR(prueth))
			prueth->hsr_mode = MODEH;

		other_port = other_port_id(port_id);
		/* MAC instance index starts from 0. So index by port_id - 1 */
		other_emac = prueth->emac[other_port - 1];
		other_eth_node = prueth->eth_node[other_port - 1];
		prueth_configure_queue_sizes(emac, np, eth_node,
					     other_emac, other_eth_node);
		prueth_init_mmap_configs(prueth);

		emac_calculate_queue_offsets(prueth, eth_node, emac);
		if (other_emac)
			emac_calculate_queue_offsets(prueth, other_eth_node,
						     other_emac);

		ret = prueth_hostinit(prueth);
		if (ret) {
			dev_err(&ndev->dev, "hostinit failed: %d\n", ret);
			goto free_ptp_irq;
		}

		if (PRUETH_HAS_RED(prueth)) {
			prueth->mac_queue = kmalloc(sizeof(struct nt_queue_t),
						    GFP_KERNEL);
			prueth->nt = kmalloc(sizeof(*prueth->nt),
					     GFP_KERNEL);
			if (!prueth->mac_queue || !prueth->nt) {
				ret = -ENOMEM;
				goto free_ptp_irq;
			}
		}

		if (PRUETH_HAS_RED(prueth)) {
			ret = prueth_hsr_prp_debugfs_init(prueth);
			if (ret)
				goto free_ptp_irq;
		}

		if (PRUETH_HAS_PTP(prueth)) {
			if (iep_register(prueth->iep))
				dev_err(&ndev->dev, "error registering iep\n");
		} else {
			/* Currently PTP is used with PRP firmware and only
			 * on AM5xxx devices. So we reach here for non PRP
			 * firmware cases. Dual EMAC Firmware on AM3xxx devices
			 * uses IEP counter to keep track of Tx FIFO fill level
			 * since that HW capability is not available in this
			 * device. AM4xxx re-uses AM3xxx firmware. So need to
			 * have the IEP counter IEP_GLOBAL_CFG_REG initialized
			 * to 0x551 as required by the firmware on AM3xxx/4xxx
			 * devices. For other cases, IEP counter is not used
			 * in firmware and doesn't matter if it is initialized
			 * or not. So we alway initialize the register to
			 * POR value and keep it enabled to satisfy the
			 * firmware on AM3xxx/4xxx devices.
			 *
			 * TODO: Re-visit this firmware dependency when PTP
			 * is extended to Dual EMAC firmware on AM3xxx/4xxx.
			 */
			prueth_set_reg(prueth, PRUETH_MEM_IEP, 0,
				       IEP_GLOBAL_CFG_REG_MASK,
				       IEP_GLOBAL_CFG_REG_DEF_VAL);
		}

		/* Set VLAN filter table offsets */
		if (prueth->eth_type == 0) {
			prueth->fw_offsets->vlan_ctrl_byte  =
				ICSS_EMAC_FW_VLAN_FILTER_CTRL_BITMAP_OFFSET;
			prueth->fw_offsets->vlan_filter_tbl =
				ICSS_EMAC_FW_VLAN_FLTR_TBL_BASE_ADDR;

			prueth->fw_offsets->mc_ctrl_byte  =
				ICSS_EMAC_FW_MULTICAST_FILTER_CTRL_OFFSET;
			prueth->fw_offsets->mc_filter_mask =
				ICSS_EMAC_FW_MULTICAST_FILTER_MASK_OFFSET;
			prueth->fw_offsets->mc_filter_tbl =
				ICSS_EMAC_FW_MULTICAST_FILTER_TABLE;
		} else {
			prueth->fw_offsets->vlan_ctrl_byte  =
				VLAN_FLTR_CTRL_BYTE;
			prueth->fw_offsets->vlan_filter_tbl =
				VLAN_FLTR_TBL_BASE_ADDR;

			prueth->fw_offsets->mc_ctrl_byte  =
				M_MULTICAST_TABLE_SEARCH_OP_CONTROL_BIT;
			prueth->fw_offsets->mc_filter_mask =
				MULTICAST_FILTER_MASK;
			prueth->fw_offsets->mc_filter_tbl =
				MULTICAST_FILTER_TABLE;
		}
	}

	/* Init emac debugfs */
	if (PRUETH_IS_EMAC(prueth)) {
		ret = prueth_dualemac_debugfs_init(emac);
		if (ret)
			goto clean_debugfs_hsr_prp;
	}

	if (PRUETH_HAS_PTP(prueth)) {
		prueth_init_ptp_tx_work(emac);
		/* Although the cb is cleanup in ndo_stop(), it
		 * is done here also as a double pre-caution, in
		 * particular for the first ndo_open() is called,
		 * i.e., when there is no prior ndo_close() called
		 */
		for (i = 0; i <= PTP_PDLY_RSP_MSG_ID; i++) {
			dev_consume_skb_any(emac->tx_ev_cb[i].skb);
			emac->tx_ev_cb[i].skb = NULL;
			emac->tx_ev_cb[i].tmo = 0;
		}
	}

	if (PRUETH_HAS_HSR(prueth)) {
		pruptp_hsr_cut_thru_ts_work_init(emac);

		for (i = 0; i <= PTP_DLY_REQ_MSG_ID; i++) {
			dev_consume_skb_any(emac->ct_evt_cb[i].skb);
			emac->ct_evt_cb[i].skb = NULL;
			emac->ct_evt_cb[i].tmo = 0;
		}
	}

	/* reset and start PRU firmware */
	if (PRUETH_HAS_SWITCH(prueth))
		prueth_sw_emac_config(prueth, emac);
	else
		prueth_emac_config(prueth, emac);

	prueth_init_timer(prueth);

	if (PRUETH_HAS_RED(prueth)) {
		prueth_hsr_prp_config(prueth);
		if (prueth->priority_ts)
			prueth_config_priority_timestamping(prueth);
	}

	/* restore stats */
	emac_set_stats(emac, &emac->stats);

	if (PRUETH_HAS_SWITCH(prueth))
		ret = sw_emac_set_boot_pru(emac, ndev);
	else
		ret = emac_set_boot_pru(emac, ndev);

	if (ret)
		goto clean_debugfs_emac;

	/* initialized Network Storm Prevention timer count */
	emac->nsp_timer_count = PRUETH_DEFAULT_NSP_TIMER_COUNT;
	prueth_start_timer(prueth);

	/* initialize rx interrupt pacing control offsets */
	if (PRUETH_HAS_RED(prueth)) {
		prueth->emac[PRUETH_MAC0]->rx_int_pacing_offset =
			INTR_PAC_STATUS_OFFSET;
		prueth->emac[PRUETH_MAC1]->rx_int_pacing_offset =
			INTR_PAC_STATUS_OFFSET;
	} else if (emac->port_id == PRUETH_PORT_MII0) {
		emac->rx_int_pacing_offset = INTR_PAC_STATUS_OFFSET_PRU0;
	} else {
		emac->rx_int_pacing_offset = INTR_PAC_STATUS_OFFSET_PRU1;
	}

	/* Configure ecap for interrupt pacing, Don't
	 * check return value here as this returns
	 * error only if there is no ecap register address
	 * which would result in pacing disabled
	 */
	if (!prueth->emac_configured || PRUETH_IS_EMAC(prueth))
		prueth_ecap_initialization(emac,
					   DEFAULT_RX_TIMEOUT_USEC,
					   0, &emac->rx_pacing_timeout);

	prueth->emac_configured |= BIT(emac->port_id);
	mutex_unlock(&prueth->mlock);

	/* start PHY */
	phy_start(emac->phydev);

	/* enable the port */
	prueth_port_enable(prueth, emac->port_id, true);

	if (netif_msg_drv(emac))
		dev_notice(&ndev->dev, "started\n");

	return 0;

clean_debugfs_emac:
	prueth_debugfs_term(emac);
clean_debugfs_hsr_prp:
	if (PRUETH_HAS_RED(prueth))
		prueth_hsr_prp_debugfs_term(prueth);
free_ptp_irq:
	mutex_unlock(&prueth->mlock);
	if (PRUETH_HAS_PTP(prueth) && PRUETH_IS_EMAC(prueth) &&
	    emac->emac_ptp_tx_irq > 0)
		free_irq(emac->emac_ptp_tx_irq, ndev);
free_hsrprp_ptp_irq:
	if (PRUETH_HAS_PTP(prueth) && PRUETH_HAS_RED(prueth) &&
	    emac->hsrprp_ptp_tx_irq > 0)
		free_irq(emac->hsrprp_ptp_tx_irq, ndev);
free_irq:
	if (!PRUETH_HAS_SWITCH(prueth))
		free_irq(emac->tx_irq, ndev);
free_rx_irq:
	if (PRUETH_HAS_RED(prueth) && prueth->priority_ts) {
		if (!prueth->emac_configured) {
			free_irq(emac->rx_lp_irq, prueth->lp);
			free_irq(emac->rx_hp_irq, prueth->hp);
		}
	} else {
		free_irq(emac->rx_irq, ndev);
	}

	return ret;
}

static int sw_emac_pru_stop(struct prueth_emac *emac, struct net_device *ndev)
{
	struct prueth *prueth = emac->prueth;
	void __iomem *sram = prueth->mem[PRUETH_MEM_SHARED_RAM].va;

	prueth->emac_configured &= ~BIT(emac->port_id);

	/* disable ECAP timer */
	if (!prueth->emac_configured)
		writeb_relaxed(INTR_PAC_DIS_ADP_LGC_DIS,
			       sram + INTR_PAC_STATUS_OFFSET);

	/* disable and free rx irq */
	if (prueth->priority_ts) {
		if (!prueth->emac_configured) {
			disable_irq(emac->rx_lp_irq);
			disable_irq(emac->rx_hp_irq);
			free_irq(emac->rx_lp_irq, prueth->lp);
			free_irq(emac->rx_hp_irq, prueth->hp);
		}
	} else {
		disable_irq(emac->rx_irq);
		free_irq(emac->rx_irq, emac->ndev);
	}

	if (PRUETH_HAS_PTP(prueth) && emac->hsrprp_ptp_tx_irq > 0) {
		disable_irq(emac->hsrprp_ptp_tx_irq);
		free_irq(emac->hsrprp_ptp_tx_irq, emac->ndev);
		prueth_cancel_ptp_tx_work(emac);
	}

	/* another emac is still in use, don't stop the PRUs */
	if (prueth->emac_configured)
		return 0;

	prueth_hsr_prp_debugfs_term(prueth);
	rproc_shutdown(prueth->pru0);
	rproc_shutdown(prueth->pru1);
	emac_lre_get_stats(emac, &emac->prueth->lre_stats);

	if (PRUETH_HAS_RED(emac->prueth)) {
		hrtimer_cancel(&prueth->tbl_check_timer);
		prueth->tbl_check_period = 0;
		kfree(prueth->mac_queue);
		prueth->mac_queue = NULL;
		kfree(prueth->nt);
		prueth->nt = NULL;
		/* Disable VLAN filter */
		writeb(VLAN_FLTR_DIS, sram + VLAN_FLTR_CTRL_BYTE);
	}

	return 0;
}

static int emac_pru_stop(struct prueth_emac *emac, struct net_device *ndev)
{
	struct prueth *prueth = emac->prueth;
	u32 vlan_ctrl_byte = prueth->fw_offsets->vlan_ctrl_byte;
	void __iomem *ram = (emac->port_id == PRUETH_PORT_MII0) ?
				prueth->mem[PRUETH_MEM_DRAM0].va :
				prueth->mem[PRUETH_MEM_DRAM1].va;

	prueth->emac_configured &= ~BIT(emac->port_id);

	/* another emac is still in use, don't stop the PRUs */
	switch (emac->port_id) {
	case PRUETH_PORT_MII0:
		rproc_shutdown(prueth->pru0);
		break;
	case PRUETH_PORT_MII1:
		rproc_shutdown(prueth->pru1);
		break;
	default:
		/* switch mode not supported yet */
		netdev_err(ndev, "invalid port\n");
	}

	emac_dualemac_get_stats(emac, &emac->prueth->emac_stats);

	/* disable and free rx and ptp_tx/tx interrupts */
	disable_irq(emac->tx_irq);
	disable_irq(emac->rx_irq);
	disable_irq(emac->emac_ptp_tx_irq);
	free_irq(emac->tx_irq, ndev);
	free_irq(emac->rx_irq, ndev);
	free_irq(emac->emac_ptp_tx_irq, ndev);

	/* Remove debugfs directory */
	prueth_dualemac_debugfs_term(emac);

	hrtimer_cancel(&prueth->tbl_check_timer);
	/* Disable VLAN filter */
	writeb(VLAN_FLTR_DIS, ram + vlan_ctrl_byte);

	return 0;
}

/**
 * emac_ndo_stop - EMAC device stop
 * @ndev: network adapter device
 *
 * Called when system wants to stop or down the interface.
 */
static int emac_ndo_stop(struct net_device *ndev)
{
	struct prueth_emac *emac = netdev_priv(ndev);
	struct prueth *prueth = emac->prueth;
	int i;

	/* inform the upper layers. */
	netif_stop_queue(ndev);
	netif_carrier_off(ndev);

	/* stop PHY */
	phy_stop(emac->phydev);

	/* disable the mac port */
	prueth_port_enable(prueth, emac->port_id, 0);

	mutex_lock(&prueth->mlock);

	/* clean up emac ptp related */
	if (PRUETH_HAS_PTP(prueth)) {
		emac_ptp_rx_enable(emac, 0);
		emac_ptp_tx_enable(emac, 0);
		pruptp_reset_tx_ts(emac);

		for (i = 0; i <= PTP_PDLY_RSP_MSG_ID; i++) {
			dev_consume_skb_any(emac->tx_ev_cb[i].skb);
			emac->tx_ev_cb[i].skb = NULL;
			emac->tx_ev_cb[i].tmo = 0;
		}
	}

	/* clean up emac hsr cut-thru ts work */
	if (PRUETH_HAS_HSR(prueth)) {
		if (emac->ct_kworker)
			pruptp_hsr_cut_thru_ts_work_stop(emac);

		for (i = 0; i <= PTP_DLY_REQ_MSG_ID; i++) {
			dev_consume_skb_any(emac->ct_evt_cb[i].skb);
			emac->ct_evt_cb[i].skb = NULL;
			emac->ct_evt_cb[i].tmo = 0;
		}
	}

	/* stop PRU firmware */
	if (PRUETH_HAS_SWITCH(prueth))
		sw_emac_pru_stop(emac, ndev);
	else
		emac_pru_stop(emac, ndev);

	if (PRUETH_HAS_PTP(prueth) && !prueth->emac_configured)
		iep_unregister(prueth->iep);
	if (PRUETH_HAS_PTP(prueth))
		prueth_clean_ptp_tx_work();

	mutex_unlock(&prueth->mlock);

	/* save stats */
	emac_get_stats(emac, &emac->stats);

	if (netif_msg_drv(emac))
		dev_notice(&ndev->dev, "stopped\n");

	return 0;
}

static u16 prueth_get_tx_queue_id(struct prueth *prueth, struct sk_buff *skb)
{
	u16 vlan_tci, pcp;
	int err;

	err = vlan_get_tag(skb, &vlan_tci);
	if (likely(err))
		pcp = 0;
	else
		pcp = (vlan_tci & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT;
	/* For switch, we use only QUEUE4 and QUEUE3 at the egress. QUEUE2 and
	 * QUEUE1 are used for port to port traffic
	 */
	if (PRUETH_HAS_SWITCH(prueth))
		pcp >>= 1;
	return emac_pcp_tx_priority_queue_map[pcp];
}

/**
 * emac_ndo_start_xmit - EMAC Transmit function
 * @skb: SKB pointer
 * @ndev: EMAC network adapter
 *
 * Called by the system to transmit a packet  - we queue the packet in
 * EMAC hardware transmit queue
 *
 * Returns success(NETDEV_TX_OK) or error code (typically out of desc's)
 */
static int emac_ndo_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	struct prueth_emac *emac = netdev_priv(ndev);
	int ret = 0;
	u16 qid;

	if (unlikely(!emac->link)) {
		ret = -ENOLINK;
		goto fail_tx;
	}

	qid = prueth_get_tx_queue_id(emac->prueth, skb);
	if (emac->port_id == PRUETH_PORT_MII0) {
		/* packet sent on MII0 */
		ret = prueth_tx_enqueue(emac, skb, PRUETH_PORT_QUEUE_MII0,
					qid);
	} else if (emac->port_id == PRUETH_PORT_MII1) {
		/* packet sent on MII1 */
		ret = prueth_tx_enqueue(emac, skb, PRUETH_PORT_QUEUE_MII1,
					qid);
	} else {
		goto fail_tx; /* switch mode not supported yet */
	}

	if (ret) {
		if (ret != -ENOBUFS && ret != -EBUSY) {
			if (netif_msg_tx_err(emac) && net_ratelimit())
				netdev_err(ndev,
					   "packet queue failed: %d\n", ret);
			goto fail_tx;
		} else {
			return NETDEV_TX_BUSY;
		}
	}

	emac->tx_packet_counts[qid]++;
	ndev->stats.tx_packets++;
	ndev->stats.tx_bytes += skb->len;

	dev_kfree_skb_any(skb);

	return NETDEV_TX_OK;

fail_tx:
	/* error */
	ndev->stats.tx_dropped++;
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

/**
 * emac_ndo_tx_timeout - EMAC Transmit timeout function
 * @ndev: The EMAC network adapter
 *
 * Called when system detects that a skb timeout period has expired
 * potentially due to a fault in the adapter in not being able to send
 * it out on the wire.
 */
static void emac_ndo_tx_timeout(struct net_device *ndev)
{
	struct prueth_emac *emac = netdev_priv(ndev);

	if (netif_msg_tx_err(emac))
		netdev_err(ndev, "xmit timeout");

	ndev->stats.tx_errors++;

	/* TODO: can we recover or need to reboot firmware? */
}

/**
 * emac_ndo_getstats - EMAC get statistics function
 * @ndev: The EMAC network adapter
 *
 * Called when system wants to get statistics from the device.
 *
 * We return the statistics in net_device_stats structure pulled from emac
 */
static struct net_device_stats *emac_ndo_get_stats(struct net_device *ndev)
{
	struct prueth_emac *emac = netdev_priv(ndev);
	struct port_statistics pstats;
	struct net_device_stats *stats = &ndev->stats;

	emac_get_stats(emac, &pstats);
	stats->collisions = pstats.late_coll + pstats.single_coll +
			    pstats.multi_coll + pstats.excess_coll;
	stats->multicast = pstats.rx_mcast;

	return stats;
}

/**
 * emac_ndo_fix_features - function to fix up feature flag
 * @ndev: The network adapter device
 *
 * Called when update_feature() is called from the core.
 *
 * Fix up and return the feature. Here it add NETIF_F_HW_L2FW_DOFFLOAD
 * feature flag for PRP
 */
static netdev_features_t emac_ndo_fix_features(struct net_device *ndev,
					       netdev_features_t features)
{
	/* Fix up for HSR since lower layer firmware can do cut through
	 * switching and the same is to be disabled at the upper layer.
	 * This is not applicable for PRP or EMAC.
	 */
	if (features & NETIF_F_HW_HSR_RX_OFFLOAD)
		features |= NETIF_F_HW_L2FW_DOFFLOAD;
	else
		features &= ~NETIF_F_HW_L2FW_DOFFLOAD;
	return features;
}

/**
 * emac_ndo_set_features - function to set feature flag
 * @ndev: The network adapter device
 *
 * Called when ethtool -K option is invoked by user
 *
 * Change the eth_type in the prueth structure  based on hsr or prp
 * offload options from user through ethtool -K command. If the device
 * is running or if the other paired device is running, then don't accept.
 * Otherwise, set the ethernet type and offload feature flag
 *
 * Returns success if eth_type and feature flags are updated  or error
 * otherwise.
 */
static int emac_ndo_set_features(struct net_device *ndev,
				 netdev_features_t features)
{
	struct prueth_emac *emac = netdev_priv(ndev), *other_emac;
	struct prueth *prueth = emac->prueth;
	enum prueth_port other_port;
	netdev_features_t wanted = features &
		(NETIF_F_HW_HSR_RX_OFFLOAD | NETIF_F_HW_PRP_RX_OFFLOAD);
	netdev_features_t have = ndev->features &
		(NETIF_F_HW_HSR_RX_OFFLOAD | NETIF_F_HW_PRP_RX_OFFLOAD);
	bool change_request = ((wanted ^ have) != 0);

	if (netif_running(ndev) && change_request) {
		netdev_err(ndev,
			   "Can't change feature when device runs\n");
		return -EBUSY;
	}

	other_port = other_port_id(emac->port_id);
	/* MAC instance index starts from 0. So index by port_id - 1 */
	other_emac = prueth->emac[other_port - 1];
	if (other_emac && netif_running(other_emac->ndev) && change_request) {
		netdev_err(ndev,
			   "Can't change feature when other device runs\n");
		return -EBUSY;
	}

	if (features & NETIF_F_HW_HSR_RX_OFFLOAD) {
		prueth->eth_type = PRUSS_ETHTYPE_HSR;
		ndev->features = ndev->features & ~NETIF_F_HW_PRP_RX_OFFLOAD;
		ndev->features |= (NETIF_F_HW_HSR_RX_OFFLOAD |
				   NETIF_F_HW_L2FW_DOFFLOAD);

	} else if (features & NETIF_F_HW_PRP_RX_OFFLOAD) {
		prueth->eth_type = PRUSS_ETHTYPE_PRP;
		ndev->features = ndev->features & ~NETIF_F_HW_HSR_RX_OFFLOAD;
		ndev->features |= NETIF_F_HW_PRP_RX_OFFLOAD;
		ndev->features &= ~NETIF_F_HW_L2FW_DOFFLOAD;
	} else {
		prueth->eth_type = PRUSS_ETHTYPE_EMAC;
		ndev->features =
			(ndev->features & ~(NETIF_F_HW_HSR_RX_OFFLOAD |
					NETIF_F_HW_PRP_RX_OFFLOAD |
					NETIF_F_HW_L2FW_DOFFLOAD));
	}

	return 0;
}

static u8 get_hash_with_mask(u8 *mac, u8 *mask)
{
	int j;
	u8 hash;

	for (j = 0, hash = 0; j < ETHER_ADDR_LEN; j++)
		hash ^= (mac[j] & mask[j]);

	return hash;
}

static void prueth_set_rx_mode(struct prueth_emac *emac)
{
	struct prueth *prueth = emac->prueth;
	struct net_device *ndev = emac->ndev;
	void __iomem *ram;
	u32 mc_ctrl_byte = prueth->fw_offsets->mc_ctrl_byte;
	u32 mc_filter_mask = prueth->fw_offsets->mc_filter_mask;
	u32 mc_filter_tbl = prueth->fw_offsets->mc_filter_tbl;
	struct netdev_hw_addr *ha;
	u8 hash;

	if (PRUETH_IS_EMAC(prueth)) {
		ram = (emac->port_id == PRUETH_PORT_MII0) ?
				prueth->mem[PRUETH_MEM_DRAM0].va :
				prueth->mem[PRUETH_MEM_DRAM1].va;
	} else {
		ram = prueth->mem[PRUETH_MEM_DRAM1].va;
	}

	/* first copy the mask */
	memcpy_toio(ram + mc_filter_mask,
		    &emac->mc_mac_mask[0], ETH_ALEN);

	if (ndev->flags & IFF_ALLMULTI) {
		writeb(MULTICAST_FILTER_DISABLED,
		       ram + mc_ctrl_byte);
		return;
	}

	/* disable all multicast hash table entries */
	memset_io(ram + mc_filter_tbl, 0, MULTICAST_TABLE_SIZE);

	writeb(MULTICAST_FILTER_ENABLED,
	       ram + mc_ctrl_byte);

	if (netdev_mc_empty(ndev))
		return;

	netdev_for_each_mc_addr(ha, ndev) {
		hash = get_hash_with_mask(ha->addr, emac->mc_mac_mask);
		writeb(MULTICAST_FILTER_HOST_RCV_ALLOWED,
		       ram + mc_filter_tbl + hash);
	}
}

/**
 * emac_ndo_set_rx_mode - EMAC set receive mode function
 * @ndev: The EMAC network adapter
 *
 * Called when system wants to set the receive mode of the device.
 *
 */
static void emac_ndo_set_rx_mode(struct net_device *ndev)
{
	struct prueth_emac *emac = netdev_priv(ndev);
	struct prueth *prueth = emac->prueth;
	struct prueth_mmap_sram_cfg *s = &prueth->mmap_sram_cfg;
	void __iomem *sram = prueth->mem[PRUETH_MEM_SHARED_RAM].va;
	u32 reg, mask;

	if (PRUETH_HAS_RED(prueth))
		return prueth_set_rx_mode(emac);

	if (PRUETH_HAS_SWITCH(prueth)) {
		netdev_dbg(ndev,
			   "%s: promisc mode not supported for switch\n",
			   __func__);
		return;
	}

	reg = readl(sram + s->eof_48k_buffer_bd + EMAC_PROMISCUOUS_MODE_OFFSET);
	switch (emac->port_id) {
	case PRUETH_PORT_MII0:
		mask = EMAC_P1_PROMISCUOUS_BIT;
		break;
	case PRUETH_PORT_MII1:
		mask = EMAC_P2_PROMISCUOUS_BIT;
		break;
	default:
		netdev_err(ndev, "%s: invalid port\n", __func__);
		return;
	}

	if (ndev->flags & IFF_PROMISC) {
		/* Enable promiscuous mode */
		reg |= mask;
	} else {
		/* Disable promiscuous mode */
		reg &= ~mask;
		/* Enable MC filtering when promiscuous mode disabled */
		prueth_set_rx_mode(emac);
	}

	writel(reg, sram + s->eof_48k_buffer_bd + EMAC_PROMISCUOUS_MODE_OFFSET);
}

static int emac_hwtstamp_set(struct net_device *ndev, struct ifreq *ifr)
{
	struct prueth_emac *emac = netdev_priv(ndev);
	struct hwtstamp_config cfg;

	if (copy_from_user(&cfg, ifr->ifr_data, sizeof(cfg)))
		return -EFAULT;

	/* reserved for future extensions */
	if (cfg.flags)
		return -EINVAL;

	if (cfg.tx_type != HWTSTAMP_TX_OFF && cfg.tx_type != HWTSTAMP_TX_ON)
		return -ERANGE;

	switch (cfg.rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		emac_ptp_rx_enable(emac, 0);
		break;
	case HWTSTAMP_FILTER_ALL:
	case HWTSTAMP_FILTER_PTP_V1_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V1_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ:
		return -ERANGE;
	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:
		emac_ptp_rx_enable(emac, 1);
		cfg.rx_filter = HWTSTAMP_FILTER_PTP_V2_EVENT;
		break;
	default:
		return -ERANGE;
	}

	emac_ptp_tx_enable(emac, cfg.tx_type == HWTSTAMP_TX_ON);

	return copy_to_user(ifr->ifr_data, &cfg, sizeof(cfg)) ? -EFAULT : 0;
}

static int emac_hwtstamp_get(struct net_device *ndev, struct ifreq *ifr)
{
	struct prueth_emac *emac = netdev_priv(ndev);
	struct hwtstamp_config cfg;

	cfg.flags = 0;
	cfg.tx_type = emac_is_ptp_tx_enabled(emac) ?
		      HWTSTAMP_TX_ON : HWTSTAMP_TX_OFF;
	cfg.rx_filter = (emac_is_ptp_rx_enabled(emac) ?
			 HWTSTAMP_FILTER_PTP_V2_EVENT : HWTSTAMP_FILTER_NONE);

	return copy_to_user(ifr->ifr_data, &cfg, sizeof(cfg)) ? -EFAULT : 0;
}

static int emac_ndo_ioctl(struct net_device *ndev, struct ifreq *req, int cmd)
{
	struct prueth_emac *emac = netdev_priv(ndev);

	if (!netif_running(ndev))
		return -EINVAL;

	switch (cmd) {
	case SIOCSHWTSTAMP:
		if (!PRUETH_HAS_PTP(emac->prueth))
			return -ENOTSUPP;

		return emac_hwtstamp_set(ndev, req);
	case SIOCGHWTSTAMP:
		if (!PRUETH_HAS_PTP(emac->prueth))
			return -ENOTSUPP;

		return emac_hwtstamp_get(ndev, req);
	}

	return phy_mii_ioctl(emac->phydev, req, cmd);
}

static int emac_add_del_vid(struct prueth_emac *emac,
			    bool add, __be16 proto, u16 vid)
{
	struct prueth *prueth = emac->prueth;
	void __iomem *ram;
	u16 index = ((vid >> 3) & 0x1ff);
	unsigned long flags;
	u8 val;
	u32 vlan_ctrl_byte = prueth->fw_offsets->vlan_ctrl_byte;
	u32 vlan_filter_tbl = prueth->fw_offsets->vlan_filter_tbl;

	if (PRUETH_IS_EMAC(prueth)) {
		ram = (emac->port_id == PRUETH_PORT_MII0) ?
				prueth->mem[PRUETH_MEM_DRAM0].va :
				prueth->mem[PRUETH_MEM_DRAM1].va;
	} else {
		ram = prueth->mem[PRUETH_MEM_SHARED_RAM].va;
	}

	if (proto != htons(ETH_P_8021Q))
		return -EINVAL;

	if (vid >= VLAN_VID_MAX)
		return -EINVAL;

	/* VLAN filter table is 512 bytes wide. Index it using
	 * vid / 8 and then set/reset the bit using vid & 0x7
	 */
	spin_lock_irqsave(&emac->addr_lock, flags);
	/* By default enable priority tagged frames to host below by
	 * resetting bit 1 in the VLAN_FLTR_CTRL_BYTE. So vid 0 need
	 * not be added to the table.
	 */
	if (vid) {
		val = readb(ram + vlan_filter_tbl + index);
		if (add)
			val |= BIT(vid & 7);
		else
			val &= ~BIT(vid & 7);
		writeb(val, ram + vlan_filter_tbl + index);
	}

	/* Enable VLAN filter for. By default, allow priority
	 * tagged frames to be forwarded to host by enabling the
	 * corresponding control bit. However when VLAN filter is
	 * enabled, it caused SV untagged frames to be dropped as well
	 * which is undesirable. To workaround that, enable untagged
	 * frames as well to host.  By convention, 0 in control bit
	 * means forward and 1 means drop.
	 *
	 * TODO: This is still not working as desired. SV frames seem
	 * to skip VLAN filtering. When SV VLAN ID is added to filter,
	 * Host receives the untagged SV frames as well. So for now
	 * allow untagged frames to host by default and use a boot
	 * parameter to control untagged receive.
	 */
	if (prueth->fw_drop_untagged_vlan)
		writeb(VLAN_FLTR_ENA |
		       (VLAN_FLTR_UNTAG_HOST_RCV_NAL <<
			VLAN_FLTR_UNTAG_HOST_RCV_CTRL_SHIFT),
		       ram + vlan_ctrl_byte);
	else
		writeb(VLAN_FLTR_ENA, ram + vlan_ctrl_byte);
	spin_unlock_irqrestore(&emac->addr_lock, flags);

	return 0;
}

static int emac_ndo_vlan_rx_add_vid(struct net_device *dev,
				    __be16 proto, u16 vid)
{
	struct prueth_emac *emac = netdev_priv(dev);

	return emac_add_del_vid(emac, true, proto, vid);
}

static int emac_ndo_vlan_rx_kill_vid(struct net_device *dev,
				     __be16 proto, u16 vid)
{
	struct prueth_emac *emac = netdev_priv(dev);

	return emac_add_del_vid(emac, false, proto, vid);
}

static const struct net_device_ops emac_netdev_ops = {
	.ndo_open = emac_ndo_open,
	.ndo_stop = emac_ndo_stop,
	.ndo_start_xmit = emac_ndo_start_xmit,
	.ndo_set_mac_address = eth_mac_addr,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_change_mtu	= eth_change_mtu,
	.ndo_tx_timeout = emac_ndo_tx_timeout,
	.ndo_get_stats = emac_ndo_get_stats,
	.ndo_set_rx_mode = emac_ndo_set_rx_mode,
	.ndo_set_features = emac_ndo_set_features,
	.ndo_fix_features = emac_ndo_fix_features,
	.ndo_do_ioctl = emac_ndo_ioctl,
	.ndo_vlan_rx_add_vid = emac_ndo_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid = emac_ndo_vlan_rx_kill_vid,

	/* +++TODO: implement .ndo_setup_tc */
};

/**
 * emac_get_drvinfo - Get EMAC driver information
 * @ndev: The network adapter
 * @info: ethtool info structure containing name and version
 *
 * Returns EMAC driver information (name and version)
 */
static void emac_get_drvinfo(struct net_device *ndev,
			     struct ethtool_drvinfo *info)
{
	strlcpy(info->driver, PRUETH_MODULE_DESCRIPTION, sizeof(info->driver));
	strlcpy(info->version, PRUETH_MODULE_VERSION, sizeof(info->version));
}

/**
 * emac_get_settings - Get EMAC settings
 * @ndev: The network adapter
 * @ecmd: ethtool command
 *
 * Executes ethool get command
 */
static int emac_get_link_ksettings(struct net_device *ndev,
				   struct ethtool_link_ksettings *ecmd)
{
	struct prueth_emac *emac = netdev_priv(ndev);

	if (emac->phydev) {
		phy_ethtool_ksettings_get(emac->phydev, ecmd);
		return 0;
	} else {
		return -EOPNOTSUPP;
	}
}

/**
 * emac_set_settings - Set EMAC settings
 * @ndev: The EMAC network adapter
 * @ecmd: ethtool command
 *
 * Executes ethool set command
 */
static int emac_set_link_ksettings(struct net_device *ndev,
				   const struct ethtool_link_ksettings *ecmd)
{
	struct prueth_emac *emac = netdev_priv(ndev);

	if (emac->phydev)
		return phy_ethtool_ksettings_set(emac->phydev, ecmd);
	else
		return -EOPNOTSUPP;
}

#define PRUETH_STAT_OFFSET(m) offsetof(struct port_statistics, m)

static const struct {
	char string[ETH_GSTRING_LEN];
	u32 offset;
} prueth_ethtool_stats[] = {
	{"txBcast", PRUETH_STAT_OFFSET(tx_bcast)},
	{"txMcast", PRUETH_STAT_OFFSET(tx_mcast)},
	{"txUcast", PRUETH_STAT_OFFSET(tx_ucast)},
	{"txOctets", PRUETH_STAT_OFFSET(tx_octets)},
	{"rxBcast", PRUETH_STAT_OFFSET(rx_bcast)},
	{"rxMcast", PRUETH_STAT_OFFSET(rx_mcast)},
	{"rxUcast", PRUETH_STAT_OFFSET(rx_ucast)},
	{"rxOctets", PRUETH_STAT_OFFSET(rx_octets)},

	{"tx64byte", PRUETH_STAT_OFFSET(tx64byte)},
	{"tx65_127byte", PRUETH_STAT_OFFSET(tx65_127byte)},
	{"tx128_255byte", PRUETH_STAT_OFFSET(tx128_255byte)},
	{"tx256_511byte", PRUETH_STAT_OFFSET(tx256_511byte)},
	{"tx512_1023byte", PRUETH_STAT_OFFSET(tx512_1023byte)},
	{"tx1024byte", PRUETH_STAT_OFFSET(tx1024byte)},

	{"rx64byte", PRUETH_STAT_OFFSET(rx64byte)},
	{"rx65_127byte", PRUETH_STAT_OFFSET(rx65_127byte)},
	{"rx128_255byte", PRUETH_STAT_OFFSET(rx128_255byte)},
	{"rx256_511byte", PRUETH_STAT_OFFSET(rx256_511byte)},
	{"rx512_1023byte", PRUETH_STAT_OFFSET(rx512_1023byte)},
	{"rx1024byte", PRUETH_STAT_OFFSET(rx1024byte)},

	{"lateColl", PRUETH_STAT_OFFSET(late_coll)},
	{"singleColl", PRUETH_STAT_OFFSET(single_coll)},
	{"multiColl", PRUETH_STAT_OFFSET(multi_coll)},
	{"excessColl", PRUETH_STAT_OFFSET(excess_coll)},

	{"rxMisAlignmentFrames", PRUETH_STAT_OFFSET(rx_misalignment_frames)},
	{"stormPrevCounter", PRUETH_STAT_OFFSET(stormprev_counter)},
	{"macRxError", PRUETH_STAT_OFFSET(mac_rxerror)},
	{"SFDError", PRUETH_STAT_OFFSET(sfd_error)},
	{"defTx", PRUETH_STAT_OFFSET(def_tx)},
	{"macTxError", PRUETH_STAT_OFFSET(mac_txerror)},
	{"rxOverSizedFrames", PRUETH_STAT_OFFSET(rx_oversized_frames)},
	{"rxUnderSizedFrames", PRUETH_STAT_OFFSET(rx_undersized_frames)},
	{"rxCRCFrames", PRUETH_STAT_OFFSET(rx_crc_frames)},
	{"droppedPackets", PRUETH_STAT_OFFSET(dropped_packets)},

	{"txHWQOverFlow", PRUETH_STAT_OFFSET(tx_hwq_overflow)},
	{"txHWQUnderFlow", PRUETH_STAT_OFFSET(tx_hwq_underflow)},
};

#define PRUETH_LRE_STAT_OFS(m) offsetof(struct lre_statistics, m)
static const struct {
	char string[ETH_GSTRING_LEN];
	u32 offset;
} prueth_ethtool_lre_stats[] = {
	{"lreTxA", PRUETH_LRE_STAT_OFS(cnt_tx_a)},
	{"lreTxB", PRUETH_LRE_STAT_OFS(cnt_tx_b)},
	{"lreTxC", PRUETH_LRE_STAT_OFS(cnt_tx_c)},

	{"lreErrWrongLanA", PRUETH_LRE_STAT_OFS(cnt_errwronglan_a)},
	{"lreErrWrongLanB", PRUETH_LRE_STAT_OFS(cnt_errwronglan_b)},
	{"lreErrWrongLanC", PRUETH_LRE_STAT_OFS(cnt_errwronglan_c)},

	{"lreRxA", PRUETH_LRE_STAT_OFS(cnt_rx_a)},
	{"lreRxB", PRUETH_LRE_STAT_OFS(cnt_rx_b)},
	{"lreRxC", PRUETH_LRE_STAT_OFS(cnt_rx_c)},

	{"lreErrorsA", PRUETH_LRE_STAT_OFS(cnt_errors_a)},
	{"lreErrorsB", PRUETH_LRE_STAT_OFS(cnt_errors_b)},
	{"lreErrorsC", PRUETH_LRE_STAT_OFS(cnt_errors_c)},

	{"lreNodes", PRUETH_LRE_STAT_OFS(cnt_nodes)},
	{"lreProxyNodes", PRUETH_LRE_STAT_OFS(cnt_proxy_nodes)},

	{"lreUniqueRxA", PRUETH_LRE_STAT_OFS(cnt_unique_rx_a)},
	{"lreUniqueRxB", PRUETH_LRE_STAT_OFS(cnt_unique_rx_b)},
	{"lreUniqueRxC", PRUETH_LRE_STAT_OFS(cnt_unique_rx_c)},

	{"lreDuplicateRxA", PRUETH_LRE_STAT_OFS(cnt_duplicate_rx_a)},
	{"lreDuplicateRxB", PRUETH_LRE_STAT_OFS(cnt_duplicate_rx_b)},
	{"lreDuplicateRxC", PRUETH_LRE_STAT_OFS(cnt_duplicate_rx_c)},

	{"lreMultiRxA", PRUETH_LRE_STAT_OFS(cnt_multiple_rx_a)},
	{"lreMultiRxB", PRUETH_LRE_STAT_OFS(cnt_multiple_rx_b)},
	{"lreMultiRxC", PRUETH_LRE_STAT_OFS(cnt_multiple_rx_c)},

	{"lreOwnRxA", PRUETH_LRE_STAT_OFS(cnt_own_rx_a)},
	{"lreOwnRxB", PRUETH_LRE_STAT_OFS(cnt_own_rx_b)},

	{"lreDuplicateDiscard", PRUETH_LRE_STAT_OFS(duplicate_discard)},
	{"lreTransRecept", PRUETH_LRE_STAT_OFS(transparent_reception)},

	{"lreNtLookupErrA", PRUETH_LRE_STAT_OFS(node_table_lookup_error_a)},
	{"lreNtLookupErrB", PRUETH_LRE_STAT_OFS(node_table_lookup_error_b)},
	{"lreNodeTableFull", PRUETH_LRE_STAT_OFS(node_table_full)},
	{"lreMulticastDropped", PRUETH_LRE_STAT_OFS(lre_multicast_dropped)},
	{"lreVlanDropped", PRUETH_LRE_STAT_OFS(lre_vlan_dropped)},
	{"lrePaceTimerExpired", PRUETH_LRE_STAT_OFS(lre_intr_tmr_exp)},
	{"lreTotalRxA", PRUETH_LRE_STAT_OFS(lre_total_rx_a)},
	{"lreTotalRxB", PRUETH_LRE_STAT_OFS(lre_total_rx_b)},
	{"lreOverflowPru0", PRUETH_LRE_STAT_OFS(lre_overflow_pru0)},
	{"lreOverflowPru1", PRUETH_LRE_STAT_OFS(lre_overflow_pru1)},
	{"lreDDCountPru0", PRUETH_LRE_STAT_OFS(lre_cnt_dd_pru0)},
	{"lreDDCountPru1", PRUETH_LRE_STAT_OFS(lre_cnt_dd_pru1)},
	{"lreCntSupPru0", PRUETH_LRE_STAT_OFS(lre_cnt_sup_pru0)},
	{"lreCntSupPru1", PRUETH_LRE_STAT_OFS(lre_cnt_sup_pru1)},
};

#define PRUETH_EMAC_STAT_OFS(m) offsetof(struct emac_statistics, m)
static const struct {
	char string[ETH_GSTRING_LEN];
	u32 offset;
} prueth_ethtool_emac_stats[] = {
	{"emacMulticastDropped", PRUETH_EMAC_STAT_OFS(multicast_dropped)},
	{"emacVlanDropped", PRUETH_EMAC_STAT_OFS(vlan_dropped)},
};

static int emac_get_sset_count(struct net_device *ndev, int stringset)
{
	struct prueth_emac *emac = netdev_priv(ndev);
	int a_size;

	switch (stringset) {
	case ETH_SS_STATS:
		a_size = ARRAY_SIZE(prueth_ethtool_stats);

		if (PRUETH_HAS_RED(emac->prueth))
			a_size += ARRAY_SIZE(prueth_ethtool_lre_stats);
		else if (PRUETH_IS_EMAC(emac->prueth))
			a_size += ARRAY_SIZE(prueth_ethtool_emac_stats);

		return a_size;
	default:
		return -EOPNOTSUPP;
	}
}

static void emac_get_strings(struct net_device *ndev, u32 stringset, u8 *data)
{
	struct prueth_emac *emac = netdev_priv(ndev);
	u8 *p = data;
	int i;

	switch (stringset) {
	case ETH_SS_STATS:
		for (i = 0; i < ARRAY_SIZE(prueth_ethtool_stats); i++) {
			memcpy(p, prueth_ethtool_stats[i].string,
			       ETH_GSTRING_LEN);
			p += ETH_GSTRING_LEN;
		}

		if (PRUETH_HAS_RED(emac->prueth)) {
			for (i = 0; i < ARRAY_SIZE(prueth_ethtool_lre_stats);
			     i++) {
				memcpy(p, prueth_ethtool_lre_stats[i].string,
				       ETH_GSTRING_LEN);
				p += ETH_GSTRING_LEN;
			}
		} else if (PRUETH_IS_EMAC(emac->prueth)) {
			for (i = 0; i < ARRAY_SIZE(prueth_ethtool_emac_stats);
			     i++) {
				memcpy(p, prueth_ethtool_emac_stats[i].string,
				       ETH_GSTRING_LEN);
				p += ETH_GSTRING_LEN;
			}
		}
		break;
	default:
		break;
	}
}

static int emac_get_coalesce(struct net_device *ndev,
			     struct ethtool_coalesce *coal)
{
	struct prueth_emac *emac = netdev_priv(ndev);
	struct prueth *prueth = emac->prueth;
	void __iomem *sram = prueth->mem[PRUETH_MEM_SHARED_RAM].va;
	void __iomem *ecap = prueth->mem[PRUETH_MEM_ECAP].va;
	u32 val;

	if (!ecap)
		return -EOPNOTSUPP;

	val = readb_relaxed(sram + emac->rx_int_pacing_offset);
	coal->use_adaptive_rx_coalesce = (val == INTR_PAC_ENA_ADP_LGC_ENA);
	coal->rx_coalesce_usecs = emac->rx_pacing_timeout;
	return 0;
}

static int emac_set_coalesce(struct net_device *ndev,
			     struct ethtool_coalesce *coal)
{
	struct prueth_emac *emac = netdev_priv(ndev);
	struct prueth *prueth = emac->prueth;
	int ret;

	if (coal->rx_coalesce_usecs  > MAX_RX_TIMEOUT_USEC)
		return -EOPNOTSUPP;

	mutex_lock(&prueth->mlock);
	/* Start or restart the pacing timer. Also pass rx_pacing_timeout
	 * separately as it is expected to support pacing for emac firmware
	 * as well in which case, driver will have to store per emac instance
	 * timer and the same can be passed to the function here when
	 * supported
	 */
	ret = prueth_ecap_initialization(emac,
					 coal->rx_coalesce_usecs,
					 coal->use_adaptive_rx_coalesce,
					 &emac->rx_pacing_timeout);
	mutex_unlock(&prueth->mlock);

	return ret;
}

static void emac_get_ethtool_stats(struct net_device *ndev,
				   struct ethtool_stats *stats, u64 *data)
{
	struct prueth_emac *emac = netdev_priv(ndev);
	struct port_statistics pstats;
	u32 val;
	int i;
	void *ptr;
	struct lre_statistics lre_stats;
	struct emac_statistics emac_stats;
	int lre_start, emac_start;

	emac_get_stats(emac, &pstats);

	for (i = 0; i < ARRAY_SIZE(prueth_ethtool_stats); i++) {
		ptr = &pstats;
		ptr += prueth_ethtool_stats[i].offset;
		val = *(u32 *)ptr;
		data[i] = val;
	}

	if (PRUETH_HAS_RED(emac->prueth)) {
		lre_start = ARRAY_SIZE(prueth_ethtool_stats);
		emac_lre_get_stats(emac, &lre_stats);
		for (i = 0; i < ARRAY_SIZE(prueth_ethtool_lre_stats); i++) {
			ptr = &lre_stats;
			ptr += prueth_ethtool_lre_stats[i].offset;
			val = *(u32 *)ptr;
			data[lre_start + i] = val;
		}
	}
	if (PRUETH_IS_EMAC(emac->prueth)) {
		emac_dualemac_get_stats(emac, &emac_stats);
		emac_start = ARRAY_SIZE(prueth_ethtool_stats);
		for (i = 0; i < ARRAY_SIZE(prueth_ethtool_emac_stats); i++) {
			ptr = &emac_stats;
			ptr += prueth_ethtool_emac_stats[i].offset;
			val = *(u32 *)ptr;
			data[emac_start + i] = val;
		}
	}
}

/* This is a temporary HACK.
 * The ethtool set_dump API is re-used here to allow user application
 * to pass in the PTP master clock MAC ID. The PRU PRP firmware requires
 * the master clock mac ID to filter out PTP event messages received
 * from unexpected master clock. This will be removed once a more
 * satisfactory resolution is found.
 */
static int emac_set_dump(struct net_device *ndev, struct ethtool_dump *dump)
{
	struct prueth_emac *emac = netdev_priv(ndev);
	struct prueth *prueth = emac->prueth;
	void __iomem *sram = prueth->mem[PRUETH_MEM_SHARED_RAM].va;
	u8 *p;

	if (!PRUETH_HAS_PTP(prueth))
		return -ENOTSUPP;

	if (dump->version != 0xface)
		return -EOPNOTSUPP;

	p = (u8 *)&dump->flag;
	memcpy_toio(sram + SYNC_MASTER_MAC_OFFSET, p, 3);
	p = (u8 *)&dump->len;
	memcpy_toio(sram + SYNC_MASTER_MAC_OFFSET + 3, p + 1, 3);
	return 0;
}

static int emac_get_ts_info(struct net_device *ndev,
			    struct ethtool_ts_info *info)
{
	struct prueth_emac *emac = netdev_priv(ndev);
	struct prueth *prueth = emac->prueth;

	if (!PRUETH_HAS_PTP(prueth)) {
		info->so_timestamping =
			SOF_TIMESTAMPING_TX_SOFTWARE |
			SOF_TIMESTAMPING_RX_SOFTWARE |
			SOF_TIMESTAMPING_SOFTWARE;
		info->phc_index = -1;
		info->tx_types = 0;
		info->rx_filters = 0;
		return 0;
	}

	info->so_timestamping =
		SOF_TIMESTAMPING_TX_HARDWARE |
		SOF_TIMESTAMPING_TX_SOFTWARE |
		SOF_TIMESTAMPING_RX_HARDWARE |
		SOF_TIMESTAMPING_RX_SOFTWARE |
		SOF_TIMESTAMPING_SOFTWARE |
		SOF_TIMESTAMPING_RAW_HARDWARE;
	info->phc_index = prueth->iep->phc_index;
	info->tx_types =
		(1 << HWTSTAMP_TX_OFF) |
		(1 << HWTSTAMP_TX_ON);
	info->rx_filters =
		(1 << HWTSTAMP_FILTER_NONE) |
		(1 << HWTSTAMP_FILTER_PTP_V2_EVENT);
	return 0;
}

/* Ethtool support for EMAC adapter */
static const struct ethtool_ops emac_ethtool_ops = {
	.get_drvinfo = emac_get_drvinfo,
	.get_link_ksettings = emac_get_link_ksettings,
	.set_link_ksettings = emac_set_link_ksettings,
	.set_dump = emac_set_dump,
	.get_link = ethtool_op_get_link,
	.get_ts_info = emac_get_ts_info,
	.get_sset_count = emac_get_sset_count,
	.get_strings = emac_get_strings,
	.get_ethtool_stats = emac_get_ethtool_stats,
	.get_coalesce = emac_get_coalesce,
	.set_coalesce = emac_set_coalesce,
};

static int emac_lredev_attr_get(struct net_device *ndev,
				struct lredev_attr *attr)
{
	struct prueth_emac *emac = netdev_priv(ndev);
	struct prueth *prueth = emac->prueth;
	void __iomem *sram = prueth->mem[PRUETH_MEM_SHARED_RAM].va;
	void __iomem *dram0 = prueth->mem[PRUETH_MEM_DRAM0].va;
	void __iomem *dram1 = prueth->mem[PRUETH_MEM_DRAM1].va;
	int ret = 0;

	netdev_dbg(ndev, "%d:%s, id %d\n", __LINE__, __func__, attr->id);

	switch (attr->id) {
	case LREDEV_ATTR_ID_HSR_MODE:
		if (!PRUETH_HAS_HSR(prueth))
			return -EPERM;
		attr->mode = readl(dram0 + LRE_HSR_MODE);
		break;
	case LREDEV_ATTR_ID_DD_MODE:
		attr->dd_mode = readl(sram + LRE_DUPLICATE_DISCARD);
		break;
	case LREDEV_ATTR_ID_PRP_TR:
		if (!PRUETH_HAS_PRP(prueth))
			return -EINVAL;
		attr->tr_mode = prueth->prp_tr_mode;
		break;
	case LREDEV_ATTR_ID_DLRMT:
		attr->dl_reside_max_time =
			readl(dram1 + DUPLI_FORGET_TIME) * 10;
		break;
	case LREDEV_ATTR_ID_CLEAR_NT:
		attr->clear_nt_cmd = prueth->node_table_clear_last_cmd;
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int emac_lredev_attr_set(struct net_device *ndev,
				struct lredev_attr *attr)
{
	struct prueth_emac *emac = netdev_priv(ndev);
	struct prueth *prueth = emac->prueth;
	void __iomem *sram = prueth->mem[PRUETH_MEM_SHARED_RAM].va;
	void __iomem *dram0 = prueth->mem[PRUETH_MEM_DRAM0].va;
	void __iomem *dram1 = prueth->mem[PRUETH_MEM_DRAM1].va;
	int ret = 0;

	netdev_dbg(ndev, "%d:%s, id = %d\n", __LINE__, __func__, attr->id);

	switch (attr->id) {
	case LREDEV_ATTR_ID_HSR_MODE:
		if (!PRUETH_HAS_HSR(prueth))
			return -EPERM;
		prueth->hsr_mode = attr->mode;
		writel(prueth->hsr_mode, dram0 + LRE_HSR_MODE);
		break;
	case LREDEV_ATTR_ID_DD_MODE:
		writel(attr->dd_mode, sram + LRE_DUPLICATE_DISCARD);
		break;
	case LREDEV_ATTR_ID_PRP_TR:
		if (!PRUETH_HAS_PRP(prueth))
			return -EINVAL;
		prueth->prp_tr_mode = attr->tr_mode;
		break;
	case LREDEV_ATTR_ID_DLRMT:
		/* input is in milli seconds. Firmware expects in unit
		 * of 10 msec
		 */
		writel((attr->dl_reside_max_time / 10),
		       dram1 + DUPLI_FORGET_TIME);
		break;
	case LREDEV_ATTR_ID_CLEAR_NT:
		/* need to return last cmd received for corresponding
		 * get command. So save it
		 */
		prueth->node_table_clear_last_cmd = attr->clear_nt_cmd;
		if (attr->clear_nt_cmd == IEC62439_3_CLEAR_NT)
			prueth->node_table_clear = 1;
		else
			prueth->node_table_clear = 0;
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int emac_lredev_update_node_entry(struct node_tbl_t *node,
					 struct lre_node_table_entry table[],
					 int j)
{
	u8 val, is_hsr, updated = 1;

	table[j].time_last_seen_a = node->time_last_seen_a;
	table[j].time_last_seen_b = node->time_last_seen_b;

	is_hsr = node->status & NT_REM_NODE_HSR_BIT;
	val = (node->status & NT_REM_NODE_TYPE_MASK) >> NT_REM_NODE_TYPE_SHIFT;
	switch (val) {
	case NT_REM_NODE_TYPE_DAN:
		if (is_hsr)
			table[j].node_type = IEC62439_3_DANH;
		else
			table[j].node_type = IEC62439_3_DANP;
		break;

	case NT_REM_NODE_TYPE_REDBOX:
		if (is_hsr)
			table[j].node_type = IEC62439_3_REDBOXH;
		else
			table[j].node_type = IEC62439_3_REDBOXP;
		break;

	case NT_REM_NODE_TYPE_VDAN:
		if (is_hsr)
			table[j].node_type = IEC62439_3_VDANH;
		else
			table[j].node_type = IEC62439_3_VDANP;
		break;
	default:
		updated = 0;
		break;
	}

	return updated;
}

static int emac_lredev_get_node_table(struct net_device *ndev,
				      struct lre_node_table_entry table[],
				      int size)
{
	struct prueth_emac *emac = netdev_priv(ndev);
	struct prueth *prueth = emac->prueth;
	struct node_tbl *nt = prueth->nt;
	struct bin_tbl_t *bin;
	struct node_tbl_t *node;
	int i, j = 0, updated;
	unsigned long flags;

	netdev_dbg(ndev, "%d:%s\n", __LINE__, __func__);

	if (size < nt->nt_lre_cnt->lre_cnt)
		netdev_warn(ndev,
			    "actual table size %d is < required size %d\n",
			    size,  nt->nt_lre_cnt->lre_cnt);

	spin_lock_irqsave(&prueth->nt_lock, flags);
	for (i = 0; i < nt->bin_array_max_entries; i++) {
		if (nt->bin_array->bin_tbl[i].node_tbl_offset <
		    nt->nt_array_max_entries) {
			bin =  &nt->bin_array->bin_tbl[i];
			if (WARN_ON(bin->node_tbl_offset >=
					nt->nt_array_max_entries))
				continue;
			node =  &nt->nt_array->node_tbl[bin->node_tbl_offset];

			if (!(node->entry_state & 0x1))
				continue;

			updated = emac_lredev_update_node_entry(node, table, j);
			if (updated) {
				table[j].mac_address[0] = bin->src_mac_id[3];
				table[j].mac_address[1] = bin->src_mac_id[2];
				table[j].mac_address[2] = bin->src_mac_id[1];
				table[j].mac_address[3] = bin->src_mac_id[0];
				table[j].mac_address[4] = bin->src_mac_id[5];
				table[j].mac_address[5] = bin->src_mac_id[4];
				j++;
			}
		}
	}
	spin_unlock_irqrestore(&prueth->nt_lock, flags);

	return j;
}

static int emac_lredev_get_stats(struct net_device *ndev,
				 struct lre_stats *stats)
{
	struct prueth_emac *emac = netdev_priv(ndev);
	struct prueth *prueth = emac->prueth;
	void __iomem *sram = prueth->mem[PRUETH_MEM_SHARED_RAM].va;

	memcpy_fromio(stats, sram + LRE_CNT_TX_A, sizeof(*stats));

	return 0;
}

static int emac_lredev_set_sv_vlan_id(struct net_device *ndev,
				      u16 vid)
{
	struct prueth_emac *emac = netdev_priv(ndev);
	struct prueth *prueth = emac->prueth;

	if (!PRUETH_HAS_RED(prueth))
		return 0;

	return emac_add_del_vid(emac, true, htons(ETH_P_8021Q), vid);
}
static const struct lredev_ops emac_lredev_ops = {
	.lredev_attr_get = emac_lredev_attr_get,
	.lredev_attr_set = emac_lredev_attr_set,
	.lredev_get_node_table = emac_lredev_get_node_table,
	.lredev_get_stats = emac_lredev_get_stats,
	.lredev_set_sv_vlan_id = emac_lredev_set_sv_vlan_id,
};

static int prueth_netdev_init(struct prueth *prueth,
			      struct device_node *eth_node)
{
	enum prueth_port port;
	enum prueth_mac mac;
	struct net_device *ndev;
	struct prueth_emac *emac;
	const u8 *mac_addr;
	char *tx_int;
	int ret;

	port = prueth_node_port(eth_node);
	if (port < 0)
		return -EINVAL;

	mac = prueth_node_mac(eth_node);
	if (mac < 0)
		return -EINVAL;

	/* +++TODO: use alloc_etherdev_mqs() */
	ndev = alloc_etherdev(sizeof(*emac));
	if (!ndev)
		return -ENOMEM;

	SET_NETDEV_DEV(ndev, prueth->dev);
	emac = netdev_priv(ndev);
	prueth->emac[mac] = emac;
	emac->prueth = prueth;
	emac->ndev = ndev;
	emac->port_id = port;

	if (PRUETH_HAS_PTP(prueth) && !PRUETH_IS_EMAC(prueth))
		tx_int = "hsrprp_ptp_tx";
	else
		tx_int = "tx";

	emac->rx_lp_irq = of_irq_get_byname(eth_node->parent,
					    "rx_red_lp");
	emac->rx_hp_irq = of_irq_get_byname(eth_node->parent,
					    "rx_red_hp");
	/* No error check because optional, may just use 'rx' */
	if (emac->rx_hp_irq >= 0 && emac->rx_lp_irq >= 0)
		prueth->priority_ts = 1;

	emac->rx_irq = of_irq_get_byname(eth_node, "rx");
	if (emac->rx_irq < 0) {
		ret = emac->rx_irq;
		if (ret != -EPROBE_DEFER)
			dev_err(prueth->dev,
				"could not get emac rx irq\n");
		goto free;
	}

	emac->tx_irq = of_irq_get_byname(eth_node, tx_int);
	if (emac->tx_irq < 0) {
		ret = emac->tx_irq;
		if (ret != -EPROBE_DEFER)
			dev_err(prueth->dev,
				"could not get emac %s irq\n", tx_int);
		goto free;
	}

	if (PRUETH_HAS_PTP(prueth)) {
		emac->emac_ptp_tx_irq = of_irq_get_byname(eth_node,
							  "emac_ptp_tx");
		if (emac->emac_ptp_tx_irq < 0) {
			ret = emac->emac_ptp_tx_irq;
			if (ret != -EPROBE_DEFER)
				dev_info(prueth->dev,
					 "could not get emac ptp tx irq\n");
		}

		emac->hsrprp_ptp_tx_irq = of_irq_get_byname(eth_node,
							    "hsrprp_ptp_tx");
		if (emac->hsrprp_ptp_tx_irq < 0) {
			ret = emac->hsrprp_ptp_tx_irq;
			if (ret != -EPROBE_DEFER)
				dev_info(prueth->dev,
					 "could not get hsrprp ptp tx irq\n");
		}
	}

	emac->msg_enable = netif_msg_init(debug_level, PRUETH_EMAC_DEBUG);
	spin_lock_init(&emac->lock);
	spin_lock_init(&emac->ev_msg_lock);
	spin_lock_init(&emac->addr_lock);
	/* get mac address from DT and set private and netdev addr */
	mac_addr = of_get_mac_address(eth_node);
	if (mac_addr)
		ether_addr_copy(ndev->dev_addr, mac_addr);
	if (!is_valid_ether_addr(ndev->dev_addr)) {
		eth_hw_addr_random(ndev);
		dev_warn(prueth->dev, "port %d: using random MAC addr: %pM\n",
			 port, ndev->dev_addr);
	}
	ether_addr_copy(emac->mac_addr, ndev->dev_addr);

	emac->phy_node = of_parse_phandle(eth_node, "phy-handle", 0);
	if (!emac->phy_node) {
		dev_err(prueth->dev, "couldn't find phy-handle\n");
		ret = -ENODEV;
		goto free;
	}

	emac->phy_if = of_get_phy_mode(eth_node);
	if (emac->phy_if < 0) {
		dev_err(prueth->dev, "could not get phy-mode property\n");
		ret = emac->phy_if;
		goto free;
	}

	/* connect PHY */
	emac->phydev = of_phy_connect(ndev, emac->phy_node,
				      &emac_adjust_link, 0, emac->phy_if);
	if (!emac->phydev) {
		dev_dbg(prueth->dev, "couldn't connect to phy %s\n",
			emac->phy_node->full_name);
		ret = -EPROBE_DEFER;
		goto free;
	}

	emac->phydev->advertising &= ~(ADVERTISED_1000baseT_Full |
			ADVERTISED_1000baseT_Half);
	emac->phydev->supported &= ~(SUPPORTED_1000baseT_Full |
			SUPPORTED_1000baseT_Half);

	if (PRUETH_HAS_HSR(prueth))
		ndev->features |= (NETIF_F_HW_HSR_RX_OFFLOAD |
					NETIF_F_HW_L2FW_DOFFLOAD |
					NETIF_F_HW_VLAN_CTAG_FILTER);
	else if (PRUETH_HAS_PRP(prueth))
		ndev->features |= NETIF_F_HW_PRP_RX_OFFLOAD |
				  NETIF_F_HW_VLAN_CTAG_FILTER;

	ndev->features |= NETIF_F_HW_VLAN_CTAG_FILTER;

	ndev->hw_features |= (NETIF_F_HW_PRP_RX_OFFLOAD |
				NETIF_F_HW_HSR_RX_OFFLOAD |
				NETIF_F_HW_L2FW_DOFFLOAD |
				NETIF_F_HW_VLAN_CTAG_FILTER);

	ndev->netdev_ops = &emac_netdev_ops;
	ndev->ethtool_ops = &emac_ethtool_ops;
#ifdef CONFIG_HSR_PRP
	ndev->lredev_ops = &emac_lredev_ops;
#endif

	return 0;

free:
	free_netdev(ndev);
	prueth->emac[mac] = NULL;

	return ret;
}

static void prueth_netdev_exit(struct prueth *prueth,
			       struct device_node *eth_node)
{
	struct prueth_emac *emac;
	enum prueth_mac mac;

	mac = prueth_node_mac(eth_node);
	if (mac < 0)
		return;

	emac = prueth->emac[mac];
	if (!emac)
		return;

	dev_info(prueth->dev, "freeing port%d\n", mac);

	phy_disconnect(emac->phydev);

	free_netdev(emac->ndev);
	prueth->emac[mac] = NULL;
}

static const struct of_device_id prueth_dt_match[];

static void prueth_get_mc_mac_mask(struct prueth_emac *emac, char *mc_mask)
{
	struct prueth *prueth = emac->prueth;

	int result = sscanf(mc_mask, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			    &emac->mc_mac_mask[0],
			    &emac->mc_mac_mask[1],
			    &emac->mc_mac_mask[2],
			    &emac->mc_mac_mask[3],
			    &emac->mc_mac_mask[4],
			    &emac->mc_mac_mask[5]);

	if (result == 6)
		return;

	dev_err(prueth->dev,
		"Error in prueth mc mask in bootargs %s\n",
		mc_mask);
	/* assign default mask */
	memset(&emac->mc_mac_mask[0], 0xff, ETH_ALEN);
}

static int prueth_probe(struct platform_device *pdev)
{
	struct prueth *prueth;
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;
	struct device_node *eth0_node, *eth1_node;
	const struct of_device_id *match;
	struct pruss *pruss;
	int pruss_id1, pruss_id2, ethtype1, ethtype2, drop_untagged1,
	drop_untagged2, i, ret;
	char *mc_mask1_port0, *mc_mask1_port1, *mc_mask2_port0, *mc_mask2_port1;

	if (!np)
		return -ENODEV;	/* we don't support non DT */

	match = of_match_device(prueth_dt_match, dev);
	if (!match)
		return -ENODEV;

	prueth = devm_kzalloc(dev, sizeof(*prueth), GFP_KERNEL);
	if (!prueth)
		return -ENOMEM;

	platform_set_drvdata(pdev, prueth);

	prueth->dev = dev;
	prueth->fw_data = match->data;
	prueth->prueth_np = np;

	prueth->hp = devm_kzalloc(dev, sizeof(struct prueth_ndev_priority),
				  GFP_KERNEL);
	if (!prueth->hp)
		return -ENOMEM;
	prueth->lp = devm_kzalloc(dev, sizeof(struct prueth_ndev_priority),
				  GFP_KERNEL);
	if (!prueth->hp)
		return -ENOMEM;

	if (prueth->fw_data->fw_rev == FW_REV_V1_0)
		prueth->fw_offsets = &fw_offsets_v1_0;
	else
		prueth->fw_offsets = &fw_offsets_v2_1;

	eth0_node = of_get_child_by_name(np, "ethernet-mii0");
	if (!of_device_is_available(eth0_node)) {
		of_node_put(eth0_node);
		eth0_node = NULL;
	}

	eth1_node = of_get_child_by_name(np, "ethernet-mii1");
	if (!of_device_is_available(eth1_node)) {
		of_node_put(eth1_node);
		eth1_node = NULL;
	}

	/* At least one node must be present and available else we fail */
	if (!eth0_node && !eth1_node) {
		dev_err(dev, "neither ethernet-mii0 nor ethernet-mii1 node available\n");
		ret = -ENODEV;
		goto put_node;
	}

	prueth->eth_node[PRUETH_MAC0] = eth0_node;
	prueth->eth_node[PRUETH_MAC1] = eth1_node;

	if (eth0_node) {
		prueth->pru0 = pru_rproc_get(np, 0);
		if (IS_ERR(prueth->pru0)) {
			ret = PTR_ERR(prueth->pru0);
			if (ret != -EPROBE_DEFER)
				dev_err(dev, "unable to get PRU0: %d\n", ret);
			goto put_node;
		}
	}

	if (eth1_node) {
		prueth->pru1 = pru_rproc_get(np, 1);
		if (IS_ERR(prueth->pru1)) {
			ret = PTR_ERR(prueth->pru1);
			if (ret != -EPROBE_DEFER)
				dev_err(dev, "unable to get PRU1: %d\n", ret);
			goto put_pru0;
		}
	}

	pruss = pruss_get(prueth->pru0 ? prueth->pru0 : prueth->pru1,
			  &prueth->pruss_id);
	if (IS_ERR(pruss)) {
		ret = PTR_ERR(pruss);
		dev_err(dev, "unable to get pruss handle\n");
		goto put_pru1;
	}
	prueth->pruss = pruss;

	/* Configure PRUSS */
	if (eth0_node)
		pruss_cfg_gpimode(pruss, prueth->pru0, PRUSS_GPI_MODE_MII);
	if (eth1_node)
		pruss_cfg_gpimode(pruss, prueth->pru1, PRUSS_GPI_MODE_MII);
	pruss_cfg_miirt_enable(pruss, true);
	pruss_cfg_xfr_enable(pruss, true);

	/* Get PRUSS mem resources */
	/* OCMC is system resource which we get separately */
	for (i = 0; i < ARRAY_SIZE(pruss_mem_ids); i++) {
		/* skip appropriate DRAM if not required */
		if (!eth0_node && i == PRUETH_MEM_DRAM0)
			continue;

		if (!eth1_node && i == PRUETH_MEM_DRAM1)
			continue;

		ret = pruss_request_mem_region(pruss, pruss_mem_ids[i],
					       &prueth->mem[i]);
		if (ret) {
			dev_err(dev, "unable to get PRUSS resource %d: %d\n",
				i, ret);
			goto put_mem;
		}
	}

	/* Set up the proper params to be used for checking */
	if (prueth->fw_data->driver_data == PRUSS_AM57XX) {
		pruss_id1 = PRUSS1;
		pruss_id2 = PRUSS2;
		ethtype1 = pruss1_ethtype;
		ethtype2 = pruss2_ethtype;
		mc_mask1_port0 = pruss1_port0_mc_mask;
		mc_mask1_port1 = pruss1_port1_mc_mask;
		mc_mask2_port0 = pruss2_port0_mc_mask;
		mc_mask2_port1 = pruss2_port1_mc_mask;
		drop_untagged1 = pruss0_fw_drop_untagged;
		drop_untagged2 = pruss1_fw_drop_untagged;
	} else {
		pruss_id1 = PRUSS0;
		pruss_id2 = PRUSS1;
		ethtype1 = pruss0_ethtype;
		ethtype2 = pruss1_ethtype;
		mc_mask1_port0 = pruss0_port0_mc_mask;
		mc_mask1_port1 = pruss0_port1_mc_mask;
		mc_mask2_port0 = pruss1_port0_mc_mask;
		mc_mask2_port1 = pruss1_port1_mc_mask;
		drop_untagged1 = pruss0_fw_drop_untagged;
		drop_untagged2 = pruss1_fw_drop_untagged;
	}

	if (prueth->pruss_id == pruss_id1) {
		prueth->eth_type = ethtype1;
		prueth->fw_drop_untagged_vlan = drop_untagged1;
	} else {
		prueth->eth_type = ethtype2;
		prueth->fw_drop_untagged_vlan = drop_untagged2;
	}

	prueth->ocmc_ram_size = OCMC_RAM_SIZE;
	/* OCMC_RAM1 */
	prueth->sram_pool = of_gen_pool_get(np, "sram", 0);
	if (!prueth->sram_pool) {
		dev_err(dev, "unable to get SRAM pool\n");
		ret = -ENODEV;

		goto put_mem;
	}
	prueth->mem[PRUETH_MEM_OCMC].va =
			(void __iomem *)gen_pool_alloc(prueth->sram_pool,
						       prueth->ocmc_ram_size);
	if (!prueth->mem[PRUETH_MEM_OCMC].va) {
		dev_err(dev, "unable to allocate OCMC resource\n");
		ret = -ENOMEM;
		goto put_mem;
	}
	prueth->mem[PRUETH_MEM_OCMC].pa =
			gen_pool_virt_to_phys(prueth->sram_pool,
			(unsigned long)prueth->mem[PRUETH_MEM_OCMC].va);
	prueth->mem[PRUETH_MEM_OCMC].size = prueth->ocmc_ram_size;
	dev_dbg(dev, "ocmc: pa %pa va %p size %#zx\n",
		&prueth->mem[PRUETH_MEM_OCMC].pa,
		prueth->mem[PRUETH_MEM_OCMC].va,
		prueth->mem[PRUETH_MEM_OCMC].size);

	/* setup netdev interfaces */
	mutex_init(&prueth->mlock);

	if (eth0_node) {
		ret = prueth_netdev_init(prueth, eth0_node);
		if (ret) {
			if (ret != -EPROBE_DEFER) {
				dev_err(dev, "netdev init %s failed: %d\n",
					eth0_node->name, ret);
			}
			goto free_pool;
		}
	}

	if (eth1_node) {
		ret = prueth_netdev_init(prueth, eth1_node);
		if (ret) {
			if (ret != -EPROBE_DEFER) {
				dev_err(dev, "netdev init %s failed: %d\n",
					eth1_node->name, ret);
			}
			goto netdev_exit;
		}
	}

	prueth_init_mem(prueth);

	if (prueth->pruss_id == pruss_id1) {
		if (eth0_node)
			prueth_get_mc_mac_mask(prueth->emac[PRUETH_MAC0],
					       mc_mask1_port0);
		if (eth1_node)
			prueth_get_mc_mac_mask(prueth->emac[PRUETH_MAC1],
					       mc_mask1_port1);
	} else {
		if (eth0_node)
			prueth_get_mc_mac_mask(prueth->emac[PRUETH_MAC0],
					       mc_mask2_port0);
		if (eth1_node)
			prueth_get_mc_mac_mask(prueth->emac[PRUETH_MAC1],
					       mc_mask2_port1);
	}

	dev_info(dev, "pruss_fw_drop_untagged_vlan %d\n",
		 prueth->fw_drop_untagged_vlan);
	if (eth0_node) {
		dev_info(dev, "pruss MC Mask (Port 0) %x:%x:%x:%x:%x:%x\n",
			 prueth->emac[PRUETH_MAC0]->mc_mac_mask[0],
			 prueth->emac[PRUETH_MAC0]->mc_mac_mask[1],
			 prueth->emac[PRUETH_MAC0]->mc_mac_mask[2],
			 prueth->emac[PRUETH_MAC0]->mc_mac_mask[3],
			 prueth->emac[PRUETH_MAC0]->mc_mac_mask[4],
			 prueth->emac[PRUETH_MAC0]->mc_mac_mask[5]);
	}
	if (eth1_node) {
		dev_info(dev, "pruss MC Mask (Port 1) %x:%x:%x:%x:%x:%x\n",
			 prueth->emac[PRUETH_MAC1]->mc_mac_mask[0],
			 prueth->emac[PRUETH_MAC1]->mc_mac_mask[1],
			 prueth->emac[PRUETH_MAC1]->mc_mac_mask[2],
			 prueth->emac[PRUETH_MAC1]->mc_mac_mask[3],
			 prueth->emac[PRUETH_MAC1]->mc_mac_mask[4],
			 prueth->emac[PRUETH_MAC1]->mc_mac_mask[5]);
	}
	prueth->iep = iep_create(prueth->dev,
				 prueth->mem[PRUETH_MEM_SHARED_RAM].va,
				 prueth->mem[PRUETH_MEM_IEP].va,
				 prueth->pruss_id,
				 prueth->fw_data->fw_rev);
	if (IS_ERR(prueth->iep)) {
		ret = PTR_ERR(prueth->iep);
		goto netdev_exit;
	}

	/* register the network devices */
	if (eth0_node) {
		ret = register_netdev(prueth->emac[PRUETH_MAC0]->ndev);
		if (ret) {
			dev_err(dev, "can't register netdev for port MII0");
			goto netdev_exit;
		}
		ret = prueth_debugfs_init(prueth->emac[PRUETH_MAC0]);
		if (ret)
			goto debugfs0_exit;
		prueth_sysfs_init(prueth->emac[PRUETH_MAC0]);
		prueth->registered_netdevs[PRUETH_MAC0] = prueth->emac[PRUETH_MAC0]->ndev;
	}

	if (eth1_node) {
		ret = register_netdev(prueth->emac[PRUETH_MAC1]->ndev);
		if (ret) {
			dev_err(dev, "can't register netdev for port MII1");
			goto netdev_unregister;
		}
		ret = prueth_debugfs_init(prueth->emac[PRUETH_MAC1]);
		if (ret)
			goto debugfs1_exit;
		prueth_sysfs_init(prueth->emac[PRUETH_MAC1]);
		prueth->registered_netdevs[PRUETH_MAC1] = prueth->emac[PRUETH_MAC1]->ndev;
	}

	dev_info(dev, "TI PRU ethernet (type %u) driver initialized\n",
		 prueth->eth_type);

	return 0;

debugfs1_exit:
	prueth_debugfs_term(prueth->emac[PRUETH_MAC1]);

netdev_unregister:
	for (i = 0; i < PRUETH_NUM_MACS; i++) {
		if (!prueth->registered_netdevs[i])
			continue;
		unregister_netdev(prueth->registered_netdevs[i]);
	}
debugfs0_exit:
	prueth_debugfs_term(prueth->emac[PRUETH_MAC0]);

netdev_exit:
	for (i = 0; i < PRUETH_NUM_MACS; i++) {
		struct device_node *eth_node;

		eth_node = prueth->eth_node[i];
		if (!eth_node)
			continue;

		prueth_netdev_exit(prueth, eth_node);
	}

free_pool:
	gen_pool_free(prueth->sram_pool,
		      (unsigned long)prueth->mem[PRUETH_MEM_OCMC].va,
		      prueth->ocmc_ram_size);

put_mem:
	for (i = PRUETH_MEM_DRAM0; i < PRUETH_MEM_OCMC; i++) {
		if (prueth->mem[i].va)
			pruss_release_mem_region(pruss, &prueth->mem[i]);
	}

	pruss_put(prueth->pruss);

put_pru1:
	if (eth1_node)
		pru_rproc_put(prueth->pru1);
put_pru0:
	if (eth0_node)
		pru_rproc_put(prueth->pru0);

put_node:
	of_node_put(eth1_node);
	of_node_put(eth0_node);

	return ret;
}

static int prueth_remove(struct platform_device *pdev)
{
	struct device_node *eth_node;
	struct prueth *prueth = platform_get_drvdata(pdev);
	int i;

	iep_release(prueth->iep);
	prueth_hsr_prp_debugfs_term(prueth);
	prueth->tbl_check_period = 0;
	prueth_remove_sysfs_entries(prueth->emac[PRUETH_MAC0]);
	prueth_remove_sysfs_entries(prueth->emac[PRUETH_MAC1]);
	for (i = 0; i < PRUETH_NUM_MACS; i++) {
		if (!prueth->registered_netdevs[i])
			continue;
		prueth_debugfs_term(prueth->emac[i]);
		unregister_netdev(prueth->registered_netdevs[i]);
	}

	for (i = 0; i < PRUETH_NUM_MACS; i++) {
		eth_node = prueth->eth_node[i];
		if (!eth_node)
			continue;

		prueth_netdev_exit(prueth, eth_node);
		of_node_put(eth_node);
	}

	gen_pool_free(prueth->sram_pool,
		      (unsigned long)prueth->mem[PRUETH_MEM_OCMC].va,
		      prueth->ocmc_ram_size);

	for (i = PRUETH_MEM_DRAM0; i < PRUETH_MEM_OCMC; i++) {
		if (prueth->mem[i].va)
			pruss_release_mem_region(prueth->pruss, &prueth->mem[i]);
	}

	pruss_put(prueth->pruss);

	if (prueth->eth_node[PRUETH_MAC0])
		pru_rproc_put(prueth->pru1);
	if (prueth->eth_node[PRUETH_MAC1])
		pru_rproc_put(prueth->pru0);

	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int prueth_suspend(struct device *dev)
{
	struct prueth *prueth = dev_get_drvdata(dev);
	struct net_device *ndev;
	int i, ret;

	for (i = 0; i < PRUETH_NUM_MACS; i++) {
		ndev = prueth->registered_netdevs[i];

		if (!ndev)
			continue;

		if (netif_running(ndev)) {
			netif_device_detach(ndev);
			ret = emac_ndo_stop(ndev);
			if (ret < 0) {
				netdev_err(ndev, "failed to stop: %d", ret);
				return ret;
			}
		}
	}

	return 0;
}

static int prueth_resume(struct device *dev)
{
	struct prueth *prueth = dev_get_drvdata(dev);
	struct net_device *ndev;
	int i, ret;

	for (i = 0; i < PRUETH_NUM_MACS; i++) {
		ndev = prueth->registered_netdevs[i];

		if (!ndev)
			continue;

		if (netif_running(ndev)) {
			ret = emac_ndo_open(ndev);
			if (ret < 0) {
				netdev_err(ndev, "failed to start: %d", ret);
				return ret;
			}
			netif_device_attach(ndev);
		}
	}

	return 0;
}

#endif /* CONFIG_PM_SLEEP */

static const struct dev_pm_ops prueth_dev_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(prueth_suspend, prueth_resume)
};

/* AM33xx SoC-specific firmware data */
static struct prueth_private_data am335x_prueth_pdata = {
	.driver_data = PRUSS_AM3359,
	.fw_pru[PRUSS_PRU0] = {
		.fw_name[PRUSS_ETHTYPE_EMAC] =
			"ti-pruss/am335x-pru0-prueth-fw.elf",
		.fw_name[PRUSS_ETHTYPE_HSR] =
			"ti-pruss/am335x-pru0-pruhsr-fw.elf",
		.fw_name[PRUSS_ETHTYPE_PRP] =
			"ti-pruss/am335x-pru0-pruprp-fw.elf"
	},
	.fw_pru[PRUSS_PRU1] = {
		.fw_name[PRUSS_ETHTYPE_EMAC] =
			"ti-pruss/am335x-pru1-prueth-fw.elf",
		.fw_name[PRUSS_ETHTYPE_HSR] =
			"ti-pruss/am335x-pru1-pruhsr-fw.elf",
		.fw_name[PRUSS_ETHTYPE_PRP] =
			"ti-pruss/am335x-pru1-pruprp-fw.elf"
	},
	.fw_rev = FW_REV_V1_0,
	.ptp_support = 1
};

/* AM437x SoC-specific firmware data */
static struct prueth_private_data am437x_prueth_pdata = {
	.driver_data = PRUSS_AM4376,
	.fw_pru[PRUSS_PRU0] = {
		.fw_name[PRUSS_ETHTYPE_EMAC] =
			"ti-pruss/am437x-pru0-prueth-fw.elf",
		.fw_name[PRUSS_ETHTYPE_HSR] =
			"ti-pruss/am437x-pru0-pruhsr-fw.elf",
		.fw_name[PRUSS_ETHTYPE_PRP] =
			"ti-pruss/am437x-pru0-pruprp-fw.elf"
	},
	.fw_pru[PRUSS_PRU1] = {
		.fw_name[PRUSS_ETHTYPE_EMAC] =
			"ti-pruss/am437x-pru1-prueth-fw.elf",
		.fw_name[PRUSS_ETHTYPE_HSR] =
			"ti-pruss/am437x-pru1-pruhsr-fw.elf",
		.fw_name[PRUSS_ETHTYPE_PRP] =
			"ti-pruss/am437x-pru1-pruprp-fw.elf"
	},
	.fw_rev = FW_REV_V1_0,
	.ptp_support = 1
};

/* AM57xx SoC-specific firmware data */
static struct prueth_private_data am57xx_prueth_pdata = {
	.driver_data = PRUSS_AM57XX,
	.fw_pru[PRUSS_PRU0] = {
		.fw_name[PRUSS_ETHTYPE_EMAC] =
			"ti-pruss/am57xx-pru0-prueth-fw.elf",
		.fw_name[PRUSS_ETHTYPE_HSR] =
			"ti-pruss/am57xx-pru0-pruhsr-fw.elf",
		.fw_name[PRUSS_ETHTYPE_PRP] =
			"ti-pruss/am57xx-pru0-pruprp-fw.elf",
	},
	.fw_pru[PRUSS_PRU1] = {
		.fw_name[PRUSS_ETHTYPE_EMAC] =
			"ti-pruss/am57xx-pru1-prueth-fw.elf",
		.fw_name[PRUSS_ETHTYPE_HSR] =
			"ti-pruss/am57xx-pru1-pruhsr-fw.elf",
		.fw_name[PRUSS_ETHTYPE_PRP] =
			"ti-pruss/am57xx-pru1-pruprp-fw.elf",
	},
	.fw_rev = FW_REV_V2_1,
	.ptp_support = 1
};

/* 66AK2G SoC-specific firmware data */
static struct prueth_private_data k2g_prueth_pdata = {
	.driver_data = PRUSS_K2G,
	.fw_pru[PRUSS_PRU0] = {
		.fw_name[PRUSS_ETHTYPE_EMAC] =
			"ti-pruss/k2g-pru0-prueth-fw.elf",
		.fw_name[PRUSS_ETHTYPE_HSR] =
			"ti-pruss/k2g-pru0-pruhsr-fw.elf",
		.fw_name[PRUSS_ETHTYPE_PRP] =
			"ti-pruss/k2g-pru0-pruprp-fw.elf"
	},
	.fw_pru[PRUSS_PRU1] = {
		.fw_name[PRUSS_ETHTYPE_EMAC] =
			"ti-pruss/k2g-pru1-prueth-fw.elf",
		.fw_name[PRUSS_ETHTYPE_HSR] =
			"ti-pruss/k2g-pru1-pruhsr-fw.elf",
		.fw_name[PRUSS_ETHTYPE_PRP] =
			"ti-pruss/k2g-pru1-pruprp-fw.elf"
	},
	.fw_rev = FW_REV_V2_1,
	.ptp_support = 1
};

static const struct of_device_id prueth_dt_match[] = {
	{ .compatible = "ti,am57-prueth", .data = &am57xx_prueth_pdata, },
	{ .compatible = "ti,am4376-prueth", .data = &am437x_prueth_pdata, },
	{ .compatible = "ti,am3359-prueth", .data = &am335x_prueth_pdata, },
	{ .compatible = "ti,k2g-prueth", .data = &k2g_prueth_pdata, },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, prueth_dt_match);

static struct platform_driver prueth_driver = {
	.probe = prueth_probe,
	.remove = prueth_remove,
	.driver = {
		.name = "prueth",
		.of_match_table = prueth_dt_match,
		.pm = &prueth_dev_pm_ops,
	},
};
module_platform_driver(prueth_driver);

MODULE_AUTHOR("Roger Quadros <rogerq@ti.com>");
MODULE_AUTHOR("Andrew F. Davis <afd@ti.com>");
MODULE_DESCRIPTION("PRU Ethernet Driver");
MODULE_LICENSE("GPL v2");
