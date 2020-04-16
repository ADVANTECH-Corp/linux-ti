/* Copyright 2011-2014 Autronica Fire and Security AS
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * Author(s):
 *	2011-2014 Arvid Brodin, arvid.brodin@alten.se
 *
 * This file contains device methods for creating, using and destroying
 * virtual HSR devices.
 */

#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <linux/net_tstamp.h>
#include "hsr_prp_device.h"
#include "hsr_prp_slave.h"
#include "hsr_prp_framereg.h"
#include "hsr_prp_main.h"
#include "hsr_prp_forward.h"

static inline bool is_slave_port(struct hsr_prp_port *p)
{
	return (p->type == HSR_PRP_PT_SLAVE_A) ||
	       (p->type == HSR_PRP_PT_SLAVE_B);
}

static bool is_admin_up(struct net_device *dev)
{
	return dev && (dev->flags & IFF_UP);
}

static bool is_slave_up(struct net_device *dev)
{
	return dev && is_admin_up(dev) && netif_oper_up(dev);
}

static void __set_operstate(struct net_device *dev, int transition)
{
	write_lock_bh(&dev_base_lock);
	if (dev->operstate != transition) {
		dev->operstate = transition;
		write_unlock_bh(&dev_base_lock);
		netdev_state_change(dev);
	} else {
		write_unlock_bh(&dev_base_lock);
	}
}

static void set_operstate(struct hsr_prp_port *master, bool has_carrier)
{
	if (!is_admin_up(master->dev)) {
		__set_operstate(master->dev, IF_OPER_DOWN);
		return;
	}

	if (has_carrier)
		__set_operstate(master->dev, IF_OPER_UP);
	else
		__set_operstate(master->dev, IF_OPER_LOWERLAYERDOWN);
}

static bool hsr_prp_check_carrier(struct hsr_prp_port *master)
{
	struct hsr_prp_port *port;
	bool has_carrier;

	has_carrier = false;

	rcu_read_lock();
	hsr_prp_for_each_port(master->priv, port)
		if (port->type != HSR_PRP_PT_MASTER &&
		    is_slave_up(port->dev)) {
			has_carrier = true;
			break;
		}
	rcu_read_unlock();

	if (has_carrier)
		netif_carrier_on(master->dev);
	else
		netif_carrier_off(master->dev);

	return has_carrier;
}

static void hsr_prp_check_announce(struct net_device *priv_dev,
				   unsigned char old_operstate)
{
	struct hsr_prp_priv *priv;

	priv = netdev_priv(priv_dev);

	if (priv_dev->operstate == IF_OPER_UP &&
	    old_operstate != IF_OPER_UP) {
		/* Went up */
		priv->announce_count = 0;
		priv->announce_timer.expires = jiffies +
				msecs_to_jiffies(HSR_PRP_ANNOUNCE_INTERVAL);
		add_timer(&priv->announce_timer);
	}

	if (priv_dev->operstate != IF_OPER_UP && old_operstate == IF_OPER_UP)
		/* Went down */
		del_timer(&priv->announce_timer);
}

void hsr_prp_check_carrier_and_operstate(struct hsr_prp_priv *priv)
{
	struct hsr_prp_port *master;
	unsigned char old_operstate;
	bool has_carrier;

	master = hsr_prp_get_port(priv, HSR_PRP_PT_MASTER);
	/* netif_stacked_transfer_operstate() cannot be used here since
	 * it doesn't set IF_OPER_LOWERLAYERDOWN (?)
	 */
	old_operstate = master->dev->operstate;
	has_carrier = hsr_prp_check_carrier(master);
	set_operstate(master, has_carrier);
	hsr_prp_check_announce(master->dev, old_operstate);
}

int hsr_prp_get_max_mtu(struct hsr_prp_priv *priv)
{
	unsigned int mtu_max;
	struct hsr_prp_port *port;

	mtu_max = ETH_DATA_LEN;
	rcu_read_lock();
	hsr_prp_for_each_port(priv, port)
		if (port->type != HSR_PRP_PT_MASTER)
			mtu_max = min(port->dev->mtu, mtu_max);

	rcu_read_unlock();

	if (mtu_max < HSR_PRP_HLEN)
		return 0;

	/* For offloaded keep the mtu same as ETH_DATA_LEN as
	 * h/w is expected to extend the frame to accommodate RCT
	 * or TAG
	 */
	if (!priv->rx_offloaded)
		return mtu_max - HSR_PRP_HLEN;

	return mtu_max;
}

int hsr_prp_lredev_attr_get(struct hsr_prp_priv *priv,
			    struct lredev_attr *attr)
{
	struct hsr_prp_port *port_a =
		hsr_prp_get_port(priv, HSR_PRP_PT_SLAVE_A);
	struct net_device *slave_a_dev;

	if (!port_a)
		return -EINVAL;

	slave_a_dev = port_a->dev;
	if (slave_a_dev && slave_a_dev->lredev_ops &&
	    slave_a_dev->lredev_ops->lredev_attr_get)
		return slave_a_dev->lredev_ops->lredev_attr_get(slave_a_dev,
								attr);
	return -EINVAL;
}

int hsr_prp_lredev_attr_set(struct hsr_prp_priv *priv,
			    struct lredev_attr *attr)
{
	struct hsr_prp_port *port_a =
		hsr_prp_get_port(priv, HSR_PRP_PT_SLAVE_A);
	struct net_device *slave_a_dev;

	if (!port_a)
		return -EINVAL;

	slave_a_dev = port_a->dev;
	if (slave_a_dev && slave_a_dev->lredev_ops &&
	    slave_a_dev->lredev_ops->lredev_attr_set)
		return slave_a_dev->lredev_ops->lredev_attr_set(slave_a_dev,
								attr);
	return -EINVAL;
}

static int _hsr_prp_lredev_get_node_table(struct hsr_prp_priv *priv,
					  struct lre_node_table_entry table[],
					  int size)
{
	struct hsr_prp_node *node;
	int i = 0;

	rcu_read_lock();

	list_for_each_entry_rcu(node, &priv->node_db, mac_list) {
		if (hsr_prp_addr_is_self(priv, node->mac_address_a))
			continue;
		memcpy(&table[i].mac_address[0],
		       &node->mac_address_a[0], ETH_ALEN);
		table[i].time_last_seen_a = node->time_in[HSR_PRP_PT_SLAVE_A];
		table[i].time_last_seen_b = node->time_in[HSR_PRP_PT_SLAVE_B];
		if (priv->prot_ver == PRP_V1)
			table[i].node_type = IEC62439_3_DANP;
		else if (priv->prot_ver <= HSR_V1)
			table[i].node_type = IEC62439_3_DANH;
		else
			continue;
		i++;
	}
	rcu_read_unlock();

	return i;
}

int hsr_prp_lredev_get_node_table(struct hsr_prp_priv *priv,
				  struct lre_node_table_entry table[],
				  int size)
{
	struct hsr_prp_port *port_a =
		hsr_prp_get_port(priv, HSR_PRP_PT_SLAVE_A);
	struct net_device *slave_a_dev;
	int ret = -EINVAL;

	if (!port_a)
		return ret;

	if (!priv->rx_offloaded)
		return _hsr_prp_lredev_get_node_table(priv, table, size);

	slave_a_dev = port_a->dev;

	if (slave_a_dev && slave_a_dev->lredev_ops &&
	    slave_a_dev->lredev_ops->lredev_get_node_table)
		ret =
		slave_a_dev->lredev_ops->lredev_get_node_table(slave_a_dev,
							       table,
							       size);
	return ret;
}

static int hsr_prp_set_sv_frame_vid(struct hsr_prp_priv *priv,
				    u16 vid)
{
	struct hsr_prp_port *port_a =
		hsr_prp_get_port(priv, HSR_PRP_PT_SLAVE_A);
	struct net_device *slave_a_dev;
	int ret = -EINVAL;

	if (!port_a)
		return ret;

	slave_a_dev = port_a->dev;

	/* TODO can we use vlan_vid_add() here?? */
	if (slave_a_dev && slave_a_dev->lredev_ops &&
	    slave_a_dev->lredev_ops->lredev_set_sv_vlan_id)
		slave_a_dev->lredev_ops->lredev_set_sv_vlan_id(slave_a_dev,
							       vid);
	return 0;
}

int hsr_prp_lredev_get_lre_stats(struct hsr_prp_priv *priv,
				 struct lre_stats *stats)
{
	struct hsr_prp_port *port_a =
		hsr_prp_get_port(priv, HSR_PRP_PT_SLAVE_A);
	struct net_device *slave_a_dev;
	int ret = -EINVAL;

	if (!port_a)
		return ret;

	slave_a_dev = port_a->dev;

	if (slave_a_dev && slave_a_dev->lredev_ops &&
	    slave_a_dev->lredev_ops->lredev_get_stats)
		ret =
		slave_a_dev->lredev_ops->lredev_get_stats(slave_a_dev, stats);
	return ret;
}

static int hsr_prp_dev_change_mtu(struct net_device *dev, int new_mtu)
{
	struct hsr_prp_priv *priv;
	struct hsr_prp_port *master;
	int max;

	priv = netdev_priv(dev);
	master = hsr_prp_get_port(priv, HSR_PRP_PT_MASTER);
	max = hsr_prp_get_max_mtu(priv);
	if (new_mtu > max) {
		netdev_info(master->dev,
			    "HSR/PRP: Invalid MTU, expected (<= %d), Got %d.\n",
			    max, new_mtu);
		return -EINVAL;
	}

	dev->mtu = new_mtu;

	return 0;
}

static int hsr_prp_dev_open(struct net_device *dev)
{
	struct hsr_prp_priv *priv;
	struct hsr_prp_port *port;
	char designation;

	priv = netdev_priv(dev);
	designation = '\0';

	rcu_read_lock();
	hsr_prp_for_each_port(priv, port) {
		if (port->type == HSR_PRP_PT_MASTER)
			continue;
		switch (port->type) {
		case HSR_PRP_PT_SLAVE_A:
			designation = 'A';
			break;
		case HSR_PRP_PT_SLAVE_B:
			designation = 'B';
			break;
		default:
			designation = '?';
		}
		if (!is_slave_up(port->dev))
			netdev_warn(dev,
				    "HSR/PRP: Please bringup Slave %c (%s)\n",
				    designation, port->dev->name);
	}
	rcu_read_unlock();

	if (designation == '\0')
		netdev_warn(dev, "No slave devices configured\n");

	return 0;
}

static int hsr_prp_dev_close(struct net_device *dev)
{
	struct hsr_prp_priv *priv;
	struct hsr_prp_port *port_a, *port_b;

	priv = netdev_priv(dev);

	port_a = hsr_prp_get_port(priv, HSR_PRP_PT_SLAVE_A);
	port_b = hsr_prp_get_port(priv, HSR_PRP_PT_SLAVE_B);

	if (port_a && port_b) {
		dev_mc_unsync(port_a->dev, dev);
		dev_uc_unsync(port_a->dev, dev);
		dev_mc_unsync(port_b->dev, dev);
		dev_uc_unsync(port_b->dev, dev);
	}

	return 0;
}

static netdev_features_t hsr_prp_features_recompute(struct hsr_prp_priv *priv,
						    netdev_features_t features)
{
	netdev_features_t mask;
	struct hsr_prp_port *port;

	mask = features;

	/* Mask out all features that, if supported by one device, should be
	 * enabled for all devices (see NETIF_F_ONE_FOR_ALL).
	 *
	 * Anything that's off in mask will not be enabled - so only things
	 * that were in features originally, and also is in NETIF_F_ONE_FOR_ALL,
	 * may become enabled.
	 */
	features &= ~NETIF_F_ONE_FOR_ALL;
	hsr_prp_for_each_port(priv, port)
		features = netdev_increment_features(features,
						     port->dev->features,
						     mask);

	return features;
}

static netdev_features_t hsr_prp_fix_features(struct net_device *dev,
					      netdev_features_t features)
{
	struct hsr_prp_priv *priv = netdev_priv(dev);

	return hsr_prp_features_recompute(priv, features);
}

static int hsr_prp_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct hsr_prp_priv *priv = netdev_priv(dev);
	struct hsr_prp_port *master;

	master = hsr_prp_get_port(priv, HSR_PRP_PT_MASTER);
	skb->dev = master->dev;
	hsr_prp_forward_skb(skb, master);
	master->dev->stats.tx_packets++;
	master->dev->stats.tx_bytes += skb->len;
	INC_CNT_RX_C(priv);

	return NETDEV_TX_OK;
}

static const struct header_ops hsr_prp_header_ops = {
	.create	 = eth_header,
	.parse	 = eth_header_parse,
};

static void send_supervision_frame(struct hsr_prp_port *master,
				   u8 type, u8 prot_ver)
{
	struct sk_buff *skb;
	int hlen, tlen;
	struct hsr_tag *hsr_tag;
	struct vlan_hdr *vhdr;
	struct prp_rct *rct;
	struct hsr_prp_sup_tag *hsr_stag;
	struct hsr_prp_sup_payload *hsr_sp;
	struct hsr_prp_priv *priv;
	unsigned long irqflags;
	u16 proto, vlan_tci = 0;
	u8 *tail;
	int len;

	priv = master->priv;

	if (priv->disable_sv_frame)
		return;

	hlen = LL_RESERVED_SPACE(master->dev);
	tlen = master->dev->needed_tailroom;
	len = sizeof(struct hsr_tag) +
	      sizeof(struct hsr_prp_sup_tag) +
	      sizeof(struct hsr_prp_sup_payload) + hlen + tlen;

	if (priv->use_vlan_for_sv)
		len += VLAN_HLEN;

	/* skb size is same for PRP/HSR frames, only difference
	 * being for PRP, it is a trailor and for HSR it is a
	 * header
	 */
	skb = dev_alloc_skb(len);
	if (!skb)
		return;

	skb_reserve(skb, hlen);
	if (priv->use_vlan_for_sv) {
		proto = ETH_P_8021Q;
		skb->priority = priv->sv_frame_pcp;
	} else {
		if (!prot_ver)
			proto = ETH_P_PRP;
		else
			proto = (prot_ver == HSR_V1) ? ETH_P_HSR : ETH_P_PRP;
		skb->priority = TC_PRIO_CONTROL;
	}
	skb->protocol = htons(proto);
	skb->dev = master->dev;

	if (dev_hard_header(skb, skb->dev, proto,
			    priv->sup_multicast_addr,
			    skb->dev->dev_addr, skb->len) <= 0)
		goto out;
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);

	if (priv->use_vlan_for_sv) {
		vhdr = skb_put(skb, VLAN_HLEN);
		vlan_tci = priv->sv_frame_vid;
		vlan_tci |= (priv->sv_frame_pcp	<< VLAN_PRIO_SHIFT);
		if (priv->sv_frame_dei)
			vlan_tci |= VLAN_CFI_MASK;
		if (!prot_ver)
			proto = ETH_P_PRP;
		else
			proto = (prot_ver == HSR_V1) ? ETH_P_HSR : ETH_P_PRP;
		vhdr->h_vlan_TCI = htons(vlan_tci);
		vhdr->h_vlan_encapsulated_proto = htons(proto);
	}

	if (prot_ver == HSR_V1) {
		hsr_tag = skb_put(skb, sizeof(struct hsr_tag));
		hsr_tag->encap_proto = htons(ETH_P_PRP);
		set_hsr_tag_LSDU_size(hsr_tag, HSR_PRP_V1_SUP_LSDUSIZE);
	}

	hsr_stag = skb_put(skb, sizeof(struct hsr_prp_sup_tag));
	set_hsr_stag_path(hsr_stag, (prot_ver ? 0x0 : 0xf));
	set_hsr_stag_HSR_ver(hsr_stag, prot_ver ? 0x1 : 0x0);

	/* From HSRv1 on we have separate supervision sequence numbers. */
	spin_lock_irqsave(&master->priv->seqnr_lock, irqflags);
	if (prot_ver > 0) {
		hsr_stag->sequence_nr = htons(master->priv->sup_sequence_nr);
		master->priv->sup_sequence_nr++;
		if (prot_ver == HSR_V1) {
			hsr_tag->sequence_nr = htons(priv->sequence_nr);
			priv->sequence_nr++;
		}
	} else {
		hsr_stag->sequence_nr = htons(priv->sequence_nr);
		priv->sequence_nr++;
	}
	spin_unlock_irqrestore(&priv->seqnr_lock, irqflags);

	hsr_stag->HSR_TLV_type = type;
	/* TODO: Why 12 in HSRv0? */
	hsr_stag->HSR_TLV_length = prot_ver ?
		sizeof(struct hsr_prp_sup_payload) : 12;

	/* Payload: mac_address_a */
	hsr_sp = skb_put(skb, sizeof(struct hsr_prp_sup_payload));
	ether_addr_copy(hsr_sp->mac_address_a, master->dev->dev_addr);

	if (!priv->use_vlan_for_sv) {
		if (skb_put_padto(skb, ETH_ZLEN + HSR_PRP_HLEN))
			return;
	} else {
		if (skb_put_padto(skb, ETH_ZLEN + HSR_PRP_HLEN + VLAN_HLEN))
			return;
	}

	spin_lock_irqsave(&priv->seqnr_lock, irqflags);
	if (prot_ver == PRP_V1) {
		tail = skb_tail_pointer(skb) - HSR_PRP_HLEN;
		rct = (struct prp_rct *)tail;
		rct->PRP_suffix = htons(ETH_P_PRP);
		set_prp_LSDU_size(rct, HSR_PRP_V1_SUP_LSDUSIZE);
		rct->sequence_nr = htons(priv->sequence_nr);
		priv->sequence_nr++;
	}
	spin_unlock_irqrestore(&priv->seqnr_lock, irqflags);

	hsr_prp_forward_skb(skb, master);
	INC_CNT_TX_SUP(priv);
	return;

out:
	WARN_ONCE(1, "HSR: Could not send supervision frame\n");
	kfree_skb(skb);
}

/* Announce (supervision frame) timer function
 */
static void hsr_prp_announce(unsigned long data)
{
	struct hsr_prp_priv *priv;
	struct hsr_prp_port *master;

	priv = (struct hsr_prp_priv *)data;

	rcu_read_lock();
	master = hsr_prp_get_port(priv, HSR_PRP_PT_MASTER);

	if (priv->announce_count < 3 && priv->prot_ver == HSR_V0) {
		send_supervision_frame(master, HSR_TLV_ANNOUNCE,
				       priv->prot_ver);
		priv->announce_count++;

		priv->announce_timer.expires = jiffies +
			msecs_to_jiffies(HSR_PRP_ANNOUNCE_INTERVAL);
	} else {
		if (priv->prot_ver <= HSR_V1)
			send_supervision_frame(master, HSR_TLV_LIFE_CHECK,
					       priv->prot_ver);
		else /* PRP */
			send_supervision_frame(master,
					       (priv->dd_mode ==
						IEC62439_3_DD) ?
						PRP_TLV_LIFE_CHECK_DD :
						PRP_TLV_LIFE_CHECK_DA,
						priv->prot_ver);

		priv->announce_timer.expires = jiffies +
			msecs_to_jiffies(HSR_PRP_LIFE_CHECK_INTERVAL);
	}

	if (is_admin_up(master->dev))
		add_timer(&priv->announce_timer);

	rcu_read_unlock();
}

/* According to comments in the declaration of struct net_device, this function
 * is "Called from unregister, can be used to call free_netdev". Ok then...
 */
static void hsr_prp_dev_destroy(struct net_device *hsr_prp_dev)
{
	struct hsr_prp_priv *priv;
	struct hsr_prp_port *port;

	priv = netdev_priv(hsr_prp_dev);

	hsr_prp_remove_procfs(priv, hsr_prp_dev);
	hsr_prp_debugfs_term(priv);
	rtnl_lock();
	hsr_prp_for_each_port(priv, port)
		hsr_prp_del_port(port);
	rtnl_unlock();

	del_timer_sync(&priv->prune_timer);
	del_timer_sync(&priv->announce_timer);

	synchronize_rcu();
}

static void hsr_prp_ndo_set_rx_mode(struct net_device *dev)
{
	struct hsr_prp_port *port_a, *port_b;
	struct hsr_prp_priv *priv;

	priv = netdev_priv(dev);
	rcu_read_lock();
	port_a = hsr_prp_get_port(priv, HSR_PRP_PT_SLAVE_A);
	port_b = hsr_prp_get_port(priv, HSR_PRP_PT_SLAVE_B);

	if (port_a && port_b) {
		dev_mc_sync_multiple(port_a->dev, dev);
		dev_uc_sync_multiple(port_a->dev, dev);
		dev_mc_sync_multiple(port_b->dev, dev);
		dev_uc_sync_multiple(port_b->dev, dev);
	} else {
		netdev_err(dev,
			   "port invalid when doing set_rx_mode\n");
	}
	rcu_read_unlock();
}

static void hsr_prp_change_rx_flags(struct net_device *dev, int change)
{
	struct hsr_prp_port *port_a, *port_b;
	struct hsr_prp_priv *priv;

	priv = netdev_priv(dev);

	rcu_read_lock();
	port_a = hsr_prp_get_port(priv, HSR_PRP_PT_SLAVE_A);
	port_b = hsr_prp_get_port(priv, HSR_PRP_PT_SLAVE_B);

	if (port_a && port_b) {
		if (change & IFF_ALLMULTI) {
			dev_set_allmulti(port_a->dev,
					 dev->flags &
					 IFF_ALLMULTI ? 1 : -1);
			dev_set_allmulti(port_b->dev,
					 dev->flags &
					 IFF_ALLMULTI ? 1 : -1);
		}
	} else {
		netdev_err(dev,
			   "port invalid when doing change_rx_flags\n");
	}
	rcu_read_unlock();
}

static int hsr_prp_add_del_vid(struct net_device *dev,
			       struct hsr_prp_priv *priv, bool add,
			       __be16 proto, u16 vid)
{
	struct hsr_prp_port *port_a, *port_b;
	int ret = 0;

	rcu_read_lock();
	port_a = hsr_prp_get_port(priv, HSR_PRP_PT_SLAVE_A);
	port_b = hsr_prp_get_port(priv, HSR_PRP_PT_SLAVE_B);

	if (!port_a || !port_b) {
		netdev_err(dev, "port invalid when doing add/del vid\n");
		rcu_read_unlock();
		return -ENODEV;
	}

	if (add) {
		ret = vlan_vid_add(port_a->dev, proto, vid);
		if (!ret) {
			ret = vlan_vid_add(port_b->dev, proto, vid);
			if (ret) {
				/* clean up port a */
				netdev_err(dev,
					   "port-b failed for add vid\n");
				vlan_vid_del(port_a->dev, proto, vid);
			}
		} else {
			netdev_err(dev,
				   "port-a failed for add vid\n");
		}
	} else {
		vlan_vid_del(port_a->dev, proto, vid);
		vlan_vid_del(port_b->dev, proto, vid);
	}
	rcu_read_unlock();

	return ret;
}

static int hsr_prp_dev_ioctl(struct net_device *hsr_prp_dev,
			     struct ifreq *req, int cmd)
{
	struct hsr_prp_priv *priv = netdev_priv(hsr_prp_dev);
	struct hsr_prp_port *port;
	const struct net_device_ops *ops;
	int ret = -ENOTSUPP;

	if (cmd != SIOCSHWTSTAMP && cmd != SIOCGHWTSTAMP)
		return ret;

	hsr_prp_for_each_port(priv, port) {
		if (is_slave_port(port)) {
			ops = port->dev->netdev_ops;
			if (ops && ops->ndo_do_ioctl) {
				ret = ops->ndo_do_ioctl(port->dev, req, cmd);

				if (cmd == SIOCGHWTSTAMP || cmd < 0)
					return ret;
			}
		}
	}

	return ret;
}

static int hsr_prp_ndo_vlan_rx_add_vid(struct net_device *dev,
				       __be16 proto, u16 vid)
{
	struct hsr_prp_priv *priv;

	priv = netdev_priv(dev);
	return hsr_prp_add_del_vid(dev, priv, true, proto, vid);
}

static int hsr_prp_ndo_vlan_rx_kill_vid(struct net_device *dev,
					__be16 proto, u16 vid)
{
	struct hsr_prp_priv *priv;

	priv = netdev_priv(dev);
	return hsr_prp_add_del_vid(dev, priv, false, proto, vid);
}

static int hsr_prp_ndo_init(struct net_device *ndev)
{
	netdev_lockdep_set_classes(ndev);
	return 0;
}

static const struct net_device_ops hsr_prp_device_ops = {
	.ndo_init = hsr_prp_ndo_init,
	.ndo_change_mtu = hsr_prp_dev_change_mtu,
	.ndo_open = hsr_prp_dev_open,
	.ndo_stop = hsr_prp_dev_close,
	.ndo_start_xmit = hsr_prp_dev_xmit,
	.ndo_change_rx_flags = hsr_prp_change_rx_flags,
	.ndo_fix_features = hsr_prp_fix_features,
	.ndo_set_rx_mode = hsr_prp_ndo_set_rx_mode,
	.ndo_vlan_rx_add_vid = hsr_prp_ndo_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid = hsr_prp_ndo_vlan_rx_kill_vid,
	.ndo_do_ioctl = hsr_prp_dev_ioctl,
};

static int hsr_prp_get_ts_info(struct net_device *dev,
			       struct ethtool_ts_info *info)
{
	struct hsr_prp_priv *priv = netdev_priv(dev);
	struct hsr_prp_port *port;
	const struct ethtool_ops *ops;
	int ret = -ENOTSUPP;

	hsr_prp_for_each_port(priv, port) {
		if (is_slave_port(port)) {
			ops = port->dev->ethtool_ops;
			if (ops && ops->get_ts_info) {
				ret = ops->get_ts_info(port->dev, info);
				return ret;
			}
		}
	}

	return ret;
}

static int hsr_prp_set_dump(struct net_device *dev, struct ethtool_dump *dump)
{
	struct hsr_prp_priv *priv = netdev_priv(dev);
	struct hsr_prp_port *port;
	const struct ethtool_ops *ops;
	int ret = -ENOTSUPP;

	hsr_prp_for_each_port(priv, port) {
		if (is_slave_port(port)) {
			ops = port->dev->ethtool_ops;
			if (ops && ops->set_dump) {
				ret = ops->set_dump(port->dev, dump);
				if (ret < 0)
					return ret;
			}
		}
	}

	return 0;
}

static const struct ethtool_ops hsr_prp_ethtool_ops = {
	.get_link = ethtool_op_get_link,
	.get_ts_info = hsr_prp_get_ts_info,
	.set_dump = hsr_prp_set_dump,
};

static void hsr_prp_dev_setup(struct net_device *dev, struct device_type *type)
{
	eth_hw_addr_random(dev);

	ether_setup(dev);
	dev->min_mtu = 0;
	dev->header_ops = &hsr_prp_header_ops;
	dev->netdev_ops = &hsr_prp_device_ops;
	dev->ethtool_ops = &hsr_prp_ethtool_ops;
	SET_NETDEV_DEVTYPE(dev, type);
	dev->priv_flags |= IFF_NO_QUEUE;

	dev->needs_free_netdev = true;
	dev->priv_destructor = hsr_prp_dev_destroy;

	dev->hw_features = NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_HIGHDMA |
			   NETIF_F_GSO_MASK | NETIF_F_HW_CSUM |
			   NETIF_F_HW_VLAN_CTAG_TX |
			   NETIF_F_HW_VLAN_CTAG_FILTER;

	dev->features = dev->hw_features;

	/* Prevent recursive tx locking */
	dev->features |= NETIF_F_LLTX;

	/* Not sure about this. Taken from bridge code. netdev_features.h says
	 * it means "Does not change network namespaces".
	 */
	dev->features |= NETIF_F_NETNS_LOCAL;
}

static struct device_type hsr_type = {
	.name = "hsr",
};

void hsr_dev_setup(struct net_device *dev)
{
	hsr_prp_dev_setup(dev, &hsr_type);
}

static struct device_type prp_type = {
	.name = "prp",
};

void prp_dev_setup(struct net_device *dev)
{
	hsr_prp_dev_setup(dev, &prp_type);
}

/* Return true if dev is a HSR master; return false otherwise.
 */
inline bool is_hsr_prp_master(struct net_device *dev)
{
	return (dev->netdev_ops->ndo_start_xmit == hsr_prp_dev_xmit);
}

/* Default multicast address for HSR Supervision frames */
static const unsigned char def_multicast_addr[ETH_ALEN] __aligned(2) = {
	0x01, 0x15, 0x4e, 0x00, 0x01, 0x00
};

int hsr_prp_dev_finalize(struct net_device *hsr_prp_dev,
			 struct net_device *slave[2],
			 unsigned char multicast_spec, u8 protocol_version,
			 bool sv_vlan_tag_needed, unsigned short vid,
			 unsigned char pcp, unsigned char dei)
{
	netdev_features_t mask =
		NETIF_F_HW_PRP_RX_OFFLOAD | NETIF_F_HW_HSR_RX_OFFLOAD;
	struct hsr_prp_priv *priv;
	struct hsr_prp_port *port;
	int res;

	priv = netdev_priv(hsr_prp_dev);
	INIT_LIST_HEAD(&priv->ports);
	INIT_LIST_HEAD(&priv->node_db);
	INIT_LIST_HEAD(&priv->self_node_db);

	ether_addr_copy(hsr_prp_dev->dev_addr, slave[0]->dev_addr);

	/* Make sure we recognize frames from ourselves in hsr_rcv() */
	res = hsr_prp_create_self_node(&priv->self_node_db,
				       hsr_prp_dev->dev_addr,
				       slave[1]->dev_addr);
	if (res < 0)
		return res;

	priv->prot_ver = protocol_version;
	if (priv->prot_ver == PRP_V1) {
		/* For PRP, lan_id has most significant 3 bits holding
		 * the net_id of PRP_LAN_ID and also duplicate discard
		 * mode set.
		 */
		priv->net_id = PRP_LAN_ID << 1;
		priv->dd_mode = IEC62439_3_DD;
	} else {
		priv->hsr_mode = IEC62439_3_HSR_MODE_H;
	}

	spin_lock_init(&priv->seqnr_lock);
	/* Overflow soon to find bugs easier: */
	priv->sequence_nr = HSR_PRP_SEQNR_START;
	priv->sup_sequence_nr = HSR_PRP_SUP_SEQNR_START;

	setup_timer(&priv->announce_timer, hsr_prp_announce,
		    (unsigned long)priv);

	if (!priv->rx_offloaded)
		setup_timer(&priv->prune_timer, hsr_prp_prune_nodes,
			    (unsigned long)priv);

	ether_addr_copy(priv->sup_multicast_addr, def_multicast_addr);
	priv->sup_multicast_addr[ETH_ALEN - 1] = multicast_spec;
	/* update vlan tag infor for SV frames */
	priv->use_vlan_for_sv = sv_vlan_tag_needed;
	priv->sv_frame_vid = vid;
	priv->sv_frame_dei = dei;
	priv->sv_frame_pcp = pcp;

	/* FIXME: should I modify the value of these?
	 *
	 * - hsr_prp_dev->flags - i.e.
	 *			IFF_MASTER/SLAVE?
	 * - hsr_prp_dev->priv_flags - i.e.
	 *			IFF_EBRIDGE?
	 *			IFF_TX_SKB_SHARING?
	 *			IFF_HSR_MASTER/SLAVE?
	 */

	/* Make sure the 1st call to netif_carrier_on() gets through */
	netif_carrier_off(hsr_prp_dev);

	res = hsr_prp_add_port(priv, hsr_prp_dev, HSR_PRP_PT_MASTER);
	if (res)
		return res;

	if (priv->prot_ver == PRP_V1) {
		if ((slave[0]->features & NETIF_F_HW_HSR_RX_OFFLOAD) ||
		    (slave[1]->features & NETIF_F_HW_HSR_RX_OFFLOAD)) {
			res = -EINVAL;
			goto fail;
		}
	} else {
		if ((slave[0]->features & NETIF_F_HW_PRP_RX_OFFLOAD) ||
		    (slave[1]->features & NETIF_F_HW_PRP_RX_OFFLOAD)) {
			res = -EINVAL;
			goto fail;
		}
	}

	/* HSR/PRP LRE Rx offload supported in lower device? */
	if (((slave[0]->features & NETIF_F_HW_HSR_RX_OFFLOAD) &&
	     (slave[1]->features & NETIF_F_HW_HSR_RX_OFFLOAD)) ||
	     ((slave[0]->features & NETIF_F_HW_PRP_RX_OFFLOAD) &&
	     (slave[1]->features & NETIF_F_HW_PRP_RX_OFFLOAD)))
		priv->rx_offloaded = true;

	/* Make sure offload flags match in the slave devices */
	if ((slave[0]->features & mask) ^ (slave[1]->features & mask)) {
		res = -EINVAL;
		goto fail;
	}

	/* HSR LRE L2 forward offload supported in lower device for hsr? */
	if ((priv->prot_ver < PRP_V1) &&
	    ((slave[0]->features & NETIF_F_HW_L2FW_DOFFLOAD) &&
	     (slave[1]->features & NETIF_F_HW_L2FW_DOFFLOAD)))
		priv->l2_fwd_offloaded = true;

	hsr_prp_dev->features |= NETIF_F_HW_VLAN_CTAG_FILTER;
	res = register_netdevice(hsr_prp_dev);
	if (res)
		goto fail;

	res = hsr_prp_add_port(priv, slave[0], HSR_PRP_PT_SLAVE_A);
	if (res)
		goto fail;
	res = hsr_prp_add_port(priv, slave[1], HSR_PRP_PT_SLAVE_B);
	if (res)
		goto fail;

	/* For LRE rx offload, pruning is expected to happen
	 * at the hardware or firmware . So don't do this in software
	 */
	if (!priv->rx_offloaded)
		mod_timer(&priv->prune_timer,
			  jiffies + msecs_to_jiffies(HSR_PRP_PRUNE_PERIOD));
	/* for offloaded case, expect both slaves have the
	 * same MAC address configured. If not fail.
	 */
	if (priv->rx_offloaded &&
	    !ether_addr_equal(slave[0]->dev_addr,
			      slave[1]->dev_addr))
		goto fail;

	res = hsr_prp_create_procfs(priv, hsr_prp_dev);
	if (res)
		goto fail;

	res = hsr_prp_debugfs_init(priv, hsr_prp_dev);
	if (res)
		goto fail_procfs;

	if (priv->use_vlan_for_sv)
		res = hsr_prp_set_sv_frame_vid(priv, priv->sv_frame_vid);

	if (res)
		goto fail_procfs;

	return 0;

fail_procfs:
	hsr_prp_remove_procfs(priv, hsr_prp_dev);
fail:
	hsr_prp_for_each_port(priv, port)
		hsr_prp_del_port(port);

	return res;
}
