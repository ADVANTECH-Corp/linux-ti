/*
 * PRU IEP Driver
 *
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
#ifndef _TI_IEP_H_
#define _TI_IEP_H_

#include <linux/clk.h>
#include <linux/clkdev.h>
#include <linux/clocksource.h>
#include <linux/device.h>
#include <linux/list.h>
#include <linux/of.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/skbuff.h>
#include <linux/timecounter.h>

#define IEP_SYNC_EN                  BIT(0)
#define IEP_SYNC0_EN                 BIT(1)
#define IEP_SYNC1_EN                 BIT(2)
#define IEP_SYNC1_IND_EN             BIT(8)
#define IEP_CMP1_EN                  BIT(2)
#define IEP_CMP1_HIT                 BIT(1)

/* IEP reg offsets (32 bit IEP - IEP_REV_V1_0) */
#define PRUSS_IEP32_GLOBAL_CFG         0x00
#define PRUSS_IEP32_COMPENSATION       0x08
#define PRUSS_IEP32_COUNT_REG0         0x0C
#define PRUSS_IEP32_CAPTURE_CFG_REG    0x10
#define PRUSS_IEP32_CAPTURE_STAT_REG   0x14

#define PRUSS_IEP32_CAP6_RISE_REG0     0x30
#define PRUSS_IEP32_CAP6_FALL_REG0     0x34

#define PRUSS_IEP32_CAP7_RISE_REG0     0x38
#define PRUSS_IEP32_CAP7_FALL_REG0     0x3C

#define PRUSS_IEP32_CMP_CFG_REG        0x40
#define PRUSS_IEP32_CMP_STAT_REG       0x44
#define PRUSS_IEP32_CMP0_REG0          0x48

#define PRUSS_IEP32_CMP8_REG0          0x88
#define PRUSS_IEP32_SYNC_CTRL_REG      0x100
#define PRUSS_IEP32_SYNC0_STAT_REG     0x108
#define PRUSS_IEP32_SYNC1_STAT_REG     0x10C
#define PRUSS_IEP32_SYNC_PWIDTH_REG    0x110
#define PRUSS_IEP32_SYNC0_PERIOD_REG   0x114
#define PRUSS_IEP32_SYNC1_DELAY_REG    0x118
#define PRUSS_IEP32_SYNC_START_REG     0x11C

/* IEP reg offsets ( 64 bit IEP - IEP_REV_V2_1) */
#define PRUSS_IEP64_GLOBAL_CFG         0x00
#define PRUSS_IEP64_COMPENSATION       0x08
#define PRUSS_IEP64_SLOW_COMPENSATION  0x0C
#define PRUSS_IEP64_COUNT_REG0         0x10
#define PRUSS_IEP64_COUNT_REG1         0x14
#define PRUSS_IEP64_CAPTURE_CFG_REG    0x18
#define PRUSS_IEP64_CAPTURE_STAT_REG   0x1c

#define PRUSS_IEP64_CAP6_RISE_REG0     0x50
#define PRUSS_IEP64_CAP6_RISE_REG1     0x54
#define PRUSS_IEP64_CAP6_FALL_REG0     0x58
#define PRUSS_IEP64_CAP6_FALL_REG1     0x5c

#define PRUSS_IEP64_CAP7_RISE_REG0     0x60
#define PRUSS_IEP64_CAP7_RISE_REG1     0x64
#define PRUSS_IEP64_CAP7_FALL_REG0     0x68
#define PRUSS_IEP64_CAP7_FALL_REG1     0x6c

#define PRUSS_IEP64_CMP_CFG_REG        0x70
#define PRUSS_IEP64_CMP_STAT_REG       0x74
#define PRUSS_IEP64_CMP0_REG0          0x78
#define PRUSS_IEP64_CMP0_REG1          0x7c

#define PRUSS_IEP64_CMP8_REG0          0xc0
#define PRUSS_IEP64_CMP8_REG1          0xc4
#define PRUSS_IEP64_SYNC_CTRL_REG      0x180
#define PRUSS_IEP64_SYNC0_STAT_REG     0x188
#define PRUSS_IEP64_SYNC1_STAT_REG     0x18c
#define PRUSS_IEP64_SYNC_PWIDTH_REG    0x190
#define PRUSS_IEP64_SYNC0_PERIOD_REG   0x194
#define PRUSS_IEP64_SYNC1_DELAY_REG    0x198
#define PRUSS_IEP64_SYNC_START_REG     0x19c


#define PRUSS_IEP_CMP_INC_MASK       0xfff00
#define PRUSS_IEP_CMP_INC_SHIFT      8

#define PRUSS_IEP_DEFAULT_INC        5
#define PRUSS_IEP_DEFAULT_CMP_INC    5
#define PRUSS_IEP_CLOCK_RATE         200000000

#define IEP_TC_DEFAULT_SHIFT         28
#define IEP_TC_INCR5_MULT            (1 << IEP_TC_DEFAULT_SHIFT)
#define IEP_TC_INCR1_MULT            (5 << IEP_TC_DEFAULT_SHIFT)

#define IEP_GLOBAL_CFG_REG_MASK      0xfffff
#define IEP_GLOBAL_CFG_REG_INCR1_VAL	0x111
#define IEP_GLOBAL_CFG_REG_INCR5_VAL	0x551

/* 10 ms width */
#define IEP_DEFAULT_PPS_WIDTH        (PRUSS_IEP_CLOCK_RATE / 100)

/* 1ms pulse sync interval */
#define PULSE_SYNC_INTERVAL          1000000
#define TIMESYNC_SECONDS_COUNT_SIZE  6
#define PTP_TWO_STEP_ENABLE          1
#define TIMESYNC_ENABLE              1

#define IEP_PPS_EXTERNAL             1
#define IEP_PPS_INTERNAL             0
#define MAX_PPS                      2
#define MAX_EXTTS                    2

enum iep_revision {
	IEP_REV_V1_0 = 0,
	IEP_REV_V2_1
};

struct pps {
	struct pinctrl_state *pin_on;
	struct pinctrl_state *pin_off;
	int enable;
	int offset;
	int next_op;
	enum {
		OP_DISABLE_SYNC,
		OP_ENABLE_SYNC,
	} report_ops[4];
};

struct extts {
	struct pinctrl_state *pin_on;
	struct pinctrl_state *pin_off;
};

struct iep_regs_ofs {
	u32 global_cfg;
	u32 compensation;
	u32 count_reg;
	u32 capture_cfg_reg;
	u32 capture_stat_reg;

	u32 cap6_rise_reg;
	u32 cap6_fall_reg;
	u32 cap7_rise_reg;
	u32 cap7_fall_reg;

	u32 cmp_cfg_reg;
	u32 cmp_stat_reg;
	u32 cmp0_reg;

	u32 cmp8_reg;
	u32 sync_ctrl_reg;
	u32 sync0_stat_reg;
	u32 sync1_stat_reg;
	u32 sync_pwidth_reg;
	u32 sync0_period_reg;
	u32 sync1_delay_reg;
	u32 sync_start_reg;
};

struct iep {
	struct device *dev;
	void __iomem *sram;
	void __iomem *iep_reg;
	struct ptp_clock_info info;
	struct ptp_clock *ptp_clock;
	int phc_index;
	int ptp_tx_enable;
	int ptp_rx_enable;
	spinlock_t ptp_lock; /* serialize iep access */
	u32 cc_mult; /* for the nominal frequency */
	struct cyclecounter cc;
	struct timecounter tc;
	unsigned long ov_check_period;
	unsigned long ov_check_period_slow;
	struct pps pps[MAX_PPS];
	u32 latch_enable;
	int rev;
	struct iep_regs_ofs reg_ofs;

	int bc_clkid;
	int pruss_id;
	bool bc_pps_sync;
	struct pinctrl *pins;
	struct extts extts[MAX_EXTTS];

	u64 (*iep_get_count)(struct iep *iep);
	u64 (*iep_get_cmp)(struct iep *iep, int cmp);
	void (*iep_set_cmp)(struct iep *iep, int cmp, u64 v);
	u64 (*iep_get_timestamp_cycles)(struct iep *iep, u16 ts_ofs);
};

void iep_reset_timestamp(struct iep *iep, u16 ts_ofs);
int iep_rx_timestamp(struct iep *iep, u16 ts_ofs, struct sk_buff *skb);
int iep_tx_timestamp(struct iep *iep, u16 ts_ofs, struct sk_buff *skb,
		     unsigned long tmo);
int iep_register(struct iep *iep);
void iep_unregister(struct iep *iep);
struct iep *iep_create(struct device *dev, void __iomem *sram,
		       void __iomem *iep_reg, int pruss_id, int rev);
void iep_release(struct iep *iep);
int iep_get_timestamp(struct iep *iep, u16 ts_ofs, u64 *ns);
#endif
