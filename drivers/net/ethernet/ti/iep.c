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
#include "icss_time_sync.h"
#include "iep.h"
#include "ptp_bc.h"

#define PPS_CMP(pps)        ((pps) + 1)
#define PPS_SYNC(pps)       (pps)
#define LATCHX_CAP(x)       ((x) + 6)

#define IEP_CMPX_EN(cmp)    BIT((cmp) + 1)
#define IEP_SYNCX_EN(sync)  BIT((sync) + 1)
#define IEP_CMPX_HIT(cmp)   BIT(cmp)

#define IEP_CAP6R_1ST_EV_EN BIT(6)
#define IEP_CAP6F_1ST_EV_EN BIT(7)
#define IEP_CAP7R_1ST_EV_EN BIT(8)
#define IEP_CAP7F_1ST_EV_EN BIT(9)
#define IEP_CAP6_ASYNC_EN   BIT(16)
#define IEP_CAP7_ASYNC_EN   BIT(17)

#define IEP_CAP6_EV_EN     (IEP_CAP6_ASYNC_EN | IEP_CAP6R_1ST_EV_EN)
#define IEP_CAP7_EV_EN     (IEP_CAP7_ASYNC_EN | IEP_CAP7R_1ST_EV_EN)

#define IEP_CAPR6_VALID     BIT(6)
#define IEP_CAPR7_VALID     BIT(8)
#define LATCHX_VALID(x)     (x ? IEP_CAPR7_VALID : IEP_CAPR6_VALID)

#define SYNC0_RESET    (0x030 | IEP_SYNC0_EN)
#define SYNC1_RESET    (0x0c0 | IEP_SYNC1_EN)
#define SYNCX_RESET(x) (x ? SYNC1_RESET : SYNC0_RESET)

#define PRUSS_IEP32_REG_SIZE    4
#define PRUSS_IEP64_REG_SIZE    8
#define PRUSS_IEP32_CMP_REG0_OFFSET(c)                  \
	((c) < 8 ? (PRUSS_IEP32_CMP0_REG0 + (c) * PRUSS_IEP32_REG_SIZE) :  \
		 (PRUSS_IEP32_CMP8_REG0 + ((c) - 8) * PRUSS_IEP32_REG_SIZE))
#define PRUSS_IEP64_CMP_REG0_OFFSET(c)                  \
	((c) < 8 ? (PRUSS_IEP64_CMP0_REG0 + (c) * PRUSS_IEP64_REG_SIZE) :  \
		 (PRUSS_IEP64_CMP8_REG0 + ((c) - 8) * PRUSS_IEP64_REG_SIZE))

/* Polling period - how often iep_overflow_check() is called */
#define IEP_OVERFLOW_CHECK_PERIOD_MS   50
/* Range during which SYNC reset occurs - should be greater than
 * IEP_OVERFLOW_CHECK_PERIOD_MS to ensure at least one check is caught
 */
#define IEP32_WRAPAROUND_SYNC_TIME_MS  80
#define IEP32_WRAPAROUND_SYNC_TIME_NS  (IEP32_WRAPAROUND_SYNC_TIME_MS * 1000000)

struct iep_regs_ofs iep_regs_ofs_v1_0 = {
	.global_cfg = PRUSS_IEP32_GLOBAL_CFG,
	.compensation = PRUSS_IEP32_COMPENSATION,
	.count_reg = PRUSS_IEP32_COUNT_REG0,
	.capture_cfg_reg = PRUSS_IEP32_CAPTURE_CFG_REG,
	.capture_stat_reg = PRUSS_IEP32_CAPTURE_STAT_REG,

	.cap6_rise_reg = PRUSS_IEP32_CAP6_RISE_REG0,
	.cap6_fall_reg = PRUSS_IEP32_CAP6_FALL_REG0,

	.cap7_rise_reg = PRUSS_IEP32_CAP7_RISE_REG0,
	.cap7_fall_reg = PRUSS_IEP32_CAP7_FALL_REG0,

	.cmp_cfg_reg = PRUSS_IEP32_CMP_CFG_REG,
	.cmp_stat_reg = PRUSS_IEP32_CMP_STAT_REG,
	.cmp0_reg = PRUSS_IEP32_CMP0_REG0,

	.cmp8_reg = PRUSS_IEP32_CMP8_REG0,
	.sync_ctrl_reg = PRUSS_IEP32_SYNC_CTRL_REG,
	.sync0_stat_reg = PRUSS_IEP32_SYNC0_STAT_REG,
	.sync1_stat_reg = PRUSS_IEP32_SYNC1_STAT_REG,
	.sync_pwidth_reg = PRUSS_IEP32_SYNC_PWIDTH_REG,
	.sync0_period_reg = PRUSS_IEP32_SYNC0_PERIOD_REG,
	.sync1_delay_reg = PRUSS_IEP32_SYNC1_DELAY_REG,
	.sync_start_reg = PRUSS_IEP32_SYNC_START_REG
};

struct iep_regs_ofs iep_regs_ofs_v2_1 = {
	.global_cfg = PRUSS_IEP64_GLOBAL_CFG,
	.compensation = PRUSS_IEP64_COMPENSATION,
	.count_reg = PRUSS_IEP64_COUNT_REG0,
	.capture_cfg_reg = PRUSS_IEP64_CAPTURE_CFG_REG,
	.capture_stat_reg = PRUSS_IEP64_CAPTURE_STAT_REG,

	.cap6_rise_reg = PRUSS_IEP64_CAP6_RISE_REG0,
	.cap6_fall_reg = PRUSS_IEP64_CAP6_FALL_REG0,

	.cap7_rise_reg = PRUSS_IEP64_CAP7_RISE_REG0,
	.cap7_fall_reg = PRUSS_IEP64_CAP7_FALL_REG0,

	.cmp_cfg_reg = PRUSS_IEP64_CMP_CFG_REG,
	.cmp_stat_reg = PRUSS_IEP64_CMP_STAT_REG,
	.cmp0_reg = PRUSS_IEP64_CMP0_REG0,

	.cmp8_reg = PRUSS_IEP64_CMP8_REG0,
	.sync_ctrl_reg = PRUSS_IEP64_SYNC_CTRL_REG,
	.sync0_stat_reg = PRUSS_IEP64_SYNC0_STAT_REG,
	.sync1_stat_reg = PRUSS_IEP64_SYNC1_STAT_REG,
	.sync_pwidth_reg = PRUSS_IEP64_SYNC_PWIDTH_REG,
	.sync0_period_reg = PRUSS_IEP64_SYNC0_PERIOD_REG,
	.sync1_delay_reg = PRUSS_IEP64_SYNC1_DELAY_REG,
	.sync_start_reg = PRUSS_IEP64_SYNC_START_REG
};

static inline u32 iep_read_reg(struct iep *iep, unsigned int reg)
{
	return readl_relaxed(iep->iep_reg + reg);
}

static inline void iep_write_reg(struct iep *iep, unsigned int reg, u32 val)
{
	writel_relaxed(val, iep->iep_reg + reg);
}

static inline
void iep_set_reg(struct iep *iep, unsigned int reg, u32 mask, u32 set)
{
	u32 val;

	val = iep_read_reg(iep, reg);
	val &= ~mask;
	val |= (set & mask);
	iep_write_reg(iep, reg, val);
}

static inline void iep_disable_sync(struct iep *iep, int sync)
{
	u32 sync_ctrl;

	/* disable syncX */
	sync_ctrl = iep_read_reg(iep, iep->reg_ofs.sync_ctrl_reg);
	sync_ctrl &= ~SYNCX_RESET(sync);

	if (!(sync_ctrl & (IEP_SYNC0_EN | IEP_SYNC1_EN)))
		sync_ctrl &= ~IEP_SYNC_EN;

	iep_write_reg(iep, iep->reg_ofs.sync_ctrl_reg, sync_ctrl);

	/* clear syncX status: Wr1Clr */
	if (sync > 0)
		iep_write_reg(iep, iep->reg_ofs.sync1_stat_reg, 1);
	else
		iep_write_reg(iep, iep->reg_ofs.sync0_stat_reg, 1);
}

static inline void iep_enable_sync(struct iep *iep, int sync)
{
	/* enable syncX 1-shot mode */
	iep_write_reg(iep, iep->reg_ofs.sync_ctrl_reg,
		      IEP_SYNCX_EN(sync) | IEP_SYNC_EN);
}

/* 0 <= cmp <= 15 */
static inline u64 iep_get_cmp32(struct iep *iep, int cmp)
{
	u32 v;

	memcpy_fromio(&v, iep->iep_reg + PRUSS_IEP32_CMP_REG0_OFFSET(cmp),
		      sizeof(v));
	return (u64)v;
}

/* 0 <= cmp <= 15 */
static inline u64 iep_get_cmp64(struct iep *iep, int cmp)
{
	u64 v;

	memcpy_fromio(&v, iep->iep_reg + PRUSS_IEP64_CMP_REG0_OFFSET(cmp),
		      sizeof(v));
	return v;
}

/* 0 <= cmp <= 15 */
static inline void iep_set_cmp32(struct iep *iep, int cmp, u64 v)
{
	u32 v32 = v;

	memcpy_toio(iep->iep_reg + PRUSS_IEP32_CMP_REG0_OFFSET(cmp),
		    &v32, sizeof(v32));
}

/* 0 <= cmp <= 15 */
static inline void iep_set_cmp64(struct iep *iep, int cmp, u64 v)
{
	memcpy_toio(iep->iep_reg + PRUSS_IEP64_CMP_REG0_OFFSET(cmp),
		    &v, sizeof(v));
}

static inline void iep_disable_cmp(struct iep *iep, int cmp)
{
	u32 v;

	/* disable CMPX */
	v = iep_read_reg(iep, iep->reg_ofs.cmp_cfg_reg);
	v &= ~IEP_CMPX_EN(cmp);
	iep_write_reg(iep, iep->reg_ofs.cmp_cfg_reg, v);

	/* clear CMPX status: Wr1Clr */
	iep_write_reg(iep, iep->reg_ofs.cmp_stat_reg, IEP_CMPX_HIT(cmp));
}

static inline void iep_enable_cmp(struct iep *iep, int cmp)
{
	u32 v;

	/* enable CMP1 */
	v = iep_read_reg(iep, iep->reg_ofs.cmp_cfg_reg);
	v |= IEP_CMPX_EN(cmp);
	iep_write_reg(iep, iep->reg_ofs.cmp_cfg_reg, v);
}

/* 0 <= latch <= 1 */
static inline void iep_enable_latch(struct iep *iep, unsigned int latch)
{
	u32 v;

	/* enable capture 6/7 in 1st event mode */
	v = iep_read_reg(iep, iep->reg_ofs.capture_cfg_reg);
	v |= (latch ? IEP_CAP7_EV_EN : IEP_CAP6_EV_EN);
	iep_write_reg(iep, iep->reg_ofs.capture_cfg_reg, v);
}

/* 0 <= latch <= 1 */
static inline void iep_disable_latch(struct iep *iep, unsigned int latch)
{
	u32 v;

	v = iep_read_reg(iep, iep->reg_ofs.capture_cfg_reg);
	v &= ~(latch ? IEP_CAP7_EV_EN : IEP_CAP6_EV_EN);
	iep_write_reg(iep, iep->reg_ofs.capture_cfg_reg, v);
}

static inline u32 iep_get_latch_status(struct iep *iep)
{
	return iep_read_reg(iep, iep->reg_ofs.capture_stat_reg);
}

/* 0 <= latch <= 1 */
static inline u64 iep_get_latch_ts(struct iep *iep, unsigned int latch)
{
	u64 v;
	u32 cap_reg = (latch ?
		       iep->reg_ofs.cap6_rise_reg :
		       iep->reg_ofs.cap6_rise_reg);

	memcpy_fromio(&v, iep->iep_reg + cap_reg, sizeof(v));
	return v;
}

static inline u64 iep_get_count32(struct iep *iep)
{
	u32 v_ns = 0;
	u64 v_sec = 0;
	u64 v = 0;
	void __iomem *sram = iep->sram;

	memcpy_fromio(&v_ns, iep->iep_reg + iep->reg_ofs.count_reg, 4);
	memcpy_fromio(&v_sec, sram + TIMESYNC_SECONDS_COUNT_OFFSET,
		      TIMESYNC_SECONDS_COUNT_SIZE);
	v = (v_sec * NSEC_PER_SEC) + v_ns;

	return v;
}

static inline u64 iep_get_count64(struct iep *iep)
{
	u64 v = 0;

	memcpy_fromio(&v, iep->iep_reg + iep->reg_ofs.count_reg, 8);

	return v;
}

static u64 iep_cc_read(const struct cyclecounter *cc)
{
	struct iep *iep = container_of(cc, struct iep, cc);

	return iep->iep_get_count(iep);
}

/* Implementation is good for 1 sec or less */
static u64 iep_ns2cyc(struct iep *iep, u64 nsec)
{
	u64 dividend, cycles;

	WARN_ON(nsec > 1000000000ULL);

	dividend = nsec << iep->cc.shift;
	cycles = div_u64(dividend, iep->cc.mult);
	return cycles;
}

static int iep_adjfreq(struct ptp_clock_info *ptp, s32 ppb)
{
	struct iep *iep = container_of(ptp, struct iep, info);
	u64 adj;
	u32 diff, mult, v;
	int neg_adj = 0;
	unsigned long flags;
	struct timespec64 ts;
	u64 ns_to_sec, cyc_to_sec, cmp_val, rem;

	if (ppb < 0) {
		neg_adj = 1;
		ppb = -ppb;
	}
	mult = iep->cc_mult;
	adj = mult;
	adj *= ppb;
	diff = div_u64(adj, 1000000000ULL);

	spin_lock_irqsave(&iep->ptp_lock, flags);

	ts = ns_to_timespec64(timecounter_read(&iep->tc));

	iep->cc.mult = neg_adj ? mult - diff : mult + diff;

	/* if at least one of the pps is enabled, update cmp accordingly. */
	if ((iep->pps[0].enable == 1) || (iep->pps[1].enable == 1)) {
		ns_to_sec = NSEC_PER_SEC - ts.tv_nsec;
		ns_to_sec += iep->pps[0].offset;
		cyc_to_sec = iep_ns2cyc(iep, ns_to_sec);

		/* +++TODO: fine tune the randomly fixed 10 ticks */
		/* if it's too late to update CMP1, skip it */
		if (cyc_to_sec >= 10) {
			cmp_val = iep->tc.cycle_last + cyc_to_sec;

			if (iep->rev == IEP_REV_V1_0) {
				if (cmp_val > NSEC_PER_SEC) {
					rem = do_div(cmp_val, NSEC_PER_SEC);
					cmp_val = rem;
				}
			}

			/* if the previous HIT is not reported yet,
			 * skip update
			 */
			v = iep_read_reg(iep, iep->reg_ofs.cmp_stat_reg);

			if ((iep->pps[0].enable != -1) &&
			    !(v & IEP_CMPX_HIT(PPS_CMP(0))))
				iep->iep_set_cmp(iep, PPS_CMP(0), cmp_val);

			if ((iep->pps[1].enable != -1) &&
			    !(v & IEP_CMPX_HIT(PPS_CMP(1))))
				iep->iep_set_cmp(iep, PPS_CMP(1), cmp_val);
		}
	}

	spin_unlock_irqrestore(&iep->ptp_lock, flags);

	return 0;
}

static int iep_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	struct iep *iep = container_of(ptp, struct iep, info);
	unsigned long flags;

	spin_lock_irqsave(&iep->ptp_lock, flags);
	timecounter_adjtime(&iep->tc, delta);
	spin_unlock_irqrestore(&iep->ptp_lock, flags);

	return 0;
}

static int iep_gettime(struct ptp_clock_info *ptp, struct timespec64 *ts)
{
	struct iep *iep = container_of(ptp, struct iep, info);
	unsigned long flags;
	u64 ns;

	spin_lock_irqsave(&iep->ptp_lock, flags);
	ns = timecounter_read(&iep->tc);
	spin_unlock_irqrestore(&iep->ptp_lock, flags);

	*ts = ns_to_timespec64(ns);

	return 0;
}

static int iep_settime(struct ptp_clock_info *ptp, const struct timespec64 *ts)
{
	struct iep *iep = container_of(ptp, struct iep, info);
	unsigned long flags;
	u64 ns;

	ns = timespec64_to_ns(ts);

	spin_lock_irqsave(&iep->ptp_lock, flags);
	timecounter_init(&iep->tc, &iep->cc, ns);
	spin_unlock_irqrestore(&iep->ptp_lock, flags);

	return 0;
}

/* PPS */
static void iep_pps_pins_off(struct iep *iep)
{
	int i;

	for (i = 0; i < MAX_PPS; i++) {
		if (iep->pps[i].pin_off)
			pinctrl_select_state(iep->pins, iep->pps[i].pin_off);
	}
}

/* Stop pps:
 *   disable sync
 *   disable cmp
 *   clear sync and cmp status
 *   reset cmp reg val
 */
static inline void iep_pps_stop(struct iep *iep, unsigned int pps)
{
	iep_disable_sync(iep, PPS_SYNC(pps));
	iep_disable_cmp(iep, PPS_CMP(pps));
	iep->iep_set_cmp(iep, PPS_CMP(pps), 0);
}

/* 0 <= pps <= 1 */
static inline void iep_pps_start(struct iep *iep, unsigned int pps)
{
	iep_enable_sync(iep, PPS_SYNC(pps));
	iep_enable_cmp(iep, PPS_CMP(pps));
}

/* 0 <= pps <= 1 */
static int iep_pps_enable(struct iep *iep, unsigned int pps, int on)
{
	unsigned long flags;
	struct timespec64 ts;
	u64 cyc_to_sec_bd, ns_to_sec_bd, cyc_per_sec, cyc_last2, cmp_val, rem;
	int *pps_en;

	if (pps >= MAX_PPS)
		return -EINVAL;

	pps_en = &iep->pps[pps].enable;

	on = (on ? 1 : 0);

	if (on && *pps_en == 1) {
		/* enable: pps is already on */
		return 0;
	} else if (on && *pps_en == 0) {
		/* enable: pps is stopping but not yet stopped,
		 * so just turn it back on and return
		 */
		*pps_en = on;
		return 0;
	} else if (on && *pps_en == -1) {
		/* enable: pps is currently off
		 * turn it on and enable cmp etc.
		 */
		*pps_en = on;
	} else if (!on && *pps_en == 1) {
		/* disable: pps is currently on
		 * just set stop and return
		 * pps will stop in next pps report check
		 */
		*pps_en = on;
		return 0;
	} else if (!on && *pps_en != 1) {
		/* disable: pps is already stoppig or stopped
		 * no change, just return
		 */
		return 0;
	}

	/* Start the requested pps */
	/* get current time and counter value */
	iep_gettime(&iep->info, &ts);

	spin_lock_irqsave(&iep->ptp_lock, flags);

	/* current iep ticks per sec */
	cyc_per_sec = iep_ns2cyc(iep, NSEC_PER_SEC);

	/* align cmp count to next sec boundary */
	ns_to_sec_bd = NSEC_PER_SEC - ts.tv_nsec;
	ns_to_sec_bd += iep->pps[pps].offset;
	cyc_to_sec_bd = iep_ns2cyc(iep, ns_to_sec_bd);
	cmp_val = iep->tc.cycle_last + cyc_to_sec_bd;

	/* how many ticks has elapsed since last time */
	cyc_last2 = (u64)iep->iep_get_count(iep);

	/* if it is too close to sec boundary, start 1 sec later */
	/* +++TODO: tune this randomly fixed 10 ticks allowance */
	if (cmp_val <= cyc_last2 + 10)
		cmp_val += cyc_per_sec;

	if (iep->rev == IEP_REV_V1_0) {
		if (cmp_val > NSEC_PER_SEC) {
			rem = do_div(cmp_val, NSEC_PER_SEC);
			cmp_val = rem;
		}
	}

	pinctrl_select_state(iep->pins, iep->pps[pps].pin_on);
	iep->iep_set_cmp(iep, PPS_CMP(pps), cmp_val);
	iep_pps_start(iep, pps);

	spin_unlock_irqrestore(&iep->ptp_lock, flags);
	return 0;
}

/* One time configs
 *   pulse width
 *   sync start
 *   sync0 period
 *   sync/latch pin-mux
 *   some private vars
 */
static int iep_pps_init(struct iep *iep)
{
	u32 i;

	/* Following are one time configurations */

	/* config sync0/1 pulse width to 10 ms, ie 2000000 cycles */
	iep_write_reg(iep, iep->reg_ofs.sync_pwidth_reg, IEP_DEFAULT_PPS_WIDTH);

	/* set SYNC start to 0, ie., no delay after activation. */
	iep_write_reg(iep, iep->reg_ofs.sync_start_reg, 0);

	/* makes sure SYNC0 period is 0 */
	iep_write_reg(iep, iep->reg_ofs.sync0_period_reg, 0);

	/* set sync1 to independent mode */
	iep_write_reg(iep, iep->reg_ofs.sync_ctrl_reg, IEP_SYNC1_IND_EN);

	/* makes sure SYNC1 period is 0.
	 * when sync1 is independent mode, SYNC1_DELAY_REG
	 * val is SYNC1 period.
	 */
	iep_write_reg(iep, iep->reg_ofs.sync1_delay_reg, 0);

	for (i = 0; i < MAX_PPS; i++) {
		iep->pps[i].enable = -1;
		iep->pps[i].next_op = -1;
	}

	return 0;
}

/* EXTTS */
static void iep_extts_pins_off(struct iep *iep)
{
	int i;

	for (i = 0; i < MAX_EXTTS; i++) {
		if (iep->extts[i].pin_off)
			pinctrl_select_state(iep->pins, iep->extts[i].pin_off);
	}
}

static int iep_extts_enable(struct iep *iep, u32 index, int on)
{
	unsigned long flags;

	if (index >= iep->info.n_ext_ts)
		return -ENXIO;

	if (((iep->latch_enable & BIT(index)) >> index) == on)
		return 0;

	spin_lock_irqsave(&iep->ptp_lock, flags);

	if (on) {
		pinctrl_select_state(iep->pins, iep->extts[index].pin_on);
		iep_enable_latch(iep, index);
		iep->latch_enable |= BIT(index);
	} else {
		pinctrl_select_state(iep->pins, iep->extts[index].pin_off);
		iep_disable_latch(iep, index);
		iep->latch_enable &= ~BIT(index);
	}

	spin_unlock_irqrestore(&iep->ptp_lock, flags);
	return 0;
}

static int iep_ptp_feature_enable(struct ptp_clock_info *ptp,
				  struct ptp_clock_request *rq, int on)
{
	struct iep *iep = container_of(ptp, struct iep, info);
	struct timespec64 ts;
	s64 ns;
	bool ok;

	switch (rq->type) {
	case PTP_CLK_REQ_EXTTS:
		return iep_extts_enable(iep, rq->extts.index, on);
	case PTP_CLK_REQ_PPS:
		/* command line only enables the one for internal sync */
		if (iep->bc_pps_sync) {
			ok = ptp_bc_clock_sync_enable(iep->bc_clkid, on);
			if (!ok) {
				pr_info("iep error: bc clk sync pps enable denied\n");
				return -EBUSY;
			}
		}
		return iep_pps_enable(iep, IEP_PPS_INTERNAL, on);
	case PTP_CLK_REQ_PEROUT:
		/* this enables a pps for external measurement */
		if (rq->perout.index != 0)
			return -EINVAL;

		if (on) {
			ts.tv_sec = rq->perout.period.sec;
			ts.tv_nsec = rq->perout.period.nsec;
			ns = timespec64_to_ns(&ts);
			if (ns != NSEC_PER_SEC) {
				dev_err(iep->dev,
					"Unsupported period %llu ns. Device supports only 1 sec period.\n",
					ns);
				return -EOPNOTSUPP;
			}
		}

		return iep_pps_enable(iep, IEP_PPS_EXTERNAL, on);
	case PTP_CLK_REQ_PPS_OFFSET:
		iep->pps[IEP_PPS_INTERNAL].offset = on;
		return 0;

	default:
		break;
	}
	return -EOPNOTSUPP;
}

/* Returns whether a pps event is reported */
static bool iep_pps_report(struct iep *iep, int pps)
{
	struct ptp_clock_event pevent;
	struct pps *p = &iep->pps[pps];
	u64 cmp_val, ns;
	u32 v, reported = 0;

	v = iep_read_reg(iep, iep->reg_ofs.cmp_stat_reg);
	if (v & IEP_CMPX_HIT(PPS_CMP(pps))) {
		/* write 1 to clear CMP status */
		iep_write_reg(iep, iep->reg_ofs.cmp_stat_reg,
			      IEP_CMPX_HIT(PPS_CMP(pps)));

		/* A pulse has occurred. Post the event only if
		 * this is the pps for external measurement.
		 * Otherwise, just increment the count without
		 * posting event.
		 */
		cmp_val = iep->iep_get_cmp(iep, PPS_CMP(pps));
		ns = timecounter_cyc2time(&iep->tc, cmp_val);
		pevent.type = PTP_CLOCK_PPSUSR;
		pevent.pps_times.ts_real = ns_to_timespec64(ns);

		if (pps == IEP_PPS_INTERNAL) {
			ptp_clock_event(iep->ptp_clock, &pevent);
		} else {
			pr_debug("IEP_PPS_EXTERNAL: %lld.%09lu\n",
				 pevent.pps_times.ts_real.tv_sec,
				 pevent.pps_times.ts_real.tv_nsec);
		}

		++reported;

		/* need to keep SYNC0_EN & SYNC_EN for the PWIDTH time for
		 * otherwise ongoing pulse will be terminated. Remember
		 * we need to do this in the next check. If the check
		 * happens every 50ms, the latest to disable the sync0
		 * is 100ms after it happened, ie. a check happens right
		 * before the sync0, then is found out in the next
		 * check and is disabled in the check after the next.
		 */
		if (iep->rev == IEP_REV_V2_1)
			p->report_ops[++p->next_op] = OP_DISABLE_SYNC;
	}

	return reported;
}

static inline void iep_do_pps_report_post_ops(struct iep *iep, int pps)
{
	struct pps *p = &iep->pps[pps];
	int i;

	for (i = 0; i <= p->next_op; i++) {
		switch (p->report_ops[i]) {
		case OP_DISABLE_SYNC:
			iep_disable_sync(iep, PPS_SYNC(pps));
			break;

		case OP_ENABLE_SYNC:
			iep_enable_sync(iep, PPS_SYNC(pps));
			break;
		}
	}

	p->next_op = -1;
}

/* Returns
 *   1 - if a pps is reported
 *   0 - if succeeded in processing
 *  -1 - if failed proceessing
 */
static int iep_proc_pps(struct iep *iep, int pps)
{
	struct pps *p = &iep->pps[pps];

	if (p->enable < 0)
		/* pps not active */
		return 0;

	if (!p->enable) {
		/* pps stop was initiated */
		iep_pps_stop(iep, pps);
		pinctrl_select_state(iep->pins, p->pin_off);
		p->enable = -1;
		return 0;
	}

	/* pps is active and alive */
	if (p->next_op >= 0)
		/* if some ops are left behind in last
		 * overflow check, do them now
		 */
		iep_do_pps_report_post_ops(iep, pps);

	return iep_pps_report(iep, pps);
}

static int iep_proc_latch(struct iep *iep)
{
	struct ptp_clock_event pevent;
	int i, reported = 0;
	u64 ts;
	u32 v;

	v = iep_get_latch_status(iep);

	for (i = 0; i < iep->info.n_ext_ts; i++) {
		if (!(v & LATCHX_VALID(i)))
			continue;

		ts = iep_get_latch_ts(iep, i);
		/* report the event */
		pevent.timestamp = timecounter_cyc2time(&iep->tc, ts);
		pevent.type = PTP_CLOCK_EXTTS;
		pevent.index = i;
		ptp_clock_event(iep->ptp_clock, &pevent);
		++reported;
	}

	return reported;
}

static long iep_overflow_check(struct ptp_clock_info *ptp)
{
	struct iep *iep = container_of(ptp, struct iep, info);
	unsigned long delay = iep->ov_check_period;
	struct timespec64 ts;
	unsigned long flags;
	unsigned int reported_mask = 0;
	u64 ns_to_sec, cyc_to_sec, cmp_val, rem;
	struct pps *p;
	int pps, n;

	spin_lock_irqsave(&iep->ptp_lock, flags);
	ts = ns_to_timespec64(timecounter_read(&iep->tc));

	/* With 32-bit IEP, need to wait until wraparound (1 sec) to reset SYNC
	 * signal or the SYNC pulse will occur again because the IEP is still
	 * greater than CMP1. Below resets SYNC signal shortly before the next
	 * pulse (CMP1 event). NOTE: This can still fail if CMP1 is very low and
	 * this check resets SYNC before wraparound occurs.
	 */
	if (iep->rev == IEP_REV_V1_0 && iep->pps[0].enable) {
		if (NSEC_PER_SEC - ts.tv_nsec < IEP32_WRAPAROUND_SYNC_TIME_NS) {
			iep_disable_sync(iep, PPS_SYNC(0));
			iep_enable_sync(iep, PPS_SYNC(0));
		}
	}

	iep_proc_latch(iep);

	for (pps = 0; pps < MAX_PPS; pps++) {
		n = iep_proc_pps(iep, pps);
		reported_mask |= (n > 0 ? BIT(pps) : 0);
	}

	if (!reported_mask)
		goto done;

	/* load the next pulse */

	/* Do we need to get the updated time and counter again?
	 * Probably not. Just use the last one. ns to sec boundary
	 * will be larger to compensate.
	 */

	/* Align cmp count to next sec boundary. If overflow check is
	 * done every 50ms, the ns_to_sec  will be at least 950ms,
	 * ie. a check just happened right before the sync and is found
	 * out in the next check.
	 */
	ns_to_sec = NSEC_PER_SEC - ts.tv_nsec;
	ns_to_sec += iep->pps[0].offset;
	cyc_to_sec = iep_ns2cyc(iep, ns_to_sec);
	cmp_val = iep->tc.cycle_last + cyc_to_sec;

	if (iep->rev == IEP_REV_V1_0) {
		if (cmp_val > NSEC_PER_SEC) {
			rem = do_div(cmp_val, NSEC_PER_SEC);
			cmp_val = rem;
		}
	}

	for (pps = 0; pps < MAX_PPS; pps++) {
		if (!(reported_mask & BIT(pps)))
			continue;

		p = &iep->pps[pps];
		iep->iep_set_cmp(iep, PPS_CMP(pps), cmp_val);
		if (p->next_op >= 0 && iep->rev == IEP_REV_V2_1)
			/* some ops have not been performed
			 * put this one in the queue
			 */
			p->report_ops[++p->next_op] = OP_ENABLE_SYNC;
	}

done:
	spin_unlock_irqrestore(&iep->ptp_lock, flags);

	pr_debug("iep overflow check at %lld.%09lu\n", ts.tv_sec, ts.tv_nsec);
	return (long)delay;
}

static struct ptp_clock_info iep_info = {
	.owner		= THIS_MODULE,
	.max_adj	= 1000000,
	.n_ext_ts	= 0,
	.n_per_out	= 0,
	.pps		= 0,
	.adjfreq	= iep_adjfreq,
	.adjtime	= iep_adjtime,
	.gettime64	= iep_gettime,
	.settime64	= iep_settime,
	.enable		= iep_ptp_feature_enable,
	.do_aux_work	= iep_overflow_check,
};

void iep_reset_timestamp(struct iep *iep, u16 ts_ofs)
{
	memset_io(iep->sram + ts_ofs, 0, sizeof(u64));
}

u64 iep_get_timestamp_cycles32(struct iep *iep, u16 ts_ofs)
{
	void __iomem *sram = iep->sram;
	u64 cycles, cycles_sec = 0;
	u32 cycles_ns;

	memcpy_fromio(&cycles_ns, sram + ts_ofs, sizeof(cycles_ns));
	memcpy_fromio(&cycles_sec, sram + ts_ofs + 4, sizeof(cycles_sec));
	memset_io(sram + ts_ofs, 0, sizeof(cycles_ns));
	memset_io(sram + ts_ofs + 4, 0, sizeof(cycles_sec));
	cycles = cycles_ns + (cycles_sec * NSEC_PER_SEC);

	return cycles;
}

u64 iep_get_timestamp_cycles64(struct iep *iep, u16 ts_ofs)
{
	void __iomem *sram = iep->sram;
	u64 cycles;

	memcpy_fromio(&cycles, sram + ts_ofs, sizeof(cycles));
	memset_io(sram + ts_ofs, 0, sizeof(cycles));

	return cycles;
}

int iep_rx_timestamp(struct iep *iep, u16 ts_ofs, struct sk_buff *skb)
{
	struct skb_shared_hwtstamps *ssh;
	u64 ns, cycles;

	/* get timestamp */
	cycles = iep->iep_get_timestamp_cycles(iep, ts_ofs);

	if (!cycles)
		return -ENOENT;

	ns = timecounter_cyc2time(&iep->tc, cycles);

	ssh = skb_hwtstamps(skb);
	memset(ssh, 0, sizeof(*ssh));
	ssh->hwtstamp = ns_to_ktime(ns);
	return 0;
}

int iep_tx_timestamp(struct iep *iep, u16 ts_ofs, struct sk_buff *skb,
		     unsigned long tmo)
{
	struct skb_shared_hwtstamps ssh;
	u64 ns, cycles;

	/* get timestamp */
	cycles = iep->iep_get_timestamp_cycles(iep, ts_ofs);

	if (!cycles)
		return -ENOENT;

	if (time_after(jiffies, tmo))
		return -ETIME;

	ns = timecounter_cyc2time(&iep->tc, cycles);

	/* pass timestamp to upper */
	memset(&ssh, 0, sizeof(ssh));
	ssh.hwtstamp = ns_to_ktime(ns);
	skb_tstamp_tx(skb, &ssh);
	return 0;
}

int iep_get_timestamp(struct iep *iep, u16 ts_ofs, u64 *ns)
{
	u64 cycles;

	/* get timestamp */
	cycles = iep->iep_get_timestamp_cycles(iep, ts_ofs);

	if (!cycles) {
		*ns = 0;
		return -ENOENT;
	}

	*ns = timecounter_cyc2time(&iep->tc, cycles);
	return 0;
}

static int iep_dram_init(struct iep *iep)
{
	void __iomem *sram = iep->sram;
	u64 temp64;

	writew(0, sram + MII_RX_CORRECTION_OFFSET);
	writew(0, sram + MII_TX_CORRECTION_OFFSET);

	/*Set seconds value to 0*/
	memset_io(sram + TIMESYNC_SECONDS_COUNT_OFFSET, 0,
		  TIMESYNC_SECONDS_COUNT_SIZE);

	/* Initialize RCF to 1 (Linux N/A) */
	writel(1 * 1024, sram + TIMESYNC_TC_RCF_OFFSET);

	/* This flag will be set and cleared by firmware */
	/* Write Sync0 period for sync signal generation in PTP
	 * memory in shared RAM
	 */
	writel(IEP_DEFAULT_PPS_WIDTH, sram + TIMESYNC_SYNC0_WIDTH_OFFSET);

	/* Write CMP1 period for sync signal generation in PTP
	 * memory in shared RAM
	 */
	temp64 = PULSE_SYNC_INTERVAL;
	memcpy_toio(sram + TIMESYNC_CMP1_CMP_OFFSET, &temp64, sizeof(temp64));

	/* Write Sync0 period for sync signal generation in PTP
	 * memory in shared RAM
	 */
	writel(PULSE_SYNC_INTERVAL, sram + TIMESYNC_CMP1_PERIOD_OFFSET);

	/* Configures domainNumber list. Firmware supports 2 domains */
	writeb(0, sram + TIMESYNC_DOMAIN_NUMBER_LIST);
	writeb(0, sram + TIMESYNC_DOMAIN_NUMBER_LIST + 1);

	/* Configure 1-step/2-step */
	writeb(PTP_TWO_STEP_ENABLE, sram + DISABLE_SWITCH_SYNC_RELAY_OFFSET);

	/* Configures the setting to Link local frame without HSR tag */
	writeb(0, sram + LINK_LOCAL_FRAME_HAS_HSR_TAG);
	return 0;
}

static int iep_config(struct iep *iep)
{
	int i;

	if (iep->info.pps)
		iep_pps_pins_off(iep);

	if (iep->info.n_ext_ts)
		iep_extts_pins_off(iep);

	/* This is just to be extra cautious to avoid HW damage because
	 * of more than one output signal going against each other in our
	 * application. The unregister call stops the pps also. This extra
	 * precaution does not hurt though, in case someone enables the
	 * signal through direct register write after the driver is
	 * unregistered but before restarting the driver. But of course this
	 * is still not 100% foolproof
	 */
	for (i = 0; i < MAX_PPS; i++)
		iep_pps_stop(iep, i);

	/* sync/latch one time configs */
	iep_pps_init(iep);

	/* Reset IEP count to 0 before enabling compare config regs
	 * This ensures that we don't hit CMP1 with a large value in IEP
	 */
	iep_write_reg(iep, iep->reg_ofs.count_reg, 0);
	if (iep->rev == IEP_REV_V2_1)
		iep_write_reg(iep, iep->reg_ofs.count_reg + 4, 0);

	if (iep->rev == IEP_REV_V1_0) {
		/* Enable reset */
		iep_enable_cmp(iep, -1);
		 /* Set and enable compare 0 */
		iep->iep_set_cmp(iep, 0, NSEC_PER_SEC);
		iep_enable_cmp(iep, 0);
	}

	return 0;
}

static inline void iep_start(struct iep *iep)
{
	if (iep->rev == IEP_REV_V1_0)
		iep_set_reg(iep, iep->reg_ofs.global_cfg,
			    IEP_GLOBAL_CFG_REG_MASK,
			    IEP_GLOBAL_CFG_REG_INCR5_VAL);
	else
		iep_set_reg(iep, iep->reg_ofs.global_cfg,
			    IEP_GLOBAL_CFG_REG_MASK,
			    IEP_GLOBAL_CFG_REG_INCR1_VAL);
}

static inline void iep_time_sync_start(struct iep *iep)
{
	u8 val = 0;

	/* Disable fw background task for both HSR/PRP. */
	val &= ~TIMESYNC_CTRL_BG_ENABLE;
	/* Enable forced 2-step for HSR. No effect on PRP */
	val |= TIMESYNC_CTRL_FORCED_2STEP;

	writeb(val, iep->sram + TIMESYNC_CTRL_VAR_OFFSET);
	iep->ptp_tx_enable = TIMESYNC_ENABLE;
	iep->ptp_rx_enable = TIMESYNC_ENABLE;
}

static inline void iep_time_sync_stop(struct iep *iep)
{
	iep->ptp_tx_enable = 0;
	iep->ptp_rx_enable = 0;
}

int iep_register(struct iep *iep)
{
	int err;

	iep_dram_init(iep);

	iep_config(iep);

	iep_start(iep);

	timecounter_init(&iep->tc, &iep->cc, ktime_to_ns(ktime_get_real()));

	iep->ptp_clock = ptp_clock_register(&iep->info, iep->dev);
	if (IS_ERR(iep->ptp_clock)) {
		err = PTR_ERR(iep->ptp_clock);
		iep->ptp_clock = NULL;
		return err;
	}
	iep->phc_index = ptp_clock_index(iep->ptp_clock);

	iep_time_sync_start(iep);

	ptp_schedule_worker(iep->ptp_clock, iep->ov_check_period);

	if (iep->bc_pps_sync)
		iep->bc_clkid = ptp_bc_clock_register(
		(iep->pruss_id == 1) ? PTP_BC_CLOCK_TYPE_PRUICSS1 :
				       PTP_BC_CLOCK_TYPE_PRUICSS2);

	pr_info("iep ptp bc clkid %d\n", iep->bc_clkid);
	return 0;
}

void iep_unregister(struct iep *iep)
{
	int i;

	if (WARN_ON(!iep->ptp_clock))
		return;

	for (i = 0; i < MAX_PPS; i++)
		iep_pps_stop(iep, i);

	iep_time_sync_stop(iep);
	ptp_clock_unregister(iep->ptp_clock);
	iep->ptp_clock = NULL;
	ptp_bc_clock_unregister(iep->bc_clkid);
}

/* Get the pps (sync) and extts (latch) on/off pinctrl
 * states. on-state will be selected when pps or extts
 * pin is enabled. off-state selected when pin is disabled.
 */
static int iep_get_pps_extts_pins(struct iep *iep)
{
	struct pinctrl_state *on, *off;
	u32 has_on_off;
	struct pinctrl *pins;

	pins = devm_pinctrl_get(iep->dev);
	if (IS_ERR(pins)) {
		iep->pins = NULL;
		dev_err(iep->dev, "request for sync latch pins failed: %ld\n",
			PTR_ERR(pins));
		return PTR_ERR(pins);
	}

	iep->pins = pins;
	has_on_off = 0;

	on = pinctrl_lookup_state(iep->pins, "sync0_on");
	if (!IS_ERR(on))
		has_on_off |= BIT(1);

	off = pinctrl_lookup_state(iep->pins, "sync0_off");
	if (!IS_ERR(off))
		has_on_off |= BIT(0);

	if (has_on_off == 0x3) {
		iep->pps[0].pin_on = on;
		iep->pps[0].pin_off = off;
		iep->info.pps = 1;
	}

	has_on_off = 0;

	on = pinctrl_lookup_state(iep->pins, "latch0_on");
	if (!IS_ERR(on))
		has_on_off |= BIT(1);

	off = pinctrl_lookup_state(iep->pins, "latch0_off");
	if (!IS_ERR(off))
		has_on_off |= BIT(0);

	if (has_on_off == 0x3) {
		iep->extts[0].pin_on = on;
		iep->extts[0].pin_off = off;
		iep->info.n_ext_ts = 1;
	}

	has_on_off = 0;

	on = pinctrl_lookup_state(iep->pins, "sync1_on");
	if (!IS_ERR(on))
		has_on_off |= BIT(1);

	off = pinctrl_lookup_state(iep->pins, "sync1_off");
	if (!IS_ERR(off))
		has_on_off |= BIT(0);

	if (has_on_off == 0x3) {
		iep->pps[1].pin_on = on;
		iep->pps[1].pin_off = off;
		iep->info.n_per_out = 1;
	}

	return 0;
}

struct iep *iep_create(struct device *dev, void __iomem *sram,
		       void __iomem *iep_reg, int pruss_id, int rev)
{
	struct iep *iep;

	iep = devm_kzalloc(dev, sizeof(*iep), GFP_KERNEL);
	if (!iep)
		return ERR_PTR(-ENOMEM);

	iep->rev = rev;
	if (iep->rev == IEP_REV_V1_0) {
		iep->reg_ofs = iep_regs_ofs_v1_0;
		iep->iep_get_count = iep_get_count32;
		iep->iep_get_cmp = iep_get_cmp32;
		iep->iep_set_cmp = iep_set_cmp32;
		iep->iep_get_timestamp_cycles = iep_get_timestamp_cycles32;
	} else {
		iep->reg_ofs = iep_regs_ofs_v2_1;
		iep->iep_get_count = iep_get_count64;
		iep->iep_get_cmp = iep_get_cmp64;
		iep->iep_set_cmp = iep_set_cmp64;
		iep->iep_get_timestamp_cycles = iep_get_timestamp_cycles64;
	}

	iep->dev = dev;
	iep->sram = sram;
	iep->iep_reg = iep_reg;
	spin_lock_init(&iep->ptp_lock);
	iep->ov_check_period = msecs_to_jiffies(IEP_OVERFLOW_CHECK_PERIOD_MS);
	iep->ov_check_period_slow = iep->ov_check_period;

	iep->cc.shift = IEP_TC_DEFAULT_SHIFT;
	if (iep->rev == IEP_REV_V1_0)
		iep->cc.mult = IEP_TC_INCR5_MULT;
	else
		iep->cc.mult = IEP_TC_INCR1_MULT;
	iep->cc.read = iep_cc_read;
	iep->cc.mask = CLOCKSOURCE_MASK(64);
	iep->info = iep_info;
	snprintf(iep->info.name, sizeof(iep->info.name),
		 "PRUSS%d timer", pruss_id);

	iep_get_pps_extts_pins(iep);
	if (iep->info.pps && iep->info.n_ext_ts)
		iep->bc_pps_sync = true;
	else
		iep->bc_pps_sync = false;

	iep->bc_clkid = -1;
	iep->pruss_id = pruss_id;

	/* save cc.mult original value as it can be modified
	 * by iep_adjfreq().
	 */
	iep->cc_mult = iep->cc.mult;

	return iep;
}

void iep_release(struct iep *iep)
{
	if (iep->pins)
		devm_pinctrl_put(iep->pins);
}
