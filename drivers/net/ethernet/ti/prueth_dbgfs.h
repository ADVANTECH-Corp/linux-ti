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
#if IS_ENABLED(CONFIG_DEBUG_FS)
int prueth_dualemac_debugfs_init(struct prueth_emac *emac);
void prueth_dualemac_debugfs_term(struct prueth_emac *emac);
int prueth_hsr_prp_debugfs_init(struct prueth *prueth);
void prueth_hsr_prp_debugfs_term(struct prueth *prueth);
int prueth_debugfs_init(struct prueth_emac *emac);
void prueth_debugfs_term(struct prueth_emac *emac);

#else
static inline int prueth_hsr_prp_debugfs_init(struct prueth *prueth)
{
	return 0;
}

static inline void prueth_hsr_prp_debugfs_term(struct prueth *prueth)
{}

static inline int prueth_debugfs_init(struct prueth_emac *emac)
{
	return 0;
}

static inline void prueth_debugfs_term(struct prueth_emac *emac)
{}
#endif
