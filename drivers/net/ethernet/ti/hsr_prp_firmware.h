/*
 * Copyright (C) 2017-2018 Texas Instruments Incorporated - http://www.ti.com
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

#ifndef __ICSS_SWITCH_HSR_PRP_H
#define __ICSS_SWITCH_HSR_PRP_H

#define RED_TAG_RCT_SIZE                 6       /* HSR tag or PRP RCT size */

#define LRE_HSR_MODE                      0x1E76
#define MODEH                             0x01
#define MODEN                             0x02
#define MODET                             0x03
#define MODEU                             0x04
#define MODEM                             0x05

/* PRU0 DMEM */
#define DBG_START                         0x1E00

#define DUPLICATE_HOST_TABLE              0x0200
#define DUPLICATE_HOST_TABLE_END          0x19f4

/* PRU1 DMEM */
#define DUPLICATE_PORT_TABLE_PRU0         0x0200
#define DUPLICATE_PORT_TABLE_PRU0_END     0x0df4
#define DUPLICATE_PORT_TABLE_PRU1         0x0E00
#define DUPLICATE_PORT_TABLE_PRU1_END     0x19f4

/* Size and setup (N and M) of duplicate host table */
#define DUPLICATE_HOST_TABLE_SIZE         0x1C08
/* Size and setup (N and M) of duplicate port table (HSR Only) */
#define DUPLICATE_PORT_TABLE_SIZE         0x1C1C
/* Time after which a node entry is cleared (10ms resolution) */
#define NODE_FORGET_TIME                  0x1C20
/* Time after which an entry is removed from the dup table (10ms resolution) */
#define DUPLI_FORGET_TIME                 0x1C24
/* Time interval to check the port duplicate table */
#define DUPLI_PORT_CHECK_RESO             0x1C2C
/* Time interval to check the host duplicate table */
#define DUPLI_HOST_CHECK_RESO             0x1C30
/* NodeTable | Host | Port */
#define HOST_TIMER_CHECK_FLAGS            0x1C38
/* Arbitration flag for the host duplicate t */
#define HOST_DUPLICATE_ARBITRATION        0x1C3C
/* Supervision address in HSR */
#define SUP_ADDR                          0x1C4C
#define SUP_ADDR_LOW                      0x1C50

/* Time in TimeTicks (1/100s) */
#define DUPLICATE_FORGET_TIME_400_MS      40
/* Time in TimeTicks (1/100s) */
#define DUPLICATE_FORGET_TIME_400_MS_PRP  0x0028
/* Time in TimeTicks (1/100s) */
#define NODE_FORGET_TIME_60000_MS         6000

#define DUPLICATE_PORT_TABLE_DMEM_SIZE        0x0C00
#define DUPLICATE_HOST_TABLE_DMEM_SIZE        0x1800
#define LRE_STATS_DMEM_SIZE                   0x0088
#define DEBUG_COUNTER_DMEM_SIZE               0x0050

#define DUPLICATE_HOST_TABLE_SIZE_INIT         0x00800004  /* N = 128, M = 4 */
#define DUPLICATE_PORT_TABLE_SIZE_INIT         0x00400004  /* N = 64, M = 4 */
#define MASTER_SLAVE_BUSY_BITS_CLEAR           0x00000000
#define TABLE_CHECK_RESOLUTION_10_MS           0x0000000A
#define SUP_ADDRESS_INIT_OCTETS_HIGH           0x004E1501  /* 01-15-4E-00- */
#define SUP_ADDRESS_INIT_OCTETS_LOW            0x00000001  /* -01-00 */

/* SHARED RAM */

/* 8 bytes of VLAN PCP to RX QUEUE MAPPING */
#define QUEUE_2_PCP_MAP_OFFSET                 0x120
#define LRE_START                              0x140

/* Number of frames successfully sent over port A/B that are HSR/PRP tagged */
#define LRE_CNT_TX_A                           (LRE_START + 4)

#define LRE_DUPLICATE_DISCARD                  (LRE_START + 104)
#define LRE_TRANSPARENT_RECEPTION              (LRE_START + 108)

#define LRE_CNT_NODES                          (LRE_START + 52)

/* SRAM
 * VLAN filter defines & offsets
 */
#define VLAN_FLTR_CTRL_BYTE                          0x1FE
/* one bit field | 0 : VLAN filter disabled
 *               | 1 : VLAN filter enabled
 */
#define VLAN_FLTR_CTRL_SHIFT                         0x0
/* one bit field | 0 : untagged host rcv allowed
 *               | 1 : untagged host rcv not allowed
 */
#define VLAN_FLTR_UNTAG_HOST_RCV_CTRL_SHIFT          0x1
/* one bit field | 0 : priotag host rcv allowed
 *               | 1 : priotag host rcv not allowed
 */
#define VLAN_FLTR_PRIOTAG_HOST_RCV_CTRL_SHIFT        0x2
#define VLAN_FLTR_DIS                                0x0
#define VLAN_FLTR_ENA                                0x1

#define VLAN_FLTR_UNTAG_HOST_RCV_ALL                 0x0
#define VLAN_FLTR_UNTAG_HOST_RCV_NAL                 0x1

#define VLAN_FLTR_PRIOTAG_HOST_RCV_ALL               0x0
#define VLAN_FLTR_PRIOTAG_HOST_RCV_NAL               0x1

/* VID = 0 for priority tagged frames */
#define VLAN_FLTR_PRIOTAG_VID                        0x0
#define VLAN_FLTR_TBL_BASE_ADDR                      0x200
/* 4096 bits = 512 bytes = 0x200 bytes */
#define VLAN_FLTR_TBL_SIZE                           0x200

#define VLAN_VID_MIN                                 0x0
#define VLAN_VID_MAX                                 0x0FFF

/* Below Rx Interrupt pacing defines. */
/* shared RAM */
/* 1 byte for pace control */
#define INTR_PAC_STATUS_OFFSET                       0x1FAF
/* Interrupt Pacing disabled, Adaptive logic disabled */
#define INTR_PAC_DIS_ADP_LGC_DIS                     0x0
/* Interrupt Pacing enabled, Adaptive logic disabled */
#define INTR_PAC_ENA_ADP_LGC_DIS                     0x1
/* Interrupt Pacing enabled, Adaptive logic enabled */
#define INTR_PAC_ENA_ADP_LGC_ENA                     0x2

/* 4 bytes | previous TS from eCAP TSCNT for PRU 0 */
#define INTR_PAC_PREV_TS_OFFSET_PRU0                 0x1FB0
/* 4 bytes | timer expiration value for PRU 0 */
#define INTR_PAC_TMR_EXP_OFFSET_PRU0                 0x1FB4
/* 4 bytes | previous TS from eCAP TSCNT for PRU 1 */
#define INTR_PAC_PREV_TS_OFFSET_PRU1                 0x1FB8
/* 4 bytes | timer expiration value for PRU 1 */
#define INTR_PAC_TMR_EXP_OFFSET_PRU1                 0x1FBC
#define INTR_PAC_PREV_TS_RESET_VAL                   0x0

#define IEC62439_CONST_DUPLICATE_ACCEPT                 0x01
#define IEC62439_CONST_DUPLICATE_DISCARD                0x02
#define IEC62439_CONST_TRANSPARENT_RECEPTION_REMOVE_RCT 0x01
#define IEC62439_CONST_TRANSPARENT_RECEPTION_PASS_RCT   0x02

/* Enable/disable interrupts for high/low priority instead of per port.
 * 0 = disabled (default) 1 = enabled
 */
#define PRIORITY_INTRS_STATUS_OFFSET    0x1FAA
/* Enable/disable timestamping of packets. 0 = disabled (default) 1 = enabled */
#define TIMESTAMP_PKTS_STATUS_OFFSET    0x1FAB
#define TIMESTAMP_ARRAY_OFFSET          0xC200

/* PRU1 DMEM
 * Multicast filter defines & offsets
 */
#define M_MULTICAST_TABLE_SEARCH_OP_CONTROL_BIT         0xE0
/* one byte field :
 * 0 -> multicast filtering disabled
 * 1 -> multicast filtering enabled
 */
#define MULTICAST_FILTER_DISABLED                       0x00
#define MULTICAST_FILTER_ENABLED                        0x01
#define MULTICAST_FILTER_MASK                           0xE4
#define MULTICAST_FILTER_TABLE                          0x100
#define MULTICAST_TABLE_SIZE                            256
#define MULTICAST_FILTER_HOST_RCV_ALLOWED               0x01
#define MULTICAST_FILTER_HOST_RCV_NOT_ALLOWED           0x00

/* Node table offsets are different for AM3/4 vs AM57/K2G, set by firmware */
#define V1_0_HASH_MASK                 0x3F
#define V1_0_INDEX_ARRAY_NT            0x10
#define V1_0_BIN_ARRAY                 0x1A00
#define V1_0_NODE_TABLE_NEW            0x1FC0
#define V1_0_INDEX_ARRAY_LOC           PRUETH_MEM_DRAM0
#define V1_0_BIN_ARRAY_LOC             PRUETH_MEM_DRAM0
#define V1_0_NODE_TABLE_LOC            PRUETH_MEM_SHARED_RAM
#define V1_0_INDEX_TBL_MAX_ENTRIES     64
#define V1_0_BIN_TBL_MAX_ENTRIES       128
#define V1_0_NODE_TBL_MAX_ENTRIES      128

#define V2_1_HASH_MASK                 0xFF
#define V2_1_INDEX_ARRAY_NT            0x3000
#define V2_1_BIN_ARRAY \
	(V2_1_INDEX_ARRAY_NT + (V2_1_INDEX_TBL_MAX_ENTRIES * 6))
#define V2_1_NODE_TABLE_NEW \
	(V2_1_BIN_ARRAY + (V2_1_BIN_TBL_MAX_ENTRIES * 8))
#define V2_1_INDEX_ARRAY_LOC           PRUETH_MEM_SHARED_RAM
#define V2_1_BIN_ARRAY_LOC             PRUETH_MEM_SHARED_RAM
#define V2_1_NODE_TABLE_LOC            PRUETH_MEM_SHARED_RAM
#define V2_1_INDEX_TBL_MAX_ENTRIES     256
#define V2_1_BIN_TBL_MAX_ENTRIES       256
#define V2_1_NODE_TBL_MAX_ENTRIES      256

#define NT_REM_NODE_TYPE_MASK     0x1F
#define NT_REM_NODE_TYPE_SHIFT    0x00

#define NT_REM_NODE_TYPE_SANA     0x01
#define NT_REM_NODE_TYPE_SANB     0x02
#define NT_REM_NODE_TYPE_SANAB    0x03
#define NT_REM_NODE_TYPE_DAN      0x04
#define NT_REM_NODE_TYPE_REDBOX   0x08
#define NT_REM_NODE_TYPE_VDAN     0x10

#define NT_REM_NODE_HSR_BIT       0x20 /* if set node is HSR */

#define NT_REM_NODE_DUP_MASK      0xC0
#define NT_REM_NODE_DUP_SHIFT     0x06

#define NT_REM_NODE_DUP_ACCEPT    0x40 /* Node ent duplicate type: DupAccept */
#define NT_REM_NODE_DUP_DISCARD   0x80 /* Node ent duplicate type: DupDiscard */

/* HOST_TIMER_CHECK_FLAGS bits */
#define HOST_TIMER_NODE_TABLE_CHECK_BIT    BIT(0)
#define HOST_TIMER_NODE_TABLE_CLEAR_BIT    BIT(4)
#define HOST_TIMER_HOST_TABLE_CHECK_BIT    BIT(8)
#define HOST_TIMER_P1_TABLE_CHECK_BIT      BIT(16)
#define HOST_TIMER_P2_TABLE_CHECK_BIT      BIT(24)
#define HOST_TIMER_PORT_TABLE_CHECK_BITS \
	(HOST_TIMER_P1_TABLE_CHECK_BIT | HOST_TIMER_P2_TABLE_CHECK_BIT)

#endif /* __ICSS_SWITCH_HSR_PRP_H */
