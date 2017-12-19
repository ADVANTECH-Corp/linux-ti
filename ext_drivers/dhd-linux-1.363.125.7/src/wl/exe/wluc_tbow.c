/*
 * wl tbow command module
 *
 * Copyright (C) 2017, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 *
 * <<Broadcom-WL-IPTag/Proprietary:>>
 *
 * $Id: wluc_tbow.c 458728 2014-02-27 18:15:25Z $
 */

#ifdef WIN32
#include <windows.h>
#endif

#include <wlioctl.h>


/* Because IL_BIGENDIAN was removed there are few warnings that need
 * to be fixed. Windows was not compiled earlier with IL_BIGENDIAN.
 * Hence these warnings were not seen earlier.
 * For now ignore the following warnings
 */
#ifdef WIN32
#pragma warning(push)
#pragma warning(disable : 4244)
#pragma warning(disable : 4761)
#endif

#include <bcmutils.h>
#include <bcmendian.h>
#include "wlu_common.h"
#include "wlu.h"

#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_packet.h>

static cmd_func_t wl_tbow_doho;

static cmd_t wl_tbow_cmds[] = {
	{ "tbow_doho", wl_tbow_doho, -1, WLC_SET_VAR,
	"Trigger the BT-WiFi handover/handback"},
	{ NULL, NULL, 0, 0, NULL }
};

static char *buf;

/* module initialization */
void
wluc_tbow_module_init(void)
{
	(void)g_swap;

	/* get the global buf */
	buf = wl_get_buf();

	/* register tbow commands */
	wl_module_cmds_register(wl_tbow_cmds);
}

static int
wl_tbow_doho(void *wl, cmd_t *cmd, char **argv)
{
	tbow_setup_netinfo_t netinfo;
	char ssid_buf[TBOW_MAX_SSID_LEN + 1];
	char passph[TBOW_MAX_PASSPHRASE_LEN + 1];

	if (!*++argv) {
		printf("wl tbow_doho <opmode> <chanspec> <ssid> <passphrase> <go_ifaddr>\n");
		return -1;
	}

	netinfo.version = WL_TBOW_SETUPINFO_T_VERSION;
	netinfo.opmode = atoi(*argv++);
	switch (netinfo.opmode) {
	case TBOW_HO_MODE_START_GO: /* Start GO */
	case TBOW_HO_MODE_START_STA: /* Start STA */
	case TBOW_HO_MODE_START_GC: /* Start GC */
		netinfo.chanspec = wf_chspec_aton(*argv++);
		printf("Chanspec: 0x%x\n", netinfo.chanspec);

		if (!*argv) {
			printf("SSID is not given\n");
			return -1;
		}
		netinfo.ssid_len = strlen(*argv);
		if (netinfo.ssid_len > TBOW_MAX_SSID_LEN) {
			printf("Too long SSID: %d bytes\n", netinfo.ssid_len);
			return -1;
		}
		memcpy(netinfo.ssid, *argv, netinfo.ssid_len);
		memcpy(ssid_buf, *argv, netinfo.ssid_len);
		ssid_buf[netinfo.ssid_len] = 0;
		printf("SSID: %s\n", ssid_buf);

		++argv;
		if (!*argv) {
			printf("Passphrase is not given\n");
			return -1;
		}
		netinfo.passphrase_len = strlen(*argv);
		if (netinfo.passphrase_len > TBOW_MAX_PASSPHRASE_LEN) {
			printf("Too long passphrase: %d bytes\n", netinfo.passphrase_len);
			return -1;
		}
		memcpy(netinfo.passphrase, *argv, netinfo.passphrase_len);
		memcpy(passph, *argv, netinfo.passphrase_len);
		passph[netinfo.passphrase_len] = 0;
		printf("PASSPHRASE: %s\n", passph);

		/* Start GO */
		if (netinfo.opmode == TBOW_HO_MODE_START_GO ||
		    netinfo.opmode == TBOW_HO_MODE_START_GC) {
			++argv;
			if (!*argv) {
				printf("MAC address is not given for GO/GC\n");
				return -1;
			}
			if (!wl_ether_atoe(*argv, (struct ether_addr *)&netinfo.macaddr)) {
				printf(" ERROR: no valid ether addr provided\n");
				return -1;
			}
			if (netinfo.opmode == TBOW_HO_MODE_START_GO)
				printf("Own MAC ADDRESS: %s\n",
				        wl_ether_etoa((struct ether_addr *)&netinfo.macaddr));
			else
				printf("GO BSSID: %s\n",
				        wl_ether_etoa((struct ether_addr *)&netinfo.macaddr));
		}
		break;

	case TBOW_HO_MODE_STOP_GO:
	case TBOW_HO_MODE_STOP_GC:
	case TBOW_HO_MODE_STOP_STA:
	case TBOW_HO_MODE_TEST_GO:
	case TBOW_HO_MODE_TEARDOWN:
		break;

	default:
		printf("Invalid opmode: %d\n", netinfo.opmode);
		return -1;
	}

	return wlu_iovar_set(wl, cmd->name, &netinfo, sizeof(netinfo));
}
