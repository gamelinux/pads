/*************************************************************************
 *
 * monnet.c
 *
 * Matt Shelton <matt@mattshelton.com>
 *
 * This module contains function related to the storage and retrieval of
 * monitored networks.  PADS will take a linked list of monitored networks
 * and determine whether or not an IP address falls within the network.
 *
 * Copyright (C) 2004 Matt Shelton <matt@mattshelton.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * $Id: monnet.c,v 1.3 2005/02/17 16:29:14 mattshelton Exp $
 *
 **************************************************************************/
#include "monnet.h"

struct mon_net *mn;

/* ----------------------------------------------------------
 * FUNCTION	: parse_networks
 * DESCRIPTION	: This function will parse the input from the
 *		: '-n' switch and place it into a data
 *		: structure.  This input will be formated in
 *		: the following format:
 *			192.168.0.0/24,10.10.10.0/16
 * INPUT	: 0 - Raw Input
 * RETURN	: None!
* ---------------------------------------------------------- */
void parse_networks (char *cmdline)
{
    int i = 0;
    char network[16], netmask[3], tmp[16];
    struct in_addr in_net;

    /* Make sure something was defined. */
    if (cmdline == NULL)
	return;

    /* Parse Line */
    for (;;) {
	/* End of Network */
	if (*cmdline == '/') {
	    tmp[i] = '\0';
	    strlcpy(network, tmp, sizeof(network));
	    tmp[0] = '\0';
	    i = 0;

	} else if (*cmdline == ' ') {
	    /* Do nothing, just skip the space. */

	/* End of Netmask, process string. */
	} else if (*cmdline == ',' || *cmdline == '\0') {
	    tmp[i] = '\0';
	    strlcpy(netmask, tmp, sizeof(netmask));
	    tmp[0] = '\0';
	    i = 0;

	    /* Add to monnet data structure. */
	    add_monnet(network, netmask);

	    /* Exit if it's the end of the string. */
	    if (*cmdline =='\0')
		break;
	} else {
	    tmp[i] = *cmdline;
	    i++;
	}

	*cmdline++;
    }
}

/* ----------------------------------------------------------
 * FUNCTION	: init_netmasks
 * DESCRIPTION	: This function will load netmasks into an
 *		: array.
 * INPUT	: 0 - Array
 * RETURN	: None!
 * ---------------------------------------------------------- */
void init_netmasks (unsigned int nm[33])
{
    nm[0] = 0x0;
    nm[1] = 0x80000000;
    nm[2] = 0xC0000000;
    nm[3] = 0xE0000000;
    nm[4] = 0xF0000000;
    nm[5] = 0xF8000000;
    nm[6] = 0xFC000000;
    nm[7] = 0xFE000000;
    nm[8] = 0xFF000000;
    nm[9] = 0xFF800000;
    nm[10] = 0xFFC00000;
    nm[11] = 0xFFE00000;
    nm[12] = 0xFFF00000;
    nm[13] = 0xFFF80000;
    nm[14] = 0xFFFC0000;
    nm[15] = 0xFFFE0000;
    nm[16] = 0xFFFF0000;
    nm[17] = 0xFFFF8000;
    nm[18] = 0xFFFFC000;
    nm[19] = 0xFFFFE000;
    nm[20] = 0xFFFFF000;
    nm[21] = 0xFFFFF800;
    nm[22] = 0xFFFFFC00;
    nm[23] = 0xFFFFFE00;
    nm[24] = 0xFFFFFF00;
    nm[25] = 0xFFFFFF80;
    nm[26] = 0xFFFFFFC0;
    nm[27] = 0xFFFFFFE0;
    nm[28] = 0xFFFFFFF0;
    nm[29] = 0xFFFFFFF8;
    nm[30] = 0xFFFFFFFC;
    nm[31] = 0xFFFFFFFE;
    nm[32] = 0xFFFFFFFF;
}

/* ----------------------------------------------------------
 * FUNCTION	: add_monnet
 * DESCRIPTION	: This function will add a monitored network
 *		: record to the specified data structure.
 * INPUT	: 0 - (char *) Network
 *		: 1 - (char *) Netmask
 * RETURN	: None!
 * ---------------------------------------------------------- */
void add_monnet(char *network, char *netmask)
{
    struct mon_net *rec, *data;
    struct in_addr net_addr;
    unsigned int netmasks[33];
    int nmask;

    /* Fill netmasks variable.  See init_netmasks in util.c. */
    init_netmasks(netmasks);

    nmask = atoi(netmask);

    /* Ensure that the netmask is correct. */
    if (nmask < 1 && nmask > 32)
	return;

    /* Ensure that the network is correct. */
    if ((inet_aton(network, &net_addr)) != 1)
	return;

    /* Create structure array and assign data to it. */
    rec = (struct mon_net*)malloc(sizeof(struct mon_net));
    rec->netmask = htonl(netmasks[nmask]);
    rec->network = ((unsigned long) net_addr.s_addr & rec->netmask);
    rec->next = NULL;

    /* Find position within array and assign new data to it. */
    if (mn == NULL) {
	mn = rec;
    } else {
	data = mn;
	while (data != NULL) {
	    if (data->next == NULL) {
		data->next = rec;
		break;
	    } else {
		data = data->next;
	    }
	}
    }
}

/* ----------------------------------------------------------
 * FUNCTION	: check_monnet
 * DESCRIPTION	: This function will check to see whether a
 *		: specified IP address falls within the list
 *		: of monitored networks.
 * INPUT	: 0 - IP Address
 * RETURN	: 0 - No, skip asset
 *		: 1 - Yes, process asset
 * ---------------------------------------------------------- */
short check_monnet (const struct in_addr ip_addr)
{
    struct mon_net *data;

    if (mn == NULL) {
	/* No monitored networks */
	return 1;
    } else {
	/* Go through monitored networks. */
	data = mn;

	while (data != NULL) {
	    if ((ip_addr.s_addr & data->netmask) == data->network) {
		/* Found! */
		return 1;
	    } else {
		data = data->next;
	    }
	}
    }

    /* Asset does not fall within a monitored network. */
    return 0;
}
