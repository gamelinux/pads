/*************************************************************************
 * monnet.h
 *
 * Matt Shelton	<matt@mattshelton.com>
 *
 * This header file contains information relating to the monnet.c module.
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
 * $Id: monnet.h,v 1.1 2005/02/10 06:05:05 mattshelton Exp $
 *
 **************************************************************************/

/* INCLUDES ---------------------------------------- */
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>


/* DATA STRUCTURES --------------------------------- */
struct mon_net {
    u_long	network;
    u_long	netmask;
    struct mon_net *next;
};


/* PROTOTYPES -------------------------------------- */
void parse_networks (char *cmdline);
void init_netmasks (unsigned int nm[33]);
void add_monnet(char *network, char *netmask);
short check_monnet (const struct in_addr ip_addr);


/* GLOBALS ----------------------------------------- */
