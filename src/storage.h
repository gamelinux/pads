/*************************************************************************
 * storage.h
 *
 * Matt Shelton	<matt@mattshelton.com>
 *
 * This header file contains information relating to the storage.c
 * module.
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
 * $Id: storage.h,v 1.2 2005/02/16 01:47:35 mattshelton Exp $
 *
 **************************************************************************/

/* INCLUDES ---------------------------------------- */
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>

#include "global.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>


/* DEFINES ----------------------------------------- */
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif


/* PROTOTYPES -------------------------------------- */
int check_tcp_asset (struct in_addr ip_addr, u_int16_t port);
int check_icmp_asset (struct in_addr ip_addr);
int check_arp_asset (struct in_addr ip_addr, char mac_addr[MAC_LEN]);
void add_asset (struct in_addr ip_addr, struct in_addr c_ip_addr, u_int16_t port, u_int16_t c_port, unsigned short proto, bstring service, bstring application, time_t discovered);
void add_arp_asset (struct in_addr ip_addr, char mac_addr[MAC_LEN], time_t discovered);
unsigned short get_i_attempts (struct in_addr ip_addr, u_int16_t port, unsigned short proto);
short update_i_attempts (struct in_addr ip_addr, u_int16_t port, unsigned short proto, unsigned short i_attempts);
short add_hex_payload (struct in_addr ip_addr, u_int16_t port, unsigned short proto, char *hex_payload);
short update_asset (struct in_addr ip_addr, u_int16_t port, unsigned short proto, bstring service, bstring application);
inline Asset *find_asset (struct in_addr ip_addr, u_int16_t port, unsigned short proto);
Asset *get_asset_pointer (void);
ArpAsset *get_arp_pointer (void);
void end_storage (void);

#ifdef DEBUG
void print_database ();
#endif /* DEBUG */


/* GLOBALS ----------------------------------------- */
