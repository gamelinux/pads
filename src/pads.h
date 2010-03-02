/*************************************************************************
 * pads.h
 *
 * Matt Shelton <matt@mattshelton.com>
 *
 * The purpose of this system is to determine network assets by passively
 * listening to network traffic.
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
 * $Id: pads.h,v 1.4 2005/03/11 01:04:12 mattshelton Exp $
 *
 **************************************************************************/

/* DEFINES ----------------------------------------- */
#ifdef LINUX
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#endif /* ifdef LINUX */

#define I_ATTEMPTS 4


/* INCLUDES ---------------------------------------- */
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>

#include "global.h"


/* TYPEDEFS ---------------------------------------- */
typedef void (*proc_t)(const struct pcap_pkthdr *, const u_char *);


/* PROTOTYPES -------------------------------------- */
void process_pkt(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void set_processor (pcap_t *this_handle);
void print_header(void);
void print_usage(void);
void print_version(void);
void init_pads(void);
void main_pads(void);
void end_pads(void);

void sig_term_handler(int signal);
void sig_int_handler(int signal);
void sig_quit_handler(int signal);
void sig_hup_handler(int signal);

/* packet.h LLC prototypes */
void process_eth (const struct pcap_pkthdr* pkthdr, const u_char* packet);
void process_sll (const struct pcap_pkthdr* pkthdr, const u_char* packet);

/* vim:expandtab:cindent:smartindent:ts=4:tw=0:sw=4:
 */
