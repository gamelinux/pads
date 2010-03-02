/*************************************************************************
 * packet.h
 *
 * Matt Shelton	<matt@mattshelton.com>
 *
 * The contents of this file make up the header file for the packet
 * processing module.
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
 * $Id: packet.h,v 1.1 2005/02/10 06:05:05 mattshelton Exp $
 *
 **************************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* DEFINES ----------------------------------------- */
#ifdef LINUX
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#endif /* ifdef LINUX */


/* 802.1Q VLAN tags are 4 bytes long. */
#define VLAN_HDRLEN 4

/* This is the decimal equivalent of the VLAN tag's ether frame type */
#define VLAN_ETHERTYPE 33024

/* INCLUDES ---------------------------------------- */
#include "global.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

/* DATA STRUCTURES --------------------------------- */

/*
 * SLL data structure taken from tcpdump.
 */
#ifdef DLT_LINUX_SLL
#define SLL_HDR_LEN	16		/* total header length */
#define SLL_ADDRLEN	8		/* length of address field */

struct sll_header {
    u_int16_t	sll_pkttype;		/* packet type */
    u_int16_t	sll_hatype;		/* link-layer address type */
    u_int16_t	sll_halen;		/* link-layer address length */
    u_int8_t	sll_addr[SLL_ADDRLEN];	/* link-layer address */
    u_int16_t	sll_protocol;		/* protocol */
};
#endif /* DLT_LINUX_SLL */

/* PROTOTYPES -------------------------------------- */
void process_eth (const struct pcap_pkthdr* pkthdr, const u_char* packet);
#ifdef DLT_LINUX_SLL
void process_sll (const struct pcap_pkthdr* pkthdr, const u_char* packet);
#endif /* DLT_LINUX_SLL */
void process_ip (const struct pcap_pkthdr* pkthdr, const u_char* packet, unsigned int len);
void process_arp (const struct pcap_pkthdr* pkthdr, const u_char* packet, unsigned int len);
void process_tcp (const struct pcap_pkthdr* pkthdr, const u_char* packet, unsigned int len, const struct in_addr ip_src, const struct in_addr ip_dst);
void process_icmp (const struct pcap_pkthdr* pkthdr, const u_char* packet, unsigned int len, const struct in_addr ip_src, const struct in_addr ip_dst);
