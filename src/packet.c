/*************************************************************************
 *
 * packet.c
 *
 * Matt Shelton <matt@mattshelton.com>
 *
 * This module contains functions related to packet processing.
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
 * $Id: packet.c,v 1.3 2005/02/16 01:47:35 mattshelton Exp $
 *
 **************************************************************************/
#include "packet.h"

/* ----------------------------------------------------------
 * FUNCTION	: process_eth
 * DESCRIPTION	: This function will decode and process the
 *		: ethernet contents of a packet.
 * INPUT	: 0 - PCAP Packet Header
 *		: 1 - Packet
 * RETURN	: None!
 * ---------------------------------------------------------- */
void process_eth (const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    struct ether_header *ethh;		/* net/ethernet.h */

    /* Extract the ethernet header from the packet. */
    ethh = (struct ether_header*) packet;

    /* Determine what type of ethernet packet this is. */
    switch (ntohs(ethh->ether_type)) {
	/* IP */
	case ETHERTYPE_IP:
	    process_ip (pkthdr, packet, sizeof(struct ether_header));
	    break;

	/* ARP */
	case ETHERTYPE_ARP:
	    process_arp (pkthdr, packet, sizeof(struct ether_header));
	    break;

	/* Unknown Type */
	default:
	    return;
    }

    return;
}

/* ----------------------------------------------------------
 * FUNCTION	: process_sll
 * DESCRIPTION	: This function will decode and process the
 *		: SLL contents of a packet.
 * INPUT	: 0 - PCAP Packet Header
 *		: 1 - Packet
 * RETURN	: None!
 * ---------------------------------------------------------- */
#ifdef DLT_LINUX_SLL
void process_sll (const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    struct sll_header *sllh;

    /* Extract the sll header from the packet. */
    sllh = (struct sll_header*) packet;

    /* Determine what type of sll packet this is. */
    switch(ntohs(sllh->sll_protocol)) {
	/* IP */
	case ETHERTYPE_IP:
	    process_ip (pkthdr, packet, sizeof(struct sll_header));
	    break;

	/* ARP */
	case ETHERTYPE_ARP:
	    process_arp (pkthdr, packet, sizeof(struct sll_header));
	    break;

	/* Unknown Protocol */
	default:
	    return;
    }

    return;
}
#endif /* DLT_LINUX_SLL */

/* ----------------------------------------------------------
 * FUNCTION	: process_ip
 * DESCRIPTION	: This function will decode and process the
 *		: IP contents of a packet.
 * INPUT	: 0 - PCAP Packet Header
 *		: 1 - Packet
 *		: 2 - IP Starting Point
 * RETURN	: None!
 * ---------------------------------------------------------- */
void process_ip (const struct pcap_pkthdr* pkthdr, const u_char* packet, unsigned int len)
{
    struct ip *iph;			/* netinet/ip.h */

    /* Extract the IP header from this packet. */
    iph = (struct ip*)(packet + len);

    /* Determine what type of IP packet this is. */
    switch (iph->ip_p) {
	case IPPROTO_TCP:
	    /* TCP */
	    process_tcp(pkthdr, packet, (len + sizeof(struct ip)), iph->ip_src, iph->ip_dst);
	    break;

	case IPPROTO_ICMP:
	    /* ICMP */
	    process_icmp(pkthdr, packet, (len + sizeof(struct ip)), iph->ip_src, iph->ip_dst);
	    break;

	default:
	    /* Unsupported Protocol */
	    return;
    }

    return;
}

/* ----------------------------------------------------------
 * FUNCTION	: process_arp
 * DESCRIPTION	: This function will decode and process the
 *		: ARP contents of a packet.
 * INPUT	: 0 - PCAP Packet Header
 *		: 1 - Packet
 *		: 2 - ARP Starting Point
 * RETURN	: None!
 * ---------------------------------------------------------- */
void process_arp (const struct pcap_pkthdr* pkthdr, const u_char* packet, unsigned int len)
{
    struct ether_arp *arph;
    struct in_addr ip_addr;

    arph = (struct ether_arp *)(packet + len);

    /* Process packet according to it's ARP type. */
    switch (ntohs(arph->ea_hdr.ar_op)) {
	/* ARP Reply */
	case ARPOP_REPLY:
	    memcpy(&ip_addr.s_addr, arph->arp_spa, sizeof(u_int8_t) * 4);

	    if (check_arp_asset(ip_addr, arph->arp_sha) == 1) {
		add_arp_asset(ip_addr, arph->arp_sha, 0);
		print_arp_asset (ip_addr, arph->arp_sha);
	    }

	    break;

	/* Unsupported ARP Packet */
	default:
	    return;
    }

    return;
}

/* ­---------------------------------------------------------
 * FUNCTION	: process_tcp
 * DESCRIPTION	: This function will decode and process the
 *		: TCP contents of a packet.
 * INPUT	: 0 - PCAP Packet Header
 *		: 1 - Packet
 *		: 2 - TCP Starting Point
 *		: 3 - Source IP Address
 *		: 4 - Destination IP Address
 * RETURN	: None!
 * ---------------------------------------------------------- */
void process_tcp (const struct pcap_pkthdr* pkthdr, const u_char* packet, unsigned int len,
		  const struct in_addr ip_src, const struct in_addr ip_dst)
{
    struct tcphdr *tcph;		/* netinet/tcp.h */
    char *payload;
    tcph = (struct tcphdr *)(packet + len);

    /* Process packet according to it's TCP flags. */
    switch (tcph->th_flags) {

	/* SYN-ACK:  Server Connection */
	case (TH_SYN + TH_ACK):{
		/* Check to see if this falls within our monitored networks. */
		if ((check_monnet(ip_src)) == 0)
		    return;

		/* Skip FTP data connections. */
		if((ntohs(tcph->th_dport) == 20) && (ntohs(tcph->th_sport) > 1024))
		    return;
		if((ntohs(tcph->th_dport) == 21) && (ntohs(tcph->th_sport) > 1024))
		    return;

		/* Check to see if this is a known asset. */
		if(check_tcp_asset(ip_src, tcph->th_sport)) {

		    add_asset(ip_src, ip_dst, tcph->th_sport, tcph->th_dport,
			    IPPROTO_TCP, bfromcstr("unknown"), bfromcstr("unknown"), 0);
		} else {
		    /* Record connection for statistical purposes. */
		    print_stat(ip_src, tcph->th_sport, IPPROTO_TCP);
		}

	} break;

	case (TH_ACK):
	case (TH_ACK + TH_PUSH):{
		/*
		 * Check to see if this ACK packet needs to be
		 * identified.
		 */
		payload = (u_char *)(packet + sizeof(struct tcphdr) + len);

		/* Attempt to identify this asset.  */
		if(tcp_identify(ip_src, tcph->th_sport, payload, 
			    (pkthdr->caplen - sizeof(struct tcphdr) - len)) == 1)
		{
		    /* Dump banner if option specified (-d). */
		    if (gc.dump_file)
			pcap_dump((u_char *)gc.dumper, pkthdr, packet);
		}
	} break;

	/* DEFAULT:  Return, pick up next packet. */
	default:
		return;
    }

    return;
}

/* ­---------------------------------------------------------
 * FUNCTION	: process_icmp
 * DESCRIPTION	: This function will decode and process the
 *		: ICMP contents of a packet.
 * INPUT	: 0 - PCAP Packet Header
 *		: 1 - Packet
 *		: 2 - TCP Starting Point
 *		: 3 - Source IP Address
 *		: 4 - Destination IP Address
 * RETURN	: None!
 * ---------------------------------------------------------- */
void process_icmp (const struct pcap_pkthdr* pkthdr, const u_char* packet, unsigned int len,
	const struct in_addr ip_src, const struct in_addr ip_dst)
{
    struct icmp *icmp;
    icmp = (struct icmp *)(packet + len);

    /* Check to see if this falls within our monitored networks. */
    if ((check_monnet(ip_src)) == 0)
	return;

    if (icmp->icmp_type == ICMP_ECHOREPLY) {
	if(check_icmp_asset(ip_src)) {
	    add_asset(ip_src, ip_dst, 0, 0, IPPROTO_ICMP, bfromcstr("ICMP"), bfromcstr("ICMP"), 0);
	    print_asset(ip_src, 0, IPPROTO_ICMP);
	}
    }

    return;
}

