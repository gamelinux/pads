/*************************************************************************
 * global.h
 *
 * Matt Shelton <matt@mattshelton.com>
 *
 * This header file contains the global values for all the PADS modules
 * and components.
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
 * $Id: global.h,v 1.7 2005/04/27 13:45:47 mattshelton Exp $
 *
 **************************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* DEFINES ------------------------------------------ */
#define MAX_LENGTH 500
#define MAX_SERVICE 10
#define MAX_APP 100
#define MAX_VER 25
#define MAX_MISC 100

#define STD_BUF 1024
#define VENDOR_LEN 256
#define MAC_LEN 6

#define I_ATTEMPTS 4

#define DEBUG

#define PADS_SIGNATURE_LIST "pads-signature-list"
#define PADS_ETHER_CODES "pads-ether-codes"

#if defined (BSD) || defined(LINUX) || defined (SOLARIS) || defined (DARWIN)
#define MAC_ADDR(x) x.ether_addr_octet
#define MAC_ADDR_P(x) x->ether_addr_octet
#endif
#ifdef FREEBSD
#define MAC_ADDR(x) x.octet
#define MAC_ADDR_P(x) x->octet
#endif

#if defined (BSD) || defined (FREEBSD) || defined (DARWIN)
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#endif

#include <netinet/in.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <pcre.h>

#include "bstring/bstrlib.h"

/* DATA STRUCTURES ---------------------------------- */
typedef struct _globalconf
{
    /* PCAP Variables */
    pcap_t *handle;             /* PCAP Session */
    char *dev;                  /* PCAP Listening Device */
    char *pcap_filter;          /* PCAP filter text (specified on command line). */
    struct bpf_program filter;  /* PCAP filter structure */
    bpf_u_int32 mask;           /* The netmask of our sniffing device */
    bpf_u_int32 net;            /* The IP of our sniffing device */
    pcap_dumper_t *dumper;      /* PCAP Dump Object */

    /* File Variables */
    bstring conf_file;          /* Configuration File */
    bstring report_file;        /* Output File */
    bstring fifo_file;          /* File used with FIFO output. */
    bstring pcap_file;          /* PCAP file used only if '-r' switch specified. */
    bstring dump_file;          /* PCAP output file used to store banners. */
    bstring pid_file;           /* PID file created with '-D' is used. */
    bstring sig_file;           /* File containing signatures. */
    bstring mac_file;           /* File containing MAC to Vendor translations. */

    /* Drop Privileges */
    bstring priv_user;          /* Drop privileges to this user. */
    bstring priv_group;         /* Drop privileges to this group. */

    /* Execution Variables */
    int daemon_mode;            /* Daemon Mode - 0 = No, 1 = Yes */
    int hide_unknowns;          /* Display unknown devices - 0 = No, 1 = Yes */
    int verbose;                /* Verbose - 0 = No, 1 = Yes */

} GC;

/* --------------------------------------------------------------------------
 * Asset:  Data structure used to store TCP / ICMP assets.
 * -------------------------------------------------------------------------- */
typedef struct _Asset
{
    struct in_addr ip_addr;     /* Asset IP Address */
    struct in_addr c_ip_addr;   /* Clients IP Address */
    u_int16_t port;             /* Asset Port */
    u_int16_t c_port;           /* Clients Port */
    unsigned short proto;       /* Asset Protocol */
    bstring service;            /* Asset Service (i.e. SSH, WWW, etc.) */
    bstring application;        /* Asset Application (i.e. Apache, etc.) */
    bstring hex_payload;        /* Hex data for detected banner */
    time_t discovered;          /* Time at which asset was first seen. */
    unsigned short i_attempts;  /* Attempts at identifying the asset. */
    struct _Asset *next;        /* Next Signature Structure */
} Asset;

/* --------------------------------------------------------------------------
 * ArpAsset:  Data structure used to store data collected from ARP packets.
 * -------------------------------------------------------------------------- */
typedef struct _ArpAsset
{
    struct in_addr ip_addr;     /* Asset IP Address */
    char mac_addr[MAC_LEN];     /* Asset MAC Address */
    bstring mac_resolved;       /* Asset MAC Vendor Name */
    time_t discovered;          /* Time at which asset was first seen. */
    struct _ArpAsset *next;     /* Next ARP Structure */
} ArpAsset;

/* --------------------------------------------------------------------------
 * Signature:  Data structure used to store PCRE signatures.
 * -------------------------------------------------------------------------- */
typedef struct _Signature {
    bstring service;            /* Service (i.e. SSH, WWW, etc.) */
    struct {                    /* Application Title, broken up into 3 parts. */
        bstring app;
        bstring ver;
        bstring misc;
    } title;
    pcre *regex;                /* Signature - Compiled Regular Expression */
    pcre_extra *study;          /* Studied version of the compiled regex. */
    struct _Signature *next;    /* Next Signature Structure */
} Signature;

/* --------------------------------------------------------------------------
 * Vendor:  Data structure used to store MAC address to vendor mappings.
 * -------------------------------------------------------------------------- */
typedef struct _Vendor {
    unsigned int mac;
    bstring vendor;
    struct _Vendor *next;
} Vendor;

/* GLOBAL VARIABLES -------------------------------- */
extern GC gc;

/* vim:expandtab:cindent:smartindent:ts=4:tw=0:sw=4:
 */
