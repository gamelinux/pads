/*************************************************************************
 * storage.c
 *
 * Matt Shelton <matt@mattshelton.com>
 *
 * This module contains functions related to the storage of assets.
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
 * $Id: storage.c,v 1.3 2005/02/16 01:47:35 mattshelton Exp $
 *
 **************************************************************************/
#include "storage.h"

Asset *asset_list;
ArpAsset *arp_asset_list;

/* ----------------------------------------------------------
 * FUNCTION	: check_tcp_asset
 * DESCRIPTION	: This function determines whether an asset
 *		: has already been recorded.
 * INPUT	: 0 - IP Address
 *		: 1 - TCP port
 * RETURN	: 0 - Asset Exists
 *		: 1 - New Asset
 * ---------------------------------------------------------- */
int check_tcp_asset (struct in_addr ip_addr, u_int16_t port)
{
    Asset *rec;

    /* Check the Asset data structure for an existing entry. */
    rec = asset_list;
    while (rec != NULL) {
	if (rec->ip_addr.s_addr == ip_addr.s_addr
		&& rec->port == port
		&& rec->proto == IPPROTO_TCP) {
	    return 0;

	} else {
	    rec = rec->next;
	}
    }

    /* Asset not found, return 1 */
    return 1;
}

/* ----------------------------------------------------------
 * FUNCTION	: check_icmp_asset
 * DESCRIPTION	: This function determines whether an asset
 *		: has already been recorded.
 * INPUT	: 0 - IP Address
 * RETURN	: 0 - Asset Exists
 *		: 1 - New Asset
 * ---------------------------------------------------------- */
int check_icmp_asset (struct in_addr ip_addr)
{
    Asset *rec;

    /* Check the Asset data stucture for an existing entry. */
    rec = asset_list;
    while (rec != NULL) {
	if (rec->ip_addr.s_addr == ip_addr.s_addr
		&& rec->proto == IPPROTO_ICMP) {
	    return 0;

	} else {
	    rec = rec->next;
	}
    }

    /* Asset not found, return 1 */
    return 1;
}

/* ----------------------------------------------------------
 * FUNCTION	: check_arp_asset
 * DESCRIPTION	: This function determines whether the ARP
 *		: data for an asset has been recorded in the
 *		: ARP data structure.
 * INPUT	: 0 - IP Address
 *		: 1 - MAC Address
 * RETURN	: 0 - Asset Exists
 *		: 1 - New Asset
 * ---------------------------------------------------------- */
int check_arp_asset (struct in_addr ip_addr, char mac_addr[MAC_LEN])
{
    ArpAsset *rec;

    /* Check the ARP data structure for an existing entry. */
    rec = arp_asset_list;
    while (rec != NULL) {
	if (rec->ip_addr.s_addr == ip_addr.s_addr
		&& (strcmp(rec->mac_addr, mac_addr) == 0)) {
	    return 0;

	} else {
	    rec = rec->next;
	}
    }

    /* Asset not found return 1 */
    return 1;
}

/* ----------------------------------------------------------
 * FUNCTION	: add_asset
 * DESCRIPTION	: This function will add an asset to the
 *		: specified asset data structure.
 * INPUT	: 0 - IP Address
 *		: 1 - Port
 *		: 2 - Protocol
 *		: 3 - Service
 *		: 4 - Application
 *		: 5 - Discovered
 * RETURN	: None!
 * ---------------------------------------------------------- */
void add_asset (struct in_addr ip_addr,
                struct in_addr c_ip_addr,
		u_int16_t port,
		u_int16_t c_port,
		unsigned short proto,
		bstring service,
		bstring application,
		time_t discovered)
{
    Asset *rec;
    Asset *list;

    /* Assign list to temp structure.  */
    rec = (Asset*)malloc(sizeof(Asset));
    rec->ip_addr.s_addr = ip_addr.s_addr;
    rec->c_ip_addr.s_addr = c_ip_addr.s_addr;
    rec->port = port;
    rec->c_port = c_port;
    rec->proto = proto;
    rec->service = bstrcpy(service);
    rec->application = bstrcpy(application);
    rec->next = NULL;

    /*
     * If this device has been read from a report file, set
     * the discovered time to whatever is in the report.
     * Also, we don't want to try to identify this service
     * anymore (i_attempts = 0);
     */
    if (!discovered) {
	rec->discovered = time(NULL);
	rec->i_attempts = I_ATTEMPTS;
    } else {
	rec->discovered = discovered;
	rec->i_attempts = 0;
    }

    /*
     * ICMP packets will not be identified, set i_attempts
     * to zero.
     */
    if (proto == IPPROTO_ICMP) {
	rec->i_attempts = 0;
    }

    /* Find this record's location within linked list.  */
    if (asset_list == NULL) {
	asset_list = rec;
    } else {
	list = asset_list;
	while (list != NULL) {
	    if (list->next == NULL) {
		list->next = rec;
		break;
	    } else {
		list = list->next;
	    }
	}
    }

    return;
}

/* ----------------------------------------------------------
 * FUNCTION	: add_arp_asset
 * DESCRIPTION	: This function will add an ARP entry to the
 *		: ARP data structure.
 * INPUT	: 0 - IP Address
 *		: 1 - MAC Address
 *		: 2 - Discovered
 * RETURN	: None!
 * ---------------------------------------------------------- */
void add_arp_asset (struct in_addr ip_addr, char mac_addr[MAC_LEN],
		    time_t discovered)
{
    ArpAsset *list;
    ArpAsset *rec;
    bstring mac_resolved;

    rec = (ArpAsset*)malloc(sizeof(ArpAsset));
    rec->ip_addr.s_addr = ip_addr.s_addr;
    memcpy(&rec->mac_addr, mac_addr, MAC_LEN);
    rec->next = NULL;

    /* Attempt to resolve the vendor name of the MAC address. */
#ifndef DISABLE_VENDOR
    mac_resolved = (bstring) get_vendor(mac_addr);
    rec->mac_resolved = bstrcpy(mac_resolved);
#else
    rec->mac_resolved = NULL;
#endif

    /*
     * If this device has been read from a report file, set
     * the discovered time to whatever is in the report.
     * Also, we don't want to try to identify this service
     * anymore (i_attempts = 0);
     */
    if (!discovered) {
	rec->discovered = time(NULL);
    } else {
	rec->discovered = discovered;
    }

    /* Find this record's location within linked list.  */
    if (arp_asset_list == NULL) {
	arp_asset_list = rec;
    } else {
	list = arp_asset_list;

	while (list != NULL) {
	    if (list->next == NULL) {
		list->next = rec;
		break;
	    } else {
		list = list->next;
	    }
	}
    }
}

/* ----------------------------------------------------------
 * FUNCTION	: get_i_attempts
 * DESCRIPTION	: Return an asset's i_attempts value.
 * INPUT	: 0 - IP Address
 *		: 1 - Port
 *		: 2 - Proto
 * RETURN	: unsigned short i_attempts;
 * ---------------------------------------------------------- */
unsigned short get_i_attempts (struct in_addr ip_addr,
			       u_int16_t port,
			       unsigned short proto)
{
    Asset *rec;

    /* Find asset within linked list.  */
    rec = asset_list;
    while (rec != NULL) {
	if (ip_addr.s_addr == rec->ip_addr.s_addr
		&& port == rec->port
		&& proto == rec->proto) {
	    /* Found! */
	    return rec->i_attempts;

	} else {
	    rec = rec->next;
	}
    }

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION	: update_i_attempts
 * DESCRIPTION	: Updates the i_attempts field for a
 *		: specified asset.
 * INPUT	: 0 - IP Address
 *		: 1 - Port
 *		: 2 - Proto
 *		: 3 - i_attempts
 * RETURN	: 0 - Success
 *		: 1 - Failure
 * ---------------------------------------------------------- */
short update_i_attempts (struct in_addr ip_addr,
			 u_int16_t port,
			 unsigned short proto,
			 unsigned short i_attempts)
{
    Asset *rec;

    /* Find asset within linked list.  */
    rec = asset_list;
    while (rec != NULL) {
	if (ip_addr.s_addr == rec->ip_addr.s_addr
		&& port == rec->port
		&& proto == rec->proto) {
	    /* Found! */
	    rec->i_attempts = i_attempts;
	    return 0;

	} else {
	    rec = rec->next;
	}
    }

    return 1;
}

/* ----------------------------------------------------------
 * FUNCTION	: update_asset
 * DESCRIPTION	: This function will update the service and
 *		: application fields of an asset.
 * INPUT	: 0 - IP Address
 *		: 1 - Port
 *		: 2 - Proto
 *		: 3 - Service
 *		: 4 - Application
 * RETURN	: 0 - Success!
 *		: 1 - Failure!
 * ---------------------------------------------------------- */
short update_asset (struct in_addr ip_addr,
		    u_int16_t port,
		    unsigned short proto,
		    bstring service,
		    bstring application)
{
    Asset *list;

    /* Find asset within linked list.  */
    list = asset_list;
    while (list != NULL) {
	if (ip_addr.s_addr == list->ip_addr.s_addr
		&& port == list->port
		&& proto == list->proto) {
	    /* Found! */
	    list->service = bstrcpy(service);
	    list->application = bstrcpy(application);
	    return 0;

	} else {
	    list = list->next;
	}
    }

    return 1;
}

short add_hex_payload (struct in_addr ip_addr,
                       u_int16_t port,
                       unsigned short proto,
                       char *hex_payload)
{
    Asset *list;

    /* Find asset within linked list.  */
    list = asset_list;
    while (list != NULL) {
        if (ip_addr.s_addr == list->ip_addr.s_addr
                && port == list->port
                && proto == list->proto) {
            /* Found! */
            if ( list->i_attempts == I_ATTEMPTS - 1 ) {

                /* First payload */
                list->hex_payload = bstrcpy(bfromcstr(hex_payload));

            } else {
                
                /* Append payload */
                bcatcstr(list->hex_payload, hex_payload);

            }
            return 0;

        } else {
            list = list->next;
        }
    }

    return 1;
}

/* ----------------------------------------------------------
 * FUNCTION	: end_storage
 * DESCRIPTION	: This function will free all the records
 *		: placed in the asset data structure.
 * INPUT	: None!
 * RETURN	: None!
 * ---------------------------------------------------------- */
void end_storage ()
{
    Asset *next1;
    ArpAsset *next2;

    /* Free records in asset_list (Asset). */
    while (asset_list != NULL) {
	next1 = asset_list->next;
	if (asset_list->service != NULL)
	    bdestroy(asset_list->service);
	if (asset_list->application != NULL)
	    bdestroy(asset_list->application);
        /*if (asset_list->hex_payload != NULL)
	    bdestroy(asset_list->hex_payload);*/
	if (asset_list != NULL)
	    free (asset_list);
	asset_list = next1;
    }

    /* Free records in arp_asset_list (Arasset_list). */
    while (arp_asset_list != NULL) {
	next2 = arp_asset_list->next;
	if (arp_asset_list->mac_resolved != NULL)
	    bdestroy(arp_asset_list->mac_resolved);
	if (arp_asset_list != NULL)
	    free (arp_asset_list);
	arp_asset_list = next2;
    }
}

/* ----------------------------------------------------------
 * FUNCTION	: find_asset
 * DESCRIPTION	: This function will find an asset's record
 *		: and return it.
 * INPUT	: 0 - IP Address
 *		: 1 - Port
 *		: 2 - Protocol
 * RETURN	: Pointer to Asset
 * ---------------------------------------------------------- */
inline Asset *
find_asset (struct in_addr ip_addr, u_int16_t port, unsigned short proto)
{
    Asset *list;
    Asset *rec;

    list = asset_list;

    while (list != NULL) {
	if (ip_addr.s_addr == list->ip_addr.s_addr
		&& port == list->port
		&& proto == list->proto) {

	    /* Found! */
	    rec = list;
	    break;

	} else {
	    list = list->next;
	}
    }

    /* Make sure that a record was found. */
    if (rec == NULL)
	return NULL;
    else
	return rec;
}

/* ----------------------------------------------------------
 * FUNCTION	: get_asset_pointer
 * DESCRIPTION	: This function will return the pointer to
 *		: the asset data structure.
 * INPUT	: None!
 * RETURN	: 0 - Asset Data Structure
 * ---------------------------------------------------------- */
Asset *get_asset_pointer ()
{
    return asset_list;
}

/* ----------------------------------------------------------
 * FUNCTION	: get_arp_pointer
 * DECRIPTION	: This function will return the pointer to
 *		: the asset data structure.
 * INPUT	: None!
 * RETURN	: 0 - ARP Data Structure
 * ---------------------------------------------------------- */
ArpAsset *get_arp_pointer ()
{
    return arp_asset_list;
}

/* ----------------------------------------------------------
 * FUNCTION	: print_database
 * DESCRIPTION	: This function prints out the asset data
 *		: structure.  It is mainly for debug
 *		: purposes.
 * INPUT	: None!
 * RETURN	: None!
 * ---------------------------------------------------------- */
#ifdef DEBUG
void print_database ()
{
    Asset *rec;
    ArpAsset *arp;
    int id = 0;

    printf("-- Begin Asset Database --\n");
    rec = asset_list;
    while (rec != NULL) {
	printf("%d:  %s,%d,%d,%d,%s,%s,%d\n",
		id, inet_ntoa(rec->ip_addr), ntohs(rec->port),
		rec->proto, rec->discovered,
		bdata(rec->service), bdata(rec->application),
		rec->i_attempts);
	rec = rec->next;
	id++;
    }
    printf("-- End Asset Database --\n\n");

    printf("-- Begin ARP Database --\n");
    id = 0;
    arp = arp_asset_list;
    while (arp != NULL) {
	printf("%d:  %s,%s,%d\n", id, inet_ntoa(arp->ip_addr),
		ether_ntoa(&arp->mac_addr), arp->discovered);
	arp = arp->next;
	id++;
    }
    printf("-- End ARP Database --\n\n");
}
#endif /* DEBUG */

