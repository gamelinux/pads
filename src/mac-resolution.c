/*************************************************************************
 *
 * mac-resolution.c
 *
 * Dominique Karg <dk at ossim.net>
 * Matt Shelton <matt at mattshelton.com>
 *
 * This module will take MAC addresses from the libpcap stack and attempt
 * to translate them into a vendor code.  Thanks go to Dominique for
 * coding this module!
 *
 * Copyright (C) 2004 Matt Shelton <matt at mattshelton.com>
 * Copyright (C) 2004 Dominique Karg <dk at ossim.net>
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
 * $Id: mac-resolution.c,v 1.5 2005/05/14 20:15:21 mattshelton Exp $
 *
 **************************************************************************/
#ifndef DISABLE_VENDOR

#include "mac-resolution.h"

Vendor *vendor_list = NULL;

/* ----------------------------------------------------------
 * FUNCTION     : init_mac_resolution
 * DESCRIPTION  : This file reads in the MAC address table.
 * INPUT        : None
 * RETURN       : 0 - Success
 *              : -1 - Error
 * ---------------------------------------------------------- */
int init_mac_resolution (void) {
    FILE *fp;
    bstring filename;
    bstring filedata;
    struct bstrList *lines;
    int i;

    /* Check for a PADS_ETHER_CODES file within the current directory.  */
    if ((fp = fopen(PADS_ETHER_CODES, "r")) != NULL) {
        filename = bformat("./%s", PADS_ETHER_CODES);
        fclose(fp);
    } else if (gc.mac_file != NULL) {
        filename = bstrcpy(gc.mac_file);
    } else {
        filename = bformat("%s/%s", INSTALL_SYSCONFDIR, PADS_ETHER_CODES);
    }

    /* Open Signature File */
    if ((fp = fopen(bdata(filename), "r")) == NULL) {
        err_message("Unable to open MAC resolution file - %s", bdata(filename));
    }

    /* Read file into 'filedata' and process it accordingly. */
    filedata = bread ((bNread) fread, fp);
    if ((lines = bsplit(filedata, '\n')) != NULL) {
        for (i = 0; i < lines->qty; i++) {
            parse_raw_mac(lines->entry[i]);
        }
    }

    /* Clean Up */
    if (filename != NULL)
        bdestroy(filename);
    if (filedata != NULL)
        bdestroy(filedata);
    if (lines != NULL)
        bstrListDestroy(lines);
    close(fp);

    return 0;
}

/* ----------------------------------------------------------
 * FUNCITON     : parse_raw_mac
 * DESCRIPTION  : This function will parse a line from the
 *              : PADS_ETHER_CODES file and place it into the
 *              : MAC resolution data structure.
 * INPUT        : 0 - Raw Line
 * RETURN       : 0 - Success
 *              : -1 - Error
 * ---------------------------------------------------------- */
int parse_raw_mac (bstring line)
{
    char mac[4];
    char vendor[80];
    int m1, m2, m3;

    int pos;

    /* Parse out the contents of the line. */
    if (sscanf(bdata(line), "%02X:%02X:%02X %80[^,\n],\n", &m1, &m2, &m3, vendor) != 4)
        return -1;

    mac[0] = (char) (m1);
    mac[1] = (char) (m2);
    mac[2] = (char) (m3);
    mac[3] = 0;

    /* Add vendor to the vendor data structure. */
    if ((add_vendor (mac, vendor)) == -1) {
        log_message("warning:  'add_vendor' in function 'parse_raw_mac' failed!\n");
        return -1;
    }

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION     : add_vendor
 * DESCRIPTION  : This function will add a MAC vendor to the
 *              : vendor data structure.
 * INPUT        : 0 - MAC Address (bstring)
 *              : 1 - Vendor (bstring)
 * ---------------------------------------------------------- */
int add_vendor (char *mac, char *vendor){
    Vendor *list;
    Vendor *rec;

    /* Assign data to temporary data structure. */
    rec = (Vendor*) malloc (sizeof (Vendor));
    rec->mac = *(int *) mac;
    rec->vendor = bfromcstr(vendor);
    rec->next = NULL;

    /* Place data structure in MAC address list. */
    if(vendor_list == NULL) {
        vendor_list = rec;
    } else {
        list = vendor_list;
        while (list != NULL) {
            if (list->next == NULL) {
                list->next = rec;
                break;
            } else {
                list = list->next;
            }
        }
    }

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION     : get_vendor
 * DESCRIPTION  : This function will retrieve the vendor name
 *              : for a given MAC address.
 * INPUT        : 0 - MAC Address
 * RETURN       : Vendor Name
 * ---------------------------------------------------------- */
bstring get_vendor (char *m)
{
    Vendor *list;
    char mac[4];

    /* Prepare MAC for matching. */
    mac[0] = *m++;
    mac[1] = *m++;
    mac[2] = *m;
    mac[3] = 0;

    /* Cycle through data structure looking for match. */
    list = vendor_list;
    while (list != NULL) {
        if (list->mac == *(u_int *) mac)
            return list->vendor;

        list = list->next;
    }

    /* Nothing Found */
    return NULL;
}

/* ----------------------------------------------------------
 * FUNCTION     : end_mac_resolution
 * DESCRIPTION  : This function will shutdown the
 *              : MAC resolution module.
 * INPUT        : None
 * RETURN       : None
 * ---------------------------------------------------------- */
void end_mac_resolution (void){

    Vendor *list, *next;

    list = vendor_list;

    while (list != NULL) {
        next = list->next;
        if (list->vendor != NULL)
            bdestroy(list->vendor);
        if (list != NULL)
            free (list);
        list = next;
    }
}

#ifdef DEBUG
void show_vendor (void){
    Vendor *list;

    list = vendor_list;

    while(list != NULL) {
        printf("Mac: %s\nVendor: %s\n\n", list->mac, bdata(list->vendor));
        list = list->next;
    }
}
#endif /* DEBUG */
#endif /* DISABLE_VENDOR */

/* vim:expandtab:cindent:smartindent:ts=4:tw=0:sw=4:
 */
