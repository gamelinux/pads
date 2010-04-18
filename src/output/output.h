/*************************************************************************
 * output.h
 *
 * Matt Shelton	<matt@mattshelton.com>
 *
 * This module contains the output mechanism for PADS.  It will control
 * all asset data leaving the application.
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
 * $Id: output.h,v 1.3 2005/02/18 05:39:09 mattshelton Exp $
 *
 **************************************************************************/

#ifndef INCLUDED_OUTPUT_H
#define INCLUDED_OUTPUT_H

#include <bstring/bstrlib.h>
#include "storage.h"

/* DATA STRUCTURES --------------------------------- */

/* --------------------------------------------------------------------------
 * OutputPlugin:  This data structure defines a single output processor.
 * -------------------------------------------------------------------------- */
typedef struct _OutputPlugin
{
    bstring name;
    int (*init) (bstring args);
    int (*print_asset) (Asset *rec);
    int (*print_arp) (ArpAsset *rec);
    int (*print_stat) (Asset *rec);
    int (*end) (void);
} OutputPlugin;

/* --------------------------------------------------------------------------
 * OutputPluginList:  This data structure stores a list of output plugins.
 * -------------------------------------------------------------------------- */
typedef struct _OutputPluginList
{
    int active;				/* Active:  0 = disable, 1 = active */
    OutputPlugin *plugin;		/* Output Processor */
    struct _OutputPluginList *next;
} OutputPluginList;

/* PROTOTYPES -------------------------------------- */
void init_output();
int register_output_plugin (OutputPlugin *plugin);
int activate_output_plugin (bstring name, bstring args);
int print_asset (struct in_addr ip_addr, u_int16_t port, unsigned short proto);
int print_arp_asset (struct in_addr ip_addr, char mac_addr[MAC_LEN]);
int print_stat(struct in_addr ip_addr, u_int16_t port, unsigned short proto);
void end_output (void);

#endif /* INCLUDED_OUTPUT_H */
