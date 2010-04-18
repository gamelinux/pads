/*************************************************************************
 * output-screen.c
 *
 * Matt Shelton	<matt@mattshelton.com>
 *
 * This output module writes PADS data to the screen.
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
 * $Id: output-screen.c,v 1.5 2005/02/22 16:09:25 mattshelton Exp $
 *
 **************************************************************************/
 
/* INCLUDES ---------------------------------------- */
#include "global.h"
 
#include <stdio.h>
#include <arpa/inet.h>

#include "output.h"
#include "output-screen.h"
#include "util.h"

/* ----------------------------------------------------------
 * FUNCTION	: setup_output_screen
 * DESCRIPTION	: This function will register the output
 *		: plugin.
 * INPUT	: None!
 * RETURN	: 0 - Success
 *		: -1 - Error
 * ---------------------------------------------------------- */
int
setup_output_screen (void)
{
    OutputPlugin *plugin;

    /* Allocate and setup plugin data record. */
    plugin = (OutputPlugin*)malloc(sizeof(OutputPlugin));
    plugin->name = bstrcpy(bfromcstr("screen"));
    plugin->init = init_output_screen;
    plugin->print_asset = print_asset_screen;
    plugin->print_arp = print_arp_asset_screen;
    plugin->print_stat = NULL;
    plugin->end = end_output_screen;

    /* Register plugin with input module. */
    if ((register_output_plugin(plugin)) == -1) {
	if (plugin != NULL)
	    free(plugin);
	log_message("warning:  'register_output_plugin' in function 'setup_output_screen' failed.");
    }

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION	: init_output_screen
 * DESCRIPTION	: This output module will initialize output
 *		: to the screen.
 * INPUT	: None
 * RETURN	: 0 - Success
 *		: -1 - Error
 * --------------------------------------------------------- */
int
init_output_screen (bstring args)
{
    verbose_message("Initializing SCREEN output processor.");

    /* Nothing to intialize! */

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION	: print_asset_screen
 * DESCRIPTION	: This function will print the specified
 *		: asset to the screen / output file.
 * INPUT	: 0 - Port
 *		: 1 - IP Address
 *		: 2 - Service
 *		: 3 - Application
 * RETURN	: 0 - Success
 *		: -1 - Error
 * ---------------------------------------------------------- */
int
print_asset_screen (Asset *rec)
{
    /* Print to Screen */
    fprintf(stdout, "[*] Asset Found:  Port - %d / Host - %s / Service - %s / Application - %s\n",
	    ntohs(rec->port), inet_ntoa(rec->ip_addr),
	    bdata(rec->service), bdata(rec->application));

    return 0;
}


/* ----------------------------------------------------------
 * FUNCTION	: print_arp_asset_screen
 * DESCRIPTION	: This function will print out the ARP asset
 *		: to the screen and to the report file.
 * INPUT	: 0 - IP Address
 *		: 1 - MAC Address
 * RETURN	: 0 - Success
 *		: -1 - Error
 * ---------------------------------------------------------- */
int
print_arp_asset_screen (ArpAsset *rec)
{
    /* Print to Screen */
    if(rec->mac_resolved != NULL) {
	fprintf(stdout, "[*] Asset Found:  IP Address - %s / MAC Address - %s (%s)\n",
		inet_ntoa(rec->ip_addr), hex2mac(rec->mac_addr), bdata(rec->mac_resolved));
    } else {
	fprintf(stdout, "[*] Asset Found:  IP Address - %s / MAC Address - %s\n",
		inet_ntoa(rec->ip_addr), hex2mac(rec->mac_addr));
    }

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION	: free_output_screen
 * DESCRIPTION	: This function will free the memory declared
 *		: by the screen output module.
 * INPUT	: None!
 * RETURN	: None!
 * ---------------------------------------------------------- */
int
end_output_screen ()
{
    verbose_message("Ending SCREEN Output Processor.");

    /* Nothing to end! */

    return 0;
}
