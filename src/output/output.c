/*************************************************************************
 * output.c
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
 * $Id: output.c,v 1.3 2005/02/18 05:39:09 mattshelton Exp $
 *
 **************************************************************************/

/* INCLUDES ---------------------------------------- */
#include "global.h"

#include <stdio.h>

#include "output.h"
#include "output-screen.h"
#include "output-fifo.h"
#include "output-csv.h"
#include "storage.h"

/* Global Variables */
OutputPluginList *output_plugin_list;

/* ----------------------------------------------------------
 * FUNCTION	: init_output()
 * DESCRIPTION	: This function will initialize the output
 *		: module.  It will register each output
 *		: plugin with the output_plugin_list data
 *		: structure.
 * INPUT	: None!
 * RETURN	: None!
 * ---------------------------------------------------------- */
void init_output()
{

    /* Load Screen Plug-in */
    setup_output_screen();

    /* Load CSV Plug-in */
    setup_output_csv();

    /* Load FIFO Plug-in */
    setup_output_fifo();

}

/* ----------------------------------------------------------
 * FUNCTION	: register_output_plugin
 * DESCRIPTION	: This function will be called by each output
 *		: plugin.  It will register the plugin with
 *		: the output module.
 * INPUT	: 0 - OutputPlugin Data Structure
 * RETURN	: 0 - Success
 *		: -1 - Error
 * ---------------------------------------------------------- */
int register_output_plugin (OutputPlugin *plugin)
{
    OutputPluginList *head, *list;

    if (plugin == NULL)
	return -1;

    /* Create OutputPluginList Record */
    list = (OutputPluginList*)malloc(sizeof(OutputPluginList));
    list->plugin = plugin;
    list->active = 0;
    list->next = NULL;

    /* Place plugin in data structure. */
    if (output_plugin_list == NULL) {
	output_plugin_list = list;
    } else {
	head = output_plugin_list;
	while (head != NULL) {
	    if (head->next == NULL) {
		head->next = list;
		break;
	    } else {
		head = head->next;
	    }
	}
    }

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION     : activate_output_plugin
 * DESCRIPTION  : This function will set the active bit on
 *		: the specified output plugin.  Afterwards,
 *		: it will run the init() function for the
 *		: plugin.
 * INPUT        : 0 - Plugin Name
 *              : 1 - Arguments
 * RETURN       : 0 - Success
 *              : -1 - Failure
 * ---------------------------------------------------------- */
int activate_output_plugin (bstring name, bstring args)
{
    OutputPluginList *list;
    OutputPlugin *plugin;

    /* Search 'output_plugin_list' for this output processor. */
    list = output_plugin_list;
    while (list != NULL) {
	plugin = list->plugin;

	/* Compare this record's name with the name passed to the function. */
	if ((biseq(plugin->name, name)) == 1) {
	    /* MATCH! Set record to active and run 'init' function. */
	    list->active = 1;
	    if (plugin != NULL && plugin->init != NULL)
		(*plugin->init)(args);
	    break;
	}

	list = list->next;
    }

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION	: print_asset
 * DESCRIPTION	: This function is an interface between the
 *		: output modules and the rest of the PADS
 *		: application.  It will print out a standard
 *		: asset.
 * INPUT	: 0 - IP Address
 *		: 1 - Port
 *		: 2 - Proto
 *              : 3 - Hex Payload
 * RETURN	: 0 - Success
 *		: -1 - Error
 * ---------------------------------------------------------- */
int print_asset (struct in_addr ip_addr, u_int16_t port, unsigned short proto)
{
    OutputPluginList *head;
    Asset *rec;

    rec = (Asset *)find_asset(ip_addr, port, proto);

    /* Make sure that a record was found. */
    if (rec == NULL)
	return -1;

    /* Cycle through output plugins and print to those that are active. */
    head = output_plugin_list;
    while (head != NULL) {
	/* Only print to active plugins. */
	if (head->active == 1) {
	    if (head->plugin->print_asset)
		(*head->plugin->print_asset)(rec);
	}

	head = head->next;
    }

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION     : print_arp_asset
 * DESCRIPTION  : This function is an interface between the
 *		: output modules and the rest of the PADS
 *		: application.  It will print out a standard
 *		: asset.
 * INPUT        : 0 - IP Address
 *              : 1 - MAC Address
 * RETURN	: None!
 * ---------------------------------------------------------- */
int print_arp_asset (struct in_addr ip_addr, char mac_addr[MAC_LEN])
{
    OutputPluginList *head;

    /* Find Asset */
    ArpAsset *list;
    ArpAsset *rec = NULL;

    list = (ArpAsset *)get_arp_pointer();
    while (list != NULL) {
	if (ip_addr.s_addr == list->ip_addr.s_addr
               && (memcmp(mac_addr, list->mac_addr, MAC_LEN) == 0)) {

	    /* Found! */
	    rec = list;
	    break;
	} else {
	    list = list->next;
	}
    }

    /* Make sure that a record was found. */
    if (rec == NULL)
	return -1;

    /* Cycle through output plugins and print to those that are active. */
    head = output_plugin_list;
    while (head != NULL) {
	/* Only print to active plugins. */
	if (head->active == 1) {
	    if (head->plugin->print_arp)
		(*head->plugin->print_arp)(rec);
	}

	head = head->next;
    }

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION	: print_stat
 * DESCRIPTION	: This function will print connection
 *		: information.
 * INPUT	: 0 - IP Address
 *		: 1 - Port
 *		: 2 - Proto
 * RETURN	: -1 - Error
 * ---------------------------------------------------------- */
int print_stat(struct in_addr ip_addr, u_int16_t port, unsigned short proto)
{
    OutputPluginList *head;
    Asset *rec;

    rec = (Asset *)find_asset(ip_addr, port, proto);

    /* Make sure that a record was found. */
    if (rec == NULL)
	return -1;

    /* Cycle through output plugins and print to those that are active. */
    head = output_plugin_list;

    while (head != NULL) {
	/* Only print to active plugins. */
	if (head->active == 1) {
	    if (head->plugin->print_stat)
		(*head->plugin->print_stat)(rec);
	}

	head = head->next;
    }

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION	: end_output
 * DESCRIPTION	: This function will shutdown the output
 *		: module.
 * INPUT	: None
 * RETURN	: None
 * ---------------------------------------------------------- */
void end_output (void)
{
    OutputPluginList *head, *next;
    OutputPlugin *tmp;

    /* Run the 'end' function for each active plugin. */
    head = output_plugin_list;
    while (head != NULL) {
	/* Only run active output plugins. */
	if (head->active == 1) {
	    tmp = head->plugin;
	    if (tmp != NULL && tmp->end != NULL)
		(*tmp->end)();
	}

	head = head->next;
    }
    tmp = NULL;

    /* Free the 'output_plugin_list' data structure. */
    while (output_plugin_list != NULL) {
	next = output_plugin_list->next;

	/* Free OutputPlugin Record */
	tmp = output_plugin_list->plugin;
	if (tmp != NULL && tmp->name != NULL)
	    bdestroy(tmp->name);
	if (tmp != NULL)
	    free(tmp);

	/* Free OutputPluginList Record */
	free(output_plugin_list);
	output_plugin_list = next;
    }
}

#ifdef DEBUG
int debug_output_list (void)
{
    OutputPluginList *head;
    OutputPlugin *tmp;
    int i = 1;

    printf("output_plugin_list:\n");

    head = output_plugin_list;

    while (head != NULL) {
	tmp = head->plugin;
	printf("D1:  %d - (%d) - %s\n", i, head->active, bdata(tmp->name));
	i++;
	head = head->next;
    }

    return 0;
}
#endif
