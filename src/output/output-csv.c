/*************************************************************************
 * output-csv.c
 *
 * Matt Shelton	<matt@mattshelton.com>
 *
 * This output module writes PADS data to a CSV file.
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
 * $Id: output-csv.c,v 1.6 2005/02/22 16:09:25 mattshelton Exp $
 *
 **************************************************************************/
 
/* INCLUDES ---------------------------------------- */
#include "global.h"
 
#include <stdio.h>
#include <arpa/inet.h>
 
#include "output.h"
#include "output-csv.h"
#include "util.h"

OutputCSVConf output_csv_conf;

/* ----------------------------------------------------------
 * FUNCTION	: setup_output_csv
 * DESCRIPTION	: This function will register the output
 *		: plugin.
 * INPUT	: None!
 * RETURN	: 0 - Success
 *		: -1 - Error
 * ---------------------------------------------------------- */
int
setup_output_csv (void)
{
    OutputPlugin *plugin;

    /* Allocate and setup plugin data record. */
    plugin = (OutputPlugin*)malloc(sizeof(OutputPlugin));
    plugin->name = bstrcpy(bfromcstr("csv"));
    plugin->init = init_output_csv;
    plugin->print_asset = print_asset_csv;
    plugin->print_arp = print_arp_asset_csv;
    plugin->print_stat = NULL;
    plugin->end = end_output_csv;

    /* Register plugin with input module. */
    if ((register_output_plugin(plugin)) == -1) {
	if (plugin != NULL)
	    free(plugin);
	log_message("warning:  'register_output_plugin' in function 'setup_output_csv' failed.");
    }

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION	: init_output_csv
 * DESCRIPTION	: This function will initialize the output
 *		: CSV file.  If the file already exists, it
 *		: will read in the file and add each asset
 *		: to the asset data structure.
 * INPUT	: 0 - CSV filename
 * RETURN	: None!
 * --------------------------------------------------------- */
int
init_output_csv (bstring filename)
{
    FILE *fp;

    verbose_message("Initializing CSV output plugin.");

    /* Make sure filename isn't NULL. */
    if (filename != NULL)
	output_csv_conf.filename = bstrcpy(filename);
    else
	output_csv_conf.filename = bstrcpy(bfromcstr("assets.csv"));

    /* Check to see if *filename exists. */
    if ((fp = fopen(bdata(output_csv_conf.filename), "r")) == NULL) {

	/* File does not exist, create new.. */
	if ((output_csv_conf.file = fopen(bdata(output_csv_conf.filename), "w")) != NULL) {
	    fprintf(output_csv_conf.file, "asset,port,proto,service,application,discovered\n");

	} else {
	    err_message("Cannot open file %s!", bdata(output_csv_conf.filename));
	}

    } else {

	/* File does exist, read it into data structure. */
	fclose(fp);
	read_report_file();

	/* Open file and assign it to the global FILE pointer.  */
	if ((output_csv_conf.file = fopen(bdata(output_csv_conf.filename), "a")) == NULL) {
	    err_message("Cannot open file %s!", bdata(output_csv_conf.filename));
	}
    }

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION	: read_report_file
 * DESCRIPTION	: This function will read in a specified
 *		: report CSV file.  It will then break a part
 *		: the line and add the assets to the
 *		: specified asset data structure.
 * INPUT	: None
 * RETURN	: None
 * ---------------------------------------------------------- */
void
read_report_file (void)
{
    FILE *fp;
    bstring filedata;
    struct bstrList *lines;
    int i;

    printf("[-] Processing Existing %s\n", bdata(output_csv_conf.filename));

    /* Open Signature File */
    if ((fp = fopen(bdata(output_csv_conf.filename), "r")) == NULL) {
	err_message("Unable to open CSV file - %s", bdata(output_csv_conf.filename));
    }

    /* Read file into 'filedata' and process it accordingly. */
    filedata = bread ((bNread) fread, fp);
    if ((lines = bsplit(filedata, '\n')) != NULL) {
	for (i = 0; i < lines->qty; i++) {
	    parse_raw_report(lines->entry[i]);
	}
    }

    /* Clean Up */
    bdestroy(filedata);
    bstrListDestroy(lines);
    fclose(fp);
}

/* ----------------------------------------------------------
 * FUNCTION	: parse_raw_report
 * DESCRIPTION	: This function will parse through a single
 *		: line of the CSV file.
 * INPUT	: 0 - Raw Line
 * RETURN	: 0 - Sucess
 *		: -1 - Error
 * ---------------------------------------------------------- */
int
parse_raw_report (bstring line)
{
    struct bstrList *list;
    int ret = 0;

    /* Temporary Storage */
    struct in_addr ip_addr;
    char mac_addr[MAC_LEN];
    int port;
    int proto;
    bstring service;
    bstring application;
    time_t discovered;

    /* Check to see if this line has something to read. */
    if (line->data[0] == '\0' || line->data[0] == '#')
	return -1;

    /* Break line apart. */
    if ((list = bsplit(line, ',')) == NULL)
	return -1;

    /* Check to see if this line contains the header. */
    if ((biseqcstr(list->entry[0], "asset")) == 1) {
	if (list != NULL)
	    bstrListDestroy(list);
	return -1;
    }

    /* Place data from 'list' into temporary data storage. */
    if ((inet_aton(bdata(list->entry[0]), &ip_addr)) == -1)
	ret = -1;

    if ((port = htons(atoi(bdata(list->entry[1])))) == -1)
	ret = -1;

    if ((proto = atoi(bdata(list->entry[2]))) == -1)
	ret = -1;

    if ((service = bstrcpy(list->entry[3])) == NULL)
	ret = -1;

    if ((application = bstrcpy(list->entry[4])) == NULL)
        ret = -1;

    if ((discovered = atol(bdata(list->entry[5]))) == -1)
	ret = -1;

    /* Make sure that this line contains 'good' data. */
    if (service->slen == 0 || application->slen == 0 || discovered <= 0)
        ret = -1;

    /* Add Asset to Data Structure */
    if (proto == 0 && ret != -1) {
	/* ARP */
	mac2hex(bdata(application), mac_addr, MAC_LEN);
	add_arp_asset(ip_addr, mac_addr, discovered);
    } else {
	/* Everything Else */
	add_asset_csv(ip_addr, port, proto, service, application, discovered);
    }

    // Clean Up
    if (list != NULL)
	bstrListDestroy(list);
    if (service != NULL)
	bdestroy(service);
    if (application != NULL)
	bdestroy(application);

    return ret;
}

/* ----------------------------------------------------------
 * FUNCTION	: print_asset_csv
 * DESCRIPTION	: This function will print an asset to the
 *		: CSV file.
 * INPUT	: 0 - Port
 *		: 1 - IP  Address
 *		: 2 - Protocol
 *		: 3 - Service
 *		: 4 - Application
 *		: 5 - Discovered
 * RETURN	: 0 - Success
 *		: -1 - Failure
 * ---------------------------------------------------------- */
int
print_asset_csv (Asset *rec)
{
    if (output_csv_conf.file != NULL) {
	if (gc.hide_unknowns == 0 || ((biseqcstr(rec->service, "unknown") != 0) &&
		    (biseqcstr(rec->application, "unknown") != 0))) {
	    fprintf(output_csv_conf.file, "%s,%d,%d,%s,%s,%d\n",
		    inet_ntoa(rec->ip_addr), ntohs(rec->port), rec->proto, bdata(rec->service),
		    bdata(rec->application), (int)rec->discovered);
	    fflush(output_csv_conf.file);
	}
    } else {
	fprintf(stderr, "[!] ERROR:  File handle not open!\n");
	return -1;
    }

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION	: print_arp_asset_csv
 * DESCRIPTION	: This function will print an ARP asset to
 *		: the CSV file.
 * INPUT	: 0 - IP Address
 *		: 1 - MAC Address
 *		: 2 - MAC Resolved
 * RETURN	: 0 - Success
 *		: -1 - Error
 * ---------------------------------------------------------- */
int
print_arp_asset_csv (ArpAsset *rec)
{
    /* Print to File */
    if (output_csv_conf.file != NULL) {
	if (rec->mac_resolved != NULL) {
	    fprintf(output_csv_conf.file, "%s,0,0,ARP (%s),%s,%d\n", inet_ntoa(rec->ip_addr),
		    bdata(rec->mac_resolved), hex2mac(rec->mac_addr), (int)rec->discovered);
	} else {
	    fprintf(output_csv_conf.file, "%s,0,0,ARP,%s,%d\n", inet_ntoa(rec->ip_addr),
		    hex2mac(rec->mac_addr), (int)rec->discovered);
	}

	fflush(output_csv_conf.file);
    } else {
	fprintf(stderr, "[!] ERROR:  File handle not open!\n");
	return -1;
    }

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION	: end_output_csv
 * DESCRIPTION	: This function will free the memory declared
 *		: by the screen output module.
 * INPUT	: None!
 * OUTPUT	: None!
 * ---------------------------------------------------------- */
int
end_output_csv ()
{
    verbose_message("Ending CSV Output Plugin.");
    verbose_message("Closing CSV File.");

    if (output_csv_conf.file != NULL)
	fclose(output_csv_conf.file);

    if (output_csv_conf.filename != NULL)
	bdestroy(output_csv_conf.filename);

    return 0;
}

