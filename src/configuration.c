/*************************************************************************
 * configuration.c
 *
 * Matt Shelton <matt@mattshelton.com>
 *
 * This module stores functions related to the configuration of the
 * pads project.
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
 * $Id: configuration.c,v 1.3 2005/04/27 13:50:29 mattshelton Exp $
 *
 **************************************************************************/
/* INCLUDES ---------------------------------------- */
#include "global.h"

#include <stdio.h>
#include <unistd.h>
#include "util.h"
#include "bstring/util.h"
#include "bstring/bstrlib.h"

#include "configuration.h"
#include "monnet.h"


/* Variable Declarations */

/* ----------------------------------------------------------
 * FUNCTION     : init_configuration
 * DESCRIPTION  : This function will read in and process a
 *              : specified configuration file.
 * INPUT        : 0 - Config File
 * RETURN       : None!
 * ---------------------------------------------------------- */
void init_configuration (bstring filename) {
    FILE *fp;
    bstring filedata;
    struct bstrList *lines;
    int i;

    verbose_message("config - Processing '%s'.", bdata(filename));

    if ((fp = fopen(bdata(filename), "r")) == NULL) {
        err_message("Unable to open configuration file - %s", bdata(filename));
    }

    /* Read file into 'filedata' and process it accordingly. */
    filedata = bread ((bNread) fread, fp);
    if ((lines = bsplit(filedata, '\n')) != NULL) {
        for (i = 0; i < lines->qty; i++) {
            parse_line(lines->entry[i]);
        }
    }

    /* Clean Up */
    bdestroy(filedata);
    bstrListDestroy(lines);
    fclose(fp);
}

/* ----------------------------------------------------------
 * FUNCTION     : parse_line
 * DESCRIPTION  : This function will process a line of data
 *              : from a configuration file.
 * INPUT        : 0 - Line (bstring)
 * ---------------------------------------------------------- */
void parse_line (bstring line)
{
    bstring param, value;
    struct bstrList *list;
    int i;

    /* Check to see if this line has something to read. */
    if (line->data[0] == '\0' || line->data[0] == '#')
       return;

    /* Check to see if this line has a comment in it. */
    if ((list = bsplit(line, '#')) != NULL) {
        if ((bassign(line, list->entry[0])) == -1) {
            log_message("warning:  'bassign' in function 'parse_line' failed.");
        }
        if (list != NULL)
            bstrListDestroy(list);
    }

    /* Seperate line into a parameter and a value. */
    if ((i = bstrchr(line, ' ')) == BSTR_ERR)
        return;
    if ((param = bmidstr(line, 0, i)) == NULL)
        return;
    if ((value = bmidstr(line, i + 1, line->slen - i)) == NULL)
        return;

    /* Normalize Strings */
    if ((btolower(param)) != 0)
        log_message("warning:  'btolower' in function 'parse_line' failed.");
    if ((bltrim(value)) != 0)
        log_message("warning:  'bltrim' in function 'parse_line' failed.");
    if ((brtrim(value)) != 0)
        log_message("warning:  'brtrim' in function 'parse_line' failed.");

    /* Do something based upon value. */
    if ((biseqcstr(param, "daemon")) == 1) {
        /* DAEMON */
        if (!gc.daemon_mode) {
            if (value->data[0] == '1')
                gc.daemon_mode = 1;
            else
                gc.daemon_mode = 0;
        }

    } else if ((biseqcstr(param, "pid_file")) == 1) {
            /* PID FILE */
        gc.pid_file = bstrcpy(value);

    } else if ((biseqcstr(param, "sig_file")) == 1) {
        /* SIGNATURE FILE */
        gc.sig_file = bstrcpy(value);
   
    } else if ((biseqcstr(param, "mac_file")) == 1) {
        /* MAC / VENDOR RESOLUTION FILE */
        gc.mac_file = bstrcpy(value);

    } else if ((biseqcstr(param, "output")) == 1) {
        /* OUTPUT */
        conf_module_plugin(value, &activate_output_plugin);

    } else if ((biseqcstr(param, "user")) == 1) {
        /* USER */
        gc.priv_user = bstrcpy(value);

    } else if ((biseqcstr(param, "group")) == 1) {
        /* GROUP */
        gc.priv_group = bstrcpy(value);

    } else if ((biseqcstr(param, "interface")) == 1) {
        /* INTERFACE */
        gc.dev = bstr2cstr(value, '-');

    } else if ((biseqcstr(param, "filter")) == 1) {
        /* FILTER */
        gc.pcap_filter = bstr2cstr(value, '-');

    } else if ((biseqcstr(param, "network")) == 1) {
        /* NETWORK */
        parse_networks(bdata(value));

    }

    verbose_message("config - PARAM:  |%s| / VALUE:  |%s|", bdata(param), bdata(value));

    /* Clean Up */
    if (param != NULL)
        bdestroy(param);
    if (value != NULL)
        bdestroy(value);
}

/* ----------------------------------------------------------
 * FUNCTION     : conf_module_plugin
 * DESCRIPTON   : This function takes a string retrieved from
 *              : the configuration file, breaks it in half
 *              : at the ':', and then sends it to the
 *              : appropriate function.
 * INPUT        : 0 - Value
 *              : 1 - Pointer to Function
 * RETURN       : 0 - Success
 *              : -1 - Error
 * ---------------------------------------------------------- */
int conf_module_plugin (bstring value, int (*ptrFunc)(bstring, bstring))
{
    struct bstrList *list;

    if (*ptrFunc == NULL)
        return -1;

    /* Split line in half.  There should only be one ':'. */
    if ((list = bsplit(value, ':')) != NULL) {
        if (list->qty > 1) {
            /* Input processor contains an argument. */
            if ((btrim(list->entry[1])) == -1)
                log_message("warning:  'btrim' in function 'conf_module_processor' faild.");
            if (((*ptrFunc)(list->entry[0], list->entry[1])) == -1)
                log_message("warning:  'ptrFunc' in function 'conf_module_processor' failed.");
        } else {
            /* Input processor does not contain an argument. */
            if (((*ptrFunc)(list->entry[0], bfromcstr(""))) == -1)
                log_message("warning:  'ptrFunc' in function 'conf_module_processor' failed.");
        }
        if (list != NULL)
            bstrListDestroy(list);

    } else {
        log_message("warning:  'split' in function 'conf_module_processor' failed.");
    }

    return 0;
}

/* vim:expandtab:cindent:smartindent:ts=4:tw=0:sw=4:
 */
