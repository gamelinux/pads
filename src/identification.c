/*************************************************************************
 *
 * identification.c
 *
 * Matt Shelton <matt@mattshelton.com>
 *
 * This module contains functions related to identifying an asset.
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
 * $Id: identification.c,v 1.5 2005/05/14 20:14:34 mattshelton Exp $
 *
 **************************************************************************/

/* INCLUDES ---------------------------------------- */
#include "global.h"
 
#include <stdio.h>
#include <signal.h>
 
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <unistd.h>
 
#include "identification.h"
#include "util.h"
#include "storage.h"
#include "output/output.h"

Signature *signature_list;

/* ----------------------------------------------------------
 * FUNCTION     : init_identification
 * DESCRIPTION  : This function will read the signature file
 *              : into the signature data structure.
 * INPUT        : 0 - Data Structure
 * RETURN       : -1 - Error
 *              : 0 - Normal Return
 * ---------------------------------------------------------- */
int init_identification()
{
    FILE *fp;
    bstring filename;
    bstring filedata;
    struct bstrList *lines;
    int i;

    /* Check for a PADS_SIGNATURE_LIST file within the current directory.  */
    if ((fp = fopen(PADS_SIGNATURE_LIST, "r")) != NULL) {
        filename = bformat("./%s", PADS_SIGNATURE_LIST);
        fclose(fp);
    } else if (gc.sig_file != NULL) {
        filename = bstrcpy(gc.sig_file);

    } else {
        filename = bformat("%s/%s", INSTALL_SYSCONFDIR, PADS_SIGNATURE_LIST);
    }

    /* Open Signature File */
    if ((fp = fopen(bdata(filename), "r")) == NULL) {
        err_message("Unable to open signature file - %s", bdata(filename));
    }

    /* Read file into 'filedata' and process it accordingly. */
    filedata = bread ((bNread) fread, fp);
    if ((lines = bsplit(filedata, '\n')) != NULL) {
        for (i = 0; i < lines->qty; i++) {
            parse_raw_signature(lines->entry[i], i + 1);
        }
    }

    /* Clean Up */
    bdestroy(filename);
    bdestroy(filedata);
    bstrListDestroy(lines);
    fclose(fp);

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION     : parse_raw_signature
 * DESCRIPTION  : This function will take a line from the
 *              : signature file and parse it into it's data
 *              : structure.
 * INPUT        : 0 - Raw Signature (bstring)
 *              : 1 - The line number this signature is on.
 * RETURN       : 0 - Success
 *              : -1 - Error
 * ---------------------------------------------------------- */
int parse_raw_signature (bstring line, int lineno)
{
    struct bstrList *raw_sig;
    struct bstrList *title = NULL;
    Signature *sig;
    bstring pcre_string = NULL;
    const char *err;            /* PCRE */
    int erroffset;              /* PCRE */
    int ret = 0;
    int i;

    /* Check to see if this line has something to read. */
    if (line->data[0] == '\0' || line->data[0] == '#')
        return -1;

    /* Split Line */
    if ((raw_sig = bsplit(line, ',')) == NULL)
        return -1;

    /* Reconstruct the PCRE string.  This is needed in case there are PCRE
     * strings containing commas within them. */
    if (raw_sig->qty < 3) {
        ret = -1;
    } else if (raw_sig->qty > 3) {
        pcre_string = bstrcpy(raw_sig->entry[2]);
        for (i = 3; i < raw_sig->qty; i++) {
            if ((bconcat(pcre_string, bfromcstr(","))) == BSTR_ERR)
                ret = -1;
            if ((bconcat(pcre_string, raw_sig->entry[i])) == BSTR_ERR)
                ret = -1;
        }
    } else {
        pcre_string = bstrcpy(raw_sig->entry[2]);
    }

    /* Split Title */
    if (raw_sig->entry[1] != NULL && ret != -1)
        if ((title = bsplit(raw_sig->entry[1], '/')) == NULL)
            ret = -1;
    if (title->qty < 3)
        ret = -1;

    /* Create signature data structure for this record. */
    if (ret != -1) {
        sig = (Signature*)malloc(sizeof(Signature));
        sig->next = NULL;
        if (raw_sig->entry[0] != NULL)
            sig->service = bstrcpy(raw_sig->entry[0]);
        if (title->entry[1] != NULL)
            sig->title.app = bstrcpy(title->entry[1]);
        if (title->entry[2] != NULL)
            sig->title.ver = bstrcpy(title->entry[2]);
        if (title->entry[3] != NULL)
            sig->title.misc = bstrcpy(title->entry[3]);

        /* PCRE */
        if (pcre_string != NULL) {
            if ((sig->regex = pcre_compile (bdata(pcre_string), 0, &err, &erroffset, NULL)) == NULL) {
                err_message("Unable to compile signature:  %s at line %d (%s)",
                err, lineno, bdata(line));
            ret = -1;
        }
    }
    if (ret != -1) {
        sig->study = pcre_study (sig->regex, 0, &err);
        if (err != NULL)
            err_message("Unable to study signature:  %s", err);
    }

    /* Add signature to 'signature_list' data structure. */
    if (ret != -1)
        add_signature (sig);
    }

    /* Garbage Collection */
    if (raw_sig != NULL)
        bstrListDestroy(raw_sig);
    if (title != NULL)
        bstrListDestroy(title);
    if (pcre_string != NULL)
        bdestroy(pcre_string);

    return ret;
}

/* ----------------------------------------------------------
 * FUNCTION     : add_signature
 * DESCRIPTION  : This function will add a signature to the
 *              : signature list.
 * INPUT        : 0 - Signature Data Structure
 * RETURN       : 0 - Success
 *              : -1 - Error
 * ---------------------------------------------------------- */
int add_signature (Signature *sig)
{
    Signature *list;

    if (signature_list == NULL) {
        signature_list = sig;
    } else {
        list = signature_list;
        while (list != NULL) {
            if (list->next == NULL) {
                list->next = sig;
                break;
            } else {
                list = list->next;
            }
        }
    }

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION     : tcp_identify
 * DESCRIPTION  : This function will take a TCP payload and
 *              : match it against the signature base.
 * INPUT        : 0 - IP Address
 *              : 1 - TCP Port
 *              : 2 - Packet Payload
 *              : 3 - Packet Payload Length
 * RETURN       : 0 - i_attempts = 0
 *              : 1 - i_attempts > 0
 * ---------------------------------------------------------- */
int tcp_identify (struct in_addr ip_addr,
           u_int16_t port,
           char *payload,
           int plen)
{
    unsigned short i_attempts;
    char *hex_payload;


    /* Retrieve i_attempts for this asset. */
    i_attempts = get_i_attempts(ip_addr, port, IPPROTO_TCP);

    if (i_attempts > 0) {
        i_attempts--;
        update_i_attempts(ip_addr, port, IPPROTO_TCP, i_attempts);

        hex_payload = fasthex((u_char *) payload, plen); 
        add_hex_payload(ip_addr, port, IPPROTO_TCP, hex_payload);

        if (pcre_identify(ip_addr, port, IPPROTO_TCP, payload, plen) == 1) {
            /* MATCH! */
            i_attempts = 0;
            update_i_attempts(ip_addr, port, IPPROTO_TCP, 0);
        }

        /* Print asset if this is the last time to identify it. */
        if (i_attempts == 0) {
            print_asset(ip_addr, port, IPPROTO_TCP);
        }

        return 1;
    }

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION     : pcre_identify
 * DESCRIPTION  : This function will match a string against
 *              : all the known signatures.
 * INPUT        : 0 - IP Address
 *              : 1 - Port
 *              : 2 - Proto
 *              : 3 - Payload
 *              : 4 - Payload Length
 * RETURN       : 0 - Not Matched
 *              : 1 - Matched
 * ---------------------------------------------------------- */
int pcre_identify (struct in_addr ip_addr,
           u_int16_t port,
           unsigned short proto,
           const char *payload,
           int plen)
{
    Signature *list = signature_list;
    int rc;
    int ovector[15];
    bstring app;

    while (list != NULL) {
        /* Execute Regular Expression */
        rc = pcre_exec(list->regex, list->study, payload, plen,
            0, 0, ovector, 15);

        if (rc != -1) {
            app = get_app_name(list, payload, ovector, rc);
            update_asset(ip_addr, port, proto, list->service, app);
            return 1;
        }

        list = list->next;
    }

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION     : get_app_name
 * DESCRIPTION  : This function will take the results of a
 *              : pcre match and compile the application name
 *              : based off of the signature.
 * INPUT        : 0 - Signature Pointer
 *              : 1 - payload
 *              : 2 - ovector
 *              : 3 - rc (return from pcre_exec)
 * RETURN       : processed app name
 * ---------------------------------------------------------- */
bstring get_app_name (Signature *sig,
            const char *payload,
            int *ovector,
            int rc)
{
    char sub[100];
    char app[5000];
    char expr[100];
    bstring retval;
    int i = 0;
    int n = 0;
    int x = 0;
    int z = 0;

    /* Create Application string using the values in signature[i].title.  */
    if (sig->title.app != NULL) {
        strlcpy(app, bdata(sig->title.app), MAX_APP);
    }
    if (sig->title.ver != NULL) {
        if (sig->title.ver->slen > 0) {
            strcat(app, " ");
            strlcat(app, bdata(sig->title.ver), MAX_VER);
        }
    }
    if (sig->title.misc != NULL) {
        if (sig->title.misc->slen > 0) {
            strcat(app, " (");
            strlcat(app, bdata(sig->title.misc), MAX_MISC);
            strcat(app, ")");
        }
    }

    /* Replace $1, $2, etc. with the appropriate substring.  */
    while (app[i] != '\0' && z < (sizeof(sub) - 1)) {
        /* Check to see if the string contains a $? mark variable. */
        if (app[i] == '$') {
            /* Yes it does, replace it with the appropriate match string. */
            i++;
            n = atoi(&app[i]);

            pcre_copy_substring(payload, ovector, rc, n, expr, sizeof(expr));
            x = 0;
            while (expr[x] != '\0' && z < (sizeof(sub) - 1)) {
                sub[z] = expr[x];
                z++;
                x++;
            }
            for (x = 0; x < sizeof(expr); x++)
                expr[x] = '\0';
            i++;
        } else {
            /* No it doesn't, copy to new string. */
            sub[z] = app[i];
            i++;
            z++;
        }
    }
    sub[z] = '\0';

    retval = bstrcpy(bfromcstr(sub));
    return retval;

}

/* ----------------------------------------------------------
 * FUNCTION     : end_identification
 * DESCRIPTION  : This function will free the signatures
 *              : data structure from memory.
 * INPUT        : None!
 * RETURN       : None!
 * ---------------------------------------------------------- */
void end_identification()
{
    Signature *next;

    /* Free records in signature_list (signature). */
    while (signature_list != NULL) {
        next = signature_list->next;

        /* Free bstring allocations. */
        if (signature_list->service != NULL)
            bdestroy(signature_list->service);
        if (signature_list->title.app != NULL)
            bdestroy(signature_list->title.app);
        if (signature_list->title.ver != NULL)
            bdestroy(signature_list->title.ver);
        if (signature_list->title.misc != NULL)
            bdestroy(signature_list->title.misc);

        /* Free Record */
        if (signature_list != NULL)
            free (signature_list);

        signature_list = next;
    }
}

/* ----------------------------------------------------------
 * FUNCTION     : print_signature
 * DESCRIPTION  : This function will print out all of the
 *              : signatures stored in the signature data
 *              : structure.
 * INPUT        : None!
 * RETURN       : None!
 * ---------------------------------------------------------- */
#ifdef DEBUG
void print_signature()
{
    Signature *list = signature_list;
    int i = 1;

    if (list == NULL)
        printf("There are no signatures!\n");

    while (list != NULL) {
        printf("[ %d ] ------------------\n", i);
        printf("1:  %s\n", bdata(list->service));
        printf("2a: %s\n", bdata(list->title.app));
        printf("2b: %s\n", bdata(list->title.ver));
        printf("2c: %s\n", bdata(list->title.misc));
        printf("3:  %s\n", (char *)list->regex);
        printf("\n");

        i++;
        list = list->next;
    }
}
#endif /* DEBUG */

/* vim:expandtab:cindent:smartindent:ts=4:tw=0:sw=4:
 */
