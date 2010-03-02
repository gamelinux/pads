/*************************************************************************
 * identification.h
 *
 * Matt Shelton	<matt@mattshelton.com>
 *
 * This header file contains information relating to the identification.c
 * module.
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
 * $Id: identification.h,v 1.2 2005/02/13 18:28:28 mattshelton Exp $
 *
 **************************************************************************/

/* INCLUDES ---------------------------------------- */
#include <stdio.h>
#include <signal.h>

#include "global.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>


/* PROTOTYPES -------------------------------------- */
int init_identification(void);
int parse_raw_signature (bstring line, int lineno);
int add_signature (Signature *sig);
int tcp_identify (struct in_addr ip_addr, u_int16_t port, char *payload, int plen);
int pcre_identify (struct in_addr ip_addr, u_int16_t port, unsigned short proto, const char *payload, int plen);
bstring get_app_name (Signature *sig, const char *payload, int *ovector, int rc);
void end_identification (void);

#ifdef DEBUG
void print_signature();
#endif /* DEBUG */

/* GLOBALS ----------------------------------------- */
