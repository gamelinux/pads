/*************************************************************************
 * output-fifo.h
 *
 * Matt Shelton	<matt@mattshelton.com>
 *
 * This output module will write data to a FIFO named pipe.  This will
 * allow external applications access to PADS data in real-time.
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
 * $Id: output-fifo.h,v 1.3 2005/02/18 05:39:09 mattshelton Exp $
 *
 **************************************************************************/


/* TYPEDEFS ---------------------------------------- */
typedef struct _OutputFIFOConf
{
    FILE *file;		/* File Reference */
    bstring filename;	/* File's OS name */
} OutputFIFOConf;


/* GLOBAL VARIABLES -------------------------------- */


/* PROTOTYPES -------------------------------------- */
int setup_output_fifo (void);
int init_output_fifo (bstring fifo_file);
int print_asset_fifo (Asset *rec);
int print_arp_asset_fifo (ArpAsset *rec);
int print_stat_fifo (Asset *rec);
int end_output_fifo (void);
const char *u_ntop(const struct in6_addr ip_addr, int af, char *dest);

