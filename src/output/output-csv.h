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
 * $Id: output-csv.h,v 1.3 2005/02/18 05:39:09 mattshelton Exp $
 *
 **************************************************************************/


/* TYPEDEFS ---------------------------------------- */
typedef struct _OutputCSVConf
{
    FILE *file;
    bstring filename;
} OutputCSVConf;


/* GLOBAL VARIABLES -------------------------------- */
/* extern _OutputCSVConf OutputCSVConf; */


/* PROTOTYPES -------------------------------------- */
int setup_output_csv (void);
int init_output_csv (bstring filename);
void read_report_file (void);
int parse_raw_report (bstring line);
int print_asset_csv (Asset *rec);
int print_arp_asset_csv (ArpAsset *rec);
int end_output_csv (void);
