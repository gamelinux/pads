/*************************************************************************
 *
 * mac-resolution.h
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
 * $Id: mac-resolution.h,v 1.3 2005/02/16 01:47:35 mattshelton Exp $
 *
 **************************************************************************/

/* DEFINES ----------------------------------------- */

/* INCLUDES ---------------------------------------- */
#include <stdio.h>
#include "global.h"


/* PROTOTYPES -------------------------------------- */
int init_mac_resolution (void);
int parse_raw_mac (bstring line);
int add_vendor (char *mac, char *vendor);
bstring get_vendor (char *m);
void end_mac_resolution (void);

#ifdef DEBUG
void show_vendor (void);
#endif /* DEBUG */
