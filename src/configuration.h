/*************************************************************************
 * configuration.h
 *
 * This module stores functions related to the configuration of the
 * pads project.
 *
 * The purpose of this system is to determine network assets by passively
 * listening to network traffic.
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
 * $Id: configuration.h,v 1.2 2005/02/18 05:50:19 mattshelton Exp $
 *
 **************************************************************************/

/* DEFINES ----------------------------------------- */
#ifdef LINUX
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#endif /* ifdef LINUX */


/* INCLUDES ---------------------------------------- */
#include "global.h"

#include <stdio.h>
#include "bstring/bstrlib.h"

/* PROTOTYPES -------------------------------------- */
void init_configuration (bstring conf_file);
void parse_line (bstring line);
int conf_module_plugin (bstring value, int (*ptrFunc)(bstring, bstring));

/* External Prototypes */
int activate_output_plugin (bstring name, bstring args);
