/*************************************************************************
 * util.h
 *
 * Matt Shelton	<matt@mattshelton.com>
 *
 * This header file contains information relating to the util.c module.
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
 * $Id: util.h,v 1.4 2005/02/22 16:09:25 mattshelton Exp $
 *
 **************************************************************************/

#include <bstring/bstrlib.h>

/* PROTOTYPES -------------------------------------- */
void strip_comment (char *string);
int chomp (char *string, int size);
void daemonize (void);
void init_pid_file (bstring pid_file, bstring user, bstring group);
char *copy_argv(register char **argv);
void log_message (const char *msg, ...);
void err_message (const char *msg, ...);
void verbose_message (const char *msg, ...);
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t size);
#endif
#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t len);
#endif
void drop_privs (bstring newuser, bstring newgroup);
void mac2hex(const char *mac, char *dst, int len);
char *hex2mac(unsigned const char *mac);
char *fasthex(u_char *, int);

/* GLOBALS ----------------------------------------- */
