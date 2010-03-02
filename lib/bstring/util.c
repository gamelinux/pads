/*************************************************************************
 * bstring/util.c
 *
 * Matt Shelton <matt@mattshelton.com>
 *
 * This file contains utility functions to the Better String Library.
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
 * $Id: util.c,v 1.1 2005/02/13 17:54:58 mattshelton Exp $
 *
 **************************************************************************/
#include "util.h"

/* ----------------------------------------------------------
 * FUNCTION	: bltrim
 * DESCRIPTION	: This function will trim the whitespace from
 *		: the left side of a string.
 * INPUT	: 0 - String
 * ---------------------------------------------------------- */
int bltrim (bstring string)
{
    int i;
    int len = 0;

    /* Find Whitespace */
    for (i = 0; i < string->slen; i++) {
	if (string->data[i] == ' ' || string->data[i] == '\t')
	    len++;
	else
	    break;
    }

    /* Remove Whitespace */
    if (len > 0)
	bdelete(string, 0, len);

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION	: brtrim
 * DESCRIPTION	: This function will trim the whitespace from
 *		: the right side of a string.
 * INPUT	: 0 - String
 * ---------------------------------------------------------- */
int brtrim (bstring string)
{
    int i;
    int len = 0;

    /* Find Whitespace */
    for (i = (string->slen - 1); i > 0; i--) {
	if (string->data[i] == ' ' || string->data[i] == '\t')
	    len++;
	else
	    break;
    }

    /* Remove Whitespace */
    if (len > 0)
	bdelete(string, i + 1, len);

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION	: btrim
 * DESCRIPTION	: This function will trim the whitespace from
 *		: both sides of a bstring.
 * INPUT	: 0 - String
 * ---------------------------------------------------------- */
int btrim (bstring string)
{
    if ((bltrim(string)) != 0)
	return -1;
    if ((brtrim(string)) != 0)
	return -1;
    return 0;
}

