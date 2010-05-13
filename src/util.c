/*************************************************************************
 *
 * util.c
 *
 * Matt Shelton <matt@mattshelton.com>
 *
 * This module contains functions miscellaneous utility functions.
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
 * $Id: util.c,v 1.6 2005/03/11 01:31:15 mattshelton Exp $
 *
 **************************************************************************/

/* INCLUDES ---------------------------------------- */
#include "global.h"

#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <strings.h>
#include <grp.h>
#include <pwd.h>
#include <syslog.h>
#include <unistd.h>
#include <ctype.h>

#include "util.h"
#include "pads.h"

/* ----------------------------------------------------------
 * FUNCTION     : strip_comment
 * DESCRIPTION  : This function will strip out anything after
 *              : a '#' within a field.
 * INPUT        : 0 - String
 * RETURN       : 1 - String
 * ---------------------------------------------------------- */
void
strip_comment (char *string)
{
    char *pos;

    while ((pos = (char *)strchr(string, '#')) != NULL) {
        while (*pos != '\r' && *pos != '\n' && *pos != '\0') {
            *pos++ = ' ';
        }
    }
}

/* ----------------------------------------------------------
 * FUNCTION    : chomp
 * DESCRIPTION : This function is similar to Perl's 'chomp'
 *             : command.  It will strip off the '\n'
 *             : closest to the end of the string.
 * INPUT       : 0 - String
 *             : 1 - Size of String
 * RETURN      : 0 - '\n' removed
 *             : 1 - '\n' was never there
 * ---------------------------------------------------------- */
int
chomp (char *string, int size)
{
    for ( ; size >= 0; size--) {
        if (string[size] == '\n') {
            string[size] = '\0';
            return 1;
        }
    }

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION     : daemonize
 * DESCRIPTION  : This function will place the application in
 *              : the background.
 * INPUT        : None!
 * RETURN       : None!
 * ---------------------------------------------------------- */
void
daemonize ()
{
    pid_t pid;

    printf("[-] Daemonizing...\n");

    pid = fork();
    if (pid > 0) {
        /* Parent */
        exit(0);
    } else if (pid < 0) {
        /* Error */
        err_message("fork");
        exit(0);
    } else {
        /* Child */
        setsid();
        close(0);
        close(1);
        close(2);
    }
}

/* ----------------------------------------------------------
 * FUNCTION     : init_pid_file
 * DESCRIPTION  : This function will generate a file
 *              : containing the application's PID.
 * INPUT        : 0 - PID filename
 * RETURN       : None!
 * ---------------------------------------------------------- */
void
init_pid_file (bstring pid_file, bstring user, bstring group)
{
    int pid;
    FILE *fp;
    struct group *this_group;
    struct passwd *this_user;
printf("%s\n",bdata(gc.pid_file));
    /* Default PID File */
    if (gc.pid_file->slen <= 0)
        gc.pid_file = bfromcstr("/var/run/pads.pid");

    /* Create PID File */
    if ((fp = fopen(bdata(gc.pid_file), "w")) != NULL) {
        pid = (int) getpid();
        fprintf(fp, "%d\n", pid);
        fclose(fp);
    } else {
        err_message("Unable to create PID file (%s).\n", bdata(gc.pid_file));
    }

    /* Change PID File's Ownership */
    if (user == NULL || group == NULL)
        return;

    if ((this_group = getgrnam(bdata(group))) == NULL)
        err_message("'%s' group does not appear to exist.", bdata(group));
    if ((this_user = getpwnam(bdata(user))) == NULL)
        err_message("'%s' user does not appear to exist.", bdata(user));
    if ((chown(bdata(pid_file), this_user->pw_uid, this_group->gr_gid)) != 0)
        err_message("Unable to change PID file's ownership.");

}

/* ----------------------------------------------------------
 * FUNCTION     : copy_argv
 * DESCRIPTION  : This function will flatten argv into a
 *              : single string.  This function was taken
 *              : from the tcpdump source code.  Hopefully
 *              : someday I will get around to rewriting it.
 * INPUT        : 0 - argv
 * ---------------------------------------------------------- */
char
*copy_argv(register char **argv)
{
    register char **p;
    register u_int len = 0;
    char *buf;
    char *src, *dst;

    p = argv;
    if (*p == 0)
        return 0;

    while (*p)
        len += strlen(*p++) + 1;

    buf = (char *)malloc(len);
    if (buf == NULL) {
        err_message("copy_argv:  malloc");
    }

    p = argv;
    dst = buf;

    while ((src = *p++) != NULL) {
        while ((*dst++ = *src++) != '\0')
        ;
        dst[-1] = ' ';
    }
    dst[-1] = '\0';

    return buf;
}

/* ----------------------------------------------------------
 * FUNCTION     : log_message
 * DESCRIPTION  : This function is to be called whenever a
 *              : message needs to be sent to the user.  It
 *              : will then determine whether to send the
 *              : message to screen or syslog.
 * INPUT        : 0 - Log Message
 * RETURN       : None!
 * ---------------------------------------------------------- */
void
log_message (const char *msg, ...)
{
    va_list args;
    char buf[STD_BUF + 1];

    va_start(args, msg);
    vsnprintf(buf, STD_BUF, msg, args);
    va_end(args);

    if (gc.daemon_mode == 1) {
        /* DAEMON:  Print to Syslog */
        if (msg[0] == '\n')
            return;
        syslog(LOG_DAEMON | LOG_NOTICE, "%s", buf);
    } else {
        /* STAND-ALONE:  Print to Screen */
        if (msg[0] == '\n')
            fprintf(stderr, "\n");
        else
            fprintf(stderr, "[-] %s", buf);

        /* Add Newline */
        if (*msg) {
            msg += strlen(msg);
            if (msg[-1] != '\n')
                fprintf(stderr, "\n");
        }
    }
}

/* ----------------------------------------------------------
 * FUNCTION     : err_message
 * DESCRIPTION  : This function is to be called whenever an
 *              : error occurs within the program.
 * INPUT        : 0 - Error Message
 * RETURN       : None!
 * ---------------------------------------------------------- */
void
err_message (const char *msg, ...)
{
    va_list args;
    char buf[STD_BUF + 1];

    va_start(args, msg);
    vsnprintf(buf, STD_BUF, msg, args);
    va_end(args);

    if (gc.daemon_mode == 1) {
        /* DAEMON:  Print to Syslog */
        syslog(LOG_DAEMON | LOG_ERR, "FATAL:  %s", buf);
    } else {
        /* STAND-ALONE:  Print to Screen */
        fprintf(stderr, "[!] FATAL:  %s", buf);

        /* Add Newline */
        if (*msg) {
            msg += strlen(msg);
            if (msg[-1] != '\n')
                fprintf(stderr, "\n");
        }
    }

    /* Exit according to whether the libpcap session was opened. */
    if (gc.handle) {
        end_pads();
    } else {
        exit(-1);
    }
}

/* ----------------------------------------------------------
 * FUNCTION     : verbose_message
 * DESCRIPTION  : This function will print a verbose message
 *              : to the console.
 * INPUT        : 0 - Verbose Message
 * RETURN       : None!
 * ---------------------------------------------------------- */
void
verbose_message (const char *msg, ...)
{
    va_list args;
    char buf[STD_BUF + 1];

    if (gc.verbose != 1)
        return;

    va_start(args, msg);
    vsnprintf(buf, STD_BUF, msg, args);
    va_end(args);

    if (gc.daemon_mode != 1) {
        /* STAND-ALONE:  Print to Screen */
        fprintf(stderr, "[v] %s", buf);

    /* Add Newline */
    if (*msg) {
        msg += strlen(msg);
        if (msg[-1] != '\n')
            fprintf(stderr, "\n");
        }
    }
}

/* ----------------------------------------------------------
 * FUNCTION     : strlcpy
 * DESCRIPTION  : Replacement for strncpy.  This function is
 *              : native in *BSD.  This function was taken
 *              : from Secure Programming Cookbook by
 *              : O'Reilly.
 * INPUT        : 0 - Destination String
 *              : 1 - Source String
 *              : 2 - Size
 * RETURN       : Length of String Created
 *  ---------------------------------------------------------- */
#ifndef HAVE_STRLCPY
size_t
strlcpy(char *dst, const char *src, size_t size) {
  char       *dstptr = dst;
  size_t     tocopy  = size;
  const char *srcptr = src;

  if (tocopy && --tocopy) {
    do {
      if (!(*dstptr++ = *srcptr++)) break;
    } while (--tocopy);
  }
  if (!tocopy) {
    if (size) *dstptr = 0;
    while (*srcptr++);
  }

  return (srcptr - src - 1);
}
#endif

/* ----------------------------------------------------------
 * FUNCTION     : strlcat
 * DESCRIPTION  : Replacement for strcat.  This function is
 *              : native in *BSD.  This function was taken
 *              : from Secure Programming Cookbook by
 *              : O'Reilly.
 * INPUT        : 0 - Destination String
 *              : 1 - Source String
 *              : 2 - Size
 * RETURN       : Length of String Created
 * ---------------------------------------------------------- */
#ifndef HAVE_STRLCAT
size_t
strlcat(char *dst, const char *src, size_t len) {
  char       *dstptr = dst;
  size_t     dstlen, tocopy = len;
  const char *srcptr = src;

  while (tocopy-- && *dstptr) dstptr++;
  dstlen = dstptr - dst;
  if (!(tocopy = len - dstlen)) return (dstlen + strlen(src));
  while (*srcptr) {
    if (tocopy != 1) {
      *dstptr++ = *srcptr;
      tocopy--;
    }
    srcptr++;
  }
  *dstptr = 0;

  return (dstlen + (srcptr - src));
}
#endif

/* ----------------------------------------------------------
 * FUNCTION     : drop_privs
 * DESCRIPTION  : This function will change the user and
 *              : group of the application.
 * INPUT        : 0 - New User
 *              : 1 - New Group
 * RETURN       : None!
 * ---------------------------------------------------------- */
void
drop_privs (bstring newuser, bstring newgroup)
{
    struct group *this_group;
    struct passwd *this_user;

    /* Only change root's privileges. */
    if (!(getuid() == 0 || geteuid() == 0 ||
        getgid() == 0 || getegid() == 0))
        return;

    if (newuser == NULL || newgroup == NULL)
        return;

    if ((this_group = getgrnam(bdata(newgroup))) == NULL)
        err_message("'%s' group does not appear to exist.", bdata(newgroup));

    if ((this_user = getpwnam(bdata(newuser))) == NULL)
        err_message("'%s' user does not appear to exist.", bdata(newuser));

    /* Set Group */
#if !defined(LINUX)
    if ((setgid(this_group->gr_gid)) == -1)
        err_message("Unable to set Group ID!");
    if ((setegid(this_group->gr_gid)) == -1)
        err_message("Unable to set Group ID!");
#else
    if ((setregid(this_group->gr_gid, this_group->gr_gid)) == -1)
        err_message("Unable to set Group ID!");
#endif

    /* Set User */
#if !defined(LINUX)
    if ((setuid(this_user->pw_uid)) == -1)
        err_message("Unable to set User ID!");
    if ((seteuid(this_user->pw_uid)) == -1)
        err_message("Unable to set User ID!");
#else
    if ((setreuid(this_user->pw_uid, this_user->pw_uid)) == -1)
        err_message("Unable to set User ID!");
#endif
}

/* ----------------------------------------------------------
 * FUNCTION     : mac2hex
 * DESCRIPTION  : Converts a string representation of a MAC
 *              : address, based on non-portable ether_aton()
 *              : This function was taken directly from
 *              : the tcpreplay source code.
 * INPUT        : 0 - MAC Address
 *              : 1 - Converted
 *              : 0 - Size of 1
 * RETURN       : None
 * ---------------------------------------------------------- */
void
mac2hex(const char *mac, char *dst, int len)
{
    int i;
    long l;
    char *pp;

    if (len < 6)
        return;

    while (isspace(*mac))
        mac++;

    /* expect 6 hex octets separated by ':' or space/NUL if last octet */
    for (i = 0; i < 6; i++) {
        l = strtol(mac, &pp, 16);
        if (pp == mac || l > 0xFF || l < 0)
            return;
        if (!(*pp == ':' || (i == 5 && (isspace(*pp) || *pp == '\0'))))
            return;
        dst[i] = (u_char) l;
        mac = pp + 1;
    }
}

/* ----------------------------------------------------------
 * FUNCTION     : hex2mac
 * DESCRIPTION  : Converts a hex representation of a MAC
 *              : address into an ASCII string.  This is a
 *              : more portable equivalent of 'ether_ntoa'.
 * INPUT        : 0 - MAC Hex Address
 * RETURN       : 0 - MAC Address String
 * ---------------------------------------------------------- */
char *
hex2mac(unsigned const char *mac)
{
    static char buf[18];

    sprintf(buf, "%X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2],
        mac[3], mac[4], mac[5]);

    return buf;
}

/* vim:expandtab:cindent:smartindent:ts=4:tw=0:sw=4:
 */

char *fasthex(u_char *xdata, int length)
{
    char conv[] = "0123456789ABCDEF";
    char *retbuf = NULL;
    char *index;
    char *end;
    char *ridx;

    index = xdata;
    end = xdata + length;
    retbuf = (char *) calloc((length*2)+1, sizeof(char));
    ridx = retbuf;

    while(index < end)
    {
        *ridx++ = conv[((*index & 0xFF)>>4)];
        *ridx++ = conv[((*index & 0xFF)&0x0F)];
        index++;
    }

    return retbuf;
}

