/*************************************************************************
 * pads.c
 *
 * Matt Shelton    <matt@mattshelton.com>
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
 * $Id: pads.c,v 1.10 2005/06/15 22:00:40 mattshelton Exp $
 *
 **************************************************************************/
#include "pads.h"

/* Variable Declarations */
GC gc;                                  /* Global Configuration */
char errbuf[PCAP_ERRBUF_SIZE];
proc_t processor;
char **prog_argv;
int prog_argc;

/* ----------------------------------------------------------
 * FUNCTION     : process_pkt
 * DESCRIPTION  : This function takes data from libpcap and
 *              : processes it based on what type of traffic
 *              : it is.
 * INPUT        : 0 - Not used
 *              : 1 - pcap packet header
 *              : 2 - pcap packet
 * ---------------------------------------------------------- */
void
process_pkt (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    /* Call LLC Processor */
    (*processor)(pkthdr, packet);
}

/* ----------------------------------------------------------
 * FUNCTION     : set_processor
 * DESCRIPTION  : This function determines what type of LLC
 *              : type is being used.  It will then set a
 *              : pointer to the correct LLC function.
 * INPUT        : PCAP Handle
 * RETURN       : None!
 * ---------------------------------------------------------- */
void
set_processor (pcap_t *this_handle)
{
    int datalink;
    datalink = pcap_datalink(this_handle);

    switch (datalink) {
        /* Ethernet */
        case DLT_EN10MB:
            processor = process_eth;
            break;

#ifdef DLT_LINUX_SLL
        /* Linux Cooked Sockets */
        case DLT_LINUX_SLL:
            processor = process_sll;
            break;
#endif /* DLT_LINUX_SLL */

    /* Default */
        default:
            err_message("LLC not supported!  Please contact the author!");
            break;
    }

    return;
}

/* ----------------------------------------------------------
 * FUNCTION     : print_header
 * DESCRIPTION  : Prints initial header.
 * ---------------------------------------------------------- */
void
print_header ()
{
    printf("pads - Passive Asset Detection System\n");
    printf("v%s - %s\n", PACKAGE_VERSION, PACKAGE_DATE);
    printf("Matt Shelton <matt@mattshelton.com>\n");
    printf("\n");
}

/* ----------------------------------------------------------
 * FUNCTION    : print_usage
 * DESCRIPTION    : Prints the Program Usage
 * ---------------------------------------------------------- */
void
print_usage()
{
    printf("Usage:\n"
       "-c <file>      : Read configuration from <file>.\n"
       "-d <file>      : Dump banner packets to a libpcap formatted file.\n"
       "-D             : Run PADS in the background (daemon mode).\n"
       "-g <group>     : Drop privileges to this group.\n"
       "-h             : Help\n"
       "-i <interface> : Listen on <interface>.  The lowest number interface\n"
       "                 will be used if an interface isn't specified.\n"
       "-n <network>   : Reads in a comma seperated list of networks\n"
       "                 to be monitored.\n"
       "                   ex.  -n \"192.168.0.0/24,10.0.0.0/16\"\n"
       "-p <file>      : PID file used with daemon mode.\n"
       "-r <file>      : Read packets from a libpcap formatted file.\n"
       "-u <user>      : Drop privileges to this user.\n"
       "-v             : Verbose\n"
       "-V             : Version\n"
       "-w <file>      : Dump data into file other than assets.csv.\n"
       "\n"
       "Additional arguments will be processed as a libpcap filter.  For example,\n"
       "the following command will not only use interface hme1 but will also only\n"
       "search for assets on port 22:\n"
       "\n"
       "    pads -i hme1 port 22\n");
    printf("\n");
    exit(0);
}

/* ----------------------------------------------------------
 * FUNCTION     : print_version
 * DESCRIPTION  : This function will print version
 *              : version information.
 * ---------------------------------------------------------- */
void
print_version (void)
{
    printf("Build:\n");
    printf("OS          - %s\n", OS_TYPE);
    printf("Compiled    - %s %s\n", __DATE__, __TIME__);
    printf("\n");
    printf("Libraries:\n");
    printf("libpcap     - %d.%d\n", PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR);
    printf("pcre        - %d.%d\n", PCRE_MAJOR, PCRE_MINOR);
    printf("\n");
}

/* ----------------------------------------------------------
 * FUNCTION     : init_pads
 * DESCRIPTION  : This function will initialize PADS.
 * ---------------------------------------------------------- */
void
init_pads (void)
{
    /* Process the command line parameters. */
    process_cmdline(prog_argc, prog_argv);

    /* Initialize Output Module */
    init_output();

    /* Process the configuration file. */
    if (gc.conf_file) {
        init_configuration(gc.conf_file);

    } else {
        /* Default Output Plugins:  These plugins are activated if a configuration
         * file is not specified. */

        /* output:  screen */
        if ((activate_output_plugin(bfromcstr("screen"), bfromcstr(""))) == -1)
            log_message("warning:  'activate_output_plugin' in function 'init_pads' failed.");
        /* output:  csv */
        if ((activate_output_plugin(bfromcstr("csv"), gc.report_file)) == -1)
            log_message("warning:  'activate_output_plugin' in function 'init_pads' failed.");
    }

    /* Initialize Modules */
    init_identification();
    init_mac_resolution();

    /* Daemon Mode:  fork child process */
    if (gc.daemon_mode) {
        daemonize();
        init_pid_file(gc.pid_file, gc.priv_user, gc.priv_group);
    }

    /* Signal Trapping */
    (void) signal(SIGTERM, sig_term_handler);
    (void) signal(SIGINT, sig_int_handler);
    (void) signal(SIGQUIT, sig_quit_handler);
    (void) signal(SIGHUP, sig_hup_handler);
}

/* ----------------------------------------------------------
 * FUNCTION     : main_pads
 * DESCRIPTION  : This is the main function for PADS.
 * ---------------------------------------------------------- */
void
main_pads (void)
{
    char pcap_filter[1044];
    /* Initialize */
    init_pads();

    if (gc.pcap_file) {
        /* Read from PCAP file specified by '-r' switch. */
        log_message("Reading from file %s\n", bdata(gc.pcap_file));
        if (!(gc.handle = pcap_open_offline(bdata(gc.pcap_file), errbuf))) {
            err_message("Unable to open %s.  (%s)", bdata(gc.pcap_file), errbuf);
        }

        gc.mask = 0;
        gc.net = 0;

    } else {
        /* Only root can access the interface. */
        if(geteuid() != 0) {
            err_message("Must be root!");
        }

        /* Determine Sniffing Interface */
        if (!gc.dev) {
            verbose_message("Looking for sniffing interface");
            if (!(gc.dev = pcap_lookupdev(errbuf)))
                err_message("Unable to find a sniffing interface!  (%s)", errbuf);
        }

        /* Set up libpcap connection. */
        if (!(gc.handle = pcap_open_live(gc.dev, BUFSIZ, 1, 0, errbuf)))
            err_message("Unable to open interface %s!  (%s)", gc.dev, errbuf);

        /* Drop Privileges */
        if (gc.priv_user != NULL && gc.priv_group != NULL) {
            verbose_message("Dropping Privileges");
            drop_privs(gc.priv_user, gc.priv_group);
        }

        /* Lookup Netmask (used with pcap_setfilter) */
        verbose_message("Looking up interface network");
        if (pcap_lookupnet(gc.dev, &gc.net, &gc.mask, errbuf) == -1) {
            log_message("WARNING:  pcap_lookupnet (%s)\n", errbuf);
            memset(&gc.net, 0, sizeof(gc.net));
            memset(&gc.mask, 0, sizeof(gc.mask));
        }
    }

    /* Determine LLC Type */
    verbose_message("Determine LLC Type");
    set_processor(gc.handle);

    /* Compile libpcap filter */
    if (prog_argc > 0) {
      if(gc.pcap_filter) {
	strcpy(pcap_filter, "(ip or vlan) and ");
	strncat(pcap_filter, gc.pcap_filter, 1024);
      } else {
	strcpy(pcap_filter, "(ip or vlan)");
      }
        log_message("Filter:  %s\n", pcap_filter);
        if (pcap_compile(gc.handle, &gc.filter, pcap_filter, 0, gc.net) == -1) {
            err_message("Unable to compile pcap filter!  %s", pcap_geterr(gc.handle));
        }
        if (pcap_setfilter(gc.handle, &gc.filter)) {
            err_message("Unable to set pcap filter!  %s", pcap_geterr(gc.handle));
        }
        free(gc.pcap_filter);
    }

    /* Open banner dump file if specified (-d). */
    if (gc.dump_file) {
        verbose_message("Opening Banner Dump File");
        if (!(gc.dumper = pcap_dump_open(gc.handle, bdata(gc.dump_file))))
            err_message("Cannot open dump file - %s\n", pcap_geterr(gc.handle));
    }

    /* Sniff libpcap connection. */
    log_message("Listening on interface %s\n", gc.dev);
    log_message("\n");
    verbose_message("Entering pcap_loop()");
    while (pcap_loop(gc.handle, -1, process_pkt, NULL));

    /* End */
    end_pads();
}

/* ----------------------------------------------------------
 * FUNCTION     : end_pads
 * DESCRIPTION  : This function needs to be called before the
 *              : program exits.  It shuts down libpcap and
 *              : everything.
 * ---------------------------------------------------------- */
void
end_pads(void)
{
    struct pcap_stat pstat;
    static int exit_status = 0;

    /* Make sure that this function is only called once. */
    if (exit_status == 1)
        return;
    else
        exit_status = 1;

    /* Display PCAP Statistics */
    if (!pcap_stats(gc.handle, &pstat)) {
        log_message("\n");
        log_message("%d Packets Received\n", pstat.ps_recv);
        log_message("%d Packets Dropped by Software\n", pstat.ps_drop);
        log_message("%d Packets Dropped by Interface\n", pstat.ps_ifdrop);
        log_message("\n");
    }

    /* Close banner dump file if specifed (-d). */
    if (gc.dump_file) {
        verbose_message("Closing Banner Dump File");
        pcap_dump_close(gc.dumper);
    }

    /* Kill PCAP Object */
    if (gc.handle) {
        log_message("Closing PCAP Connection");
        pcap_close(gc.handle);
    }

    /* Remove PID File */
    if (gc.daemon_mode == 1)
        if ((unlink(bdata(gc.pid_file))) != 0)
            log_message("WARNING:  Unable to remove PID file - %s\n", bdata(gc.pid_file));

    /* End Modules */
    verbose_message("Cleaning Up Memory");
    end_output();
    end_storage();
    end_identification();
#ifndef DISABLE_VENDOR
    end_mac_resolution();
#endif

    /* Garbage Collect GC Variable */
    if (gc.conf_file != NULL)
        bdestroy(gc.conf_file);
    if (gc.report_file != NULL)
        bdestroy(gc.report_file);
    if (gc.fifo_file != NULL)
        bdestroy(gc.fifo_file);
    if (gc.pcap_file != NULL)
        bdestroy(gc.pcap_file);
    if (gc.dump_file != NULL)
        bdestroy(gc.dump_file);
    if (gc.sig_file != NULL)
        bdestroy(gc.sig_file);
    if (gc.mac_file != NULL)
        bdestroy(gc.mac_file);
    if (gc.pid_file != NULL)
        bdestroy(gc.pid_file);
    if (gc.priv_user != NULL)
        bdestroy(gc.priv_user);
    if (gc.priv_group != NULL)
        bdestroy(gc.priv_group);

    verbose_message("Done!  Exiting...");
    exit(0);
}

/* ----------------------------------------------------------
 * FUNCTION     : process_cmdline
 * DESCRIPTION  : This function will process the command line
 *              : arguments of the program.
 * INPUT        : 0 - argc
 *              : 1 - argv
 * RETURN       : 0 - Success
 *              : -1 - Error
 * ---------------------------------------------------------- */
int
process_cmdline (int argc, char *argv[])
{
    int ch;

    /* Process Command Line Arguments */
    while ((ch = getopt(argc, argv, "c:d:Dg:hi:n:r:u:UvVw:")) != -1)  {
        switch (ch) {
            case 'c':
                gc.conf_file = blk2bstr(optarg, strlen(optarg));
                break;
            case 'd':
                gc.dump_file = blk2bstr(optarg, strlen(optarg));
                break;
            case 'D':
                gc.daemon_mode = 1;
                break;
            case 'g':
                gc.priv_group = blk2bstr(optarg, strlen(optarg));
                break;
            case 'h':
                print_usage();
                exit(0);
                break;
            case 'i':
                gc.dev = optarg;
                break;
            case 'n':
                parse_networks(optarg);
                break;
            case 'p':
                gc.pid_file = blk2bstr(optarg, strlen(optarg));
                break;
            case 'r':
                gc.pcap_file = blk2bstr(optarg, strlen(optarg));
                break;
            case 'u':
                gc.priv_user = blk2bstr(optarg, strlen(optarg));
                break;
            case 'U':
                gc.hide_unknowns = 1;
                break;
            case 'v':
                gc.verbose = 1;
                break;
            case 'V':
                /* Banner has already been printed, exit... */
                print_version();
                exit(0);
                break;
            case 'w':
                gc.report_file = blk2bstr(optarg, strlen(optarg));
                break;
            default:
                print_usage();
                exit(0);
                break;
        }
    }

    argc -= optind;
    argv += optind;

    /* Parse the rest of the command line. */
    if (argc > 0) {
        gc.pcap_filter = (char *)copy_argv(argv);
    }

    return 0;
}

/* ----------------------------------------------------------
 * The following functions are signal handlers.  They are
 * initialized in 'init_pads' and will perform a function
 * based on the signal.
 * ---------------------------------------------------------- */
void
sig_term_handler(int signal)
{
    end_pads();
}

void
sig_int_handler(int signal)
{
    end_pads();
}

void
sig_quit_handler(int signal)
{
    end_pads();
}

void
sig_hup_handler(int signal)
{
    /* The HUP signal has not been implemented yet. */
    end_pads();
}

/* ----------------------------------------------------------
 * FUNCTION     : main
 * ---------------------------------------------------------- */
int
main(int argc, char *argv[])
{
    /* Variables */
    int i;
    struct pcap_pkthdr header;      /* The header that pcap gives us */
    const u_char *packet;           /* The actual packet */

    /* Copy Command Line Args */
    prog_argc = argc;
    prog_argv = argv;

    /* Main Program */
    print_header();
    main_pads();

    return(0);
}

/* vim:expandtab:cindent:smartindent:ts=4:tw=0:sw=4:
 */
