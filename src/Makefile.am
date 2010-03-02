## $Id: Makefile.am,v 1.3 2005/02/17 16:29:54 mattshelton Exp $
AUTOMAKE_OPTIONS=foreign no-dependencies
bin_PROGRAMS = pads
pads_SOURCES = pads.c pads.h \
	       storage.c storage.h \
               identification.c identification.h \
               packet.c packet.h \
               monnet.c monnet.h \
               mac-resolution.c mac-resolution.h \
	       configuration.c configuration.h \
               util.c util.h \
               global.h
pads_LDADD = $(top_srcdir)/lib/bstring/libbstring.a output/liboutput.a
bin_SCRIPTS = pads-report

EXTRA_DIST = pads-report.pl
SUBDIRS = output
CLEANFILES = $(bin_SCRIPTS)
INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/lib

pads-report:  pads-report.pl
	cat $(srcdir)/pads-report.pl >> pads-report
	chmod +x pads-report
