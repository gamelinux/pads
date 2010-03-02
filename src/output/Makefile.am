# $Id: Makefile.am,v 1.1 2005/02/10 06:05:06 mattshelton Exp $
AUTOMAKE_OPTIONS=foreign no-dependencies
noinst_LIBRARIES = liboutput.a
liboutput_a_SOURCES = output.c output.h \
		      output-screen.c output-screen.h \
                      output-csv.c output-csv.h \
                      output-fifo.c output-fifo.h

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/src -I$(top_srcdir)/lib
