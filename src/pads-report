#!/usr/bin/perl -w
# ---------------------------------------------------------------------
# pads-report.pl
#
# Matt Shelton <matt@mattshelton.com>
#
# This script will generate a formatted report based on the data
# produced by Passive Asset Detection System (PADS).
#
# Copyright (C) 2004 Matt Shelton <matt@mattshelton.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
my $version	= '1.2';
my $date	= '06/17/05';
#
# $Id: pads-report.pl,v 1.2 2005/06/15 22:10:41 mattshelton Exp $
#
# ---------------------------------------------------------------------
use strict;
print_header();
eval("use Getopt::Long"); die "[!] ERROR:  Getopt::Long module must be installed!\n" if $@;
eval("use Socket"); die "[!] ERROR:  Socket module must be insalled!\n" if $@;
use vars qw ($opt_h $opt_r $opt_w $opt_n $opt_p);

# Variable Declarations
my $report_file		= "assets.csv";

# Data Structure:
# %asset_storage = (
#	<IP Address>	=> {
#		ARP		=> [ $mac, $discovered, $vendor ],
#		ICMP		=> ICMP,
#		TCP		=> [ $port, $service, $app, $discovered ]
#			},
#		}
# )
my %asset_storage	= ();

# Parse Command Line
GetOptions('r=s'	=> \$opt_r,
	   'w=s'	=> \$opt_w,
	   'n'		=> \$opt_n,
	   'p'		=> \$opt_p,
	   'h|?'	=> \$opt_h,
	   'help'       => \$opt_h
);
usage() if $opt_h;
$report_file = $opt_r if ($opt_r);

# --------------------------------------------
# MAIN
# --------------------------------------------

# Open Report File
open (REPORT, "<$report_file") or die "[!] ERROR:  Unable to open $report_file - $!\n";

# Read in Report File
while (<REPORT>) {
    my (@split);
    my ($ip_addr, $port, $proto);
    my ($service, $app, $discovered, $vendor);
    my (%tcp_tmp) = ();

    chomp;
    next if (/^asset,port/);

    @split	= split(/,/);
    $ip_addr	= $split[0];
    $port	= $split[1];
    $proto	= $split[2];
    $service	= $split[3];
    $app	= $split[4];
    $discovered	= $split[5];

    # Assign this line to the asset data structure.
    if ($proto == 0) {
	# ARP
	if ($service =~ /ARP \((.*)\)/) {
	    $vendor = $1;
	} else {
	    $vendor = "unknown";
	}
	push ( @{ $asset_storage{$ip_addr}->{"ARP"} }, [ $app, $discovered, $vendor ]);

    } elsif ($proto == 1) {
	# ICMP
	$asset_storage{$ip_addr}->{"ICMP"} = "ICMP";

    } elsif ($proto == 6) {
	# TCP
	push (@{$asset_storage{$ip_addr}{"TCP"}},
		[ $port, $service, $app, $discovered ]);
    }
}

# Close Report File
close (REPORT);

# Open output file if specified on the command line.
if ($opt_w) {
    open (STDOUT, ">$opt_w") or die "[!] ERROR:  $!\n";
}

# Print out this record.
my $asset;
my $id = 1;
foreach $asset (sort (keys (%asset_storage))) {
    my ($mac);
    my ($icmp);
    my (@sorted);
    my ($i);

    # Output Asset Header
    print "$id ------------------------------------------------------\n";
    print "IP:       $asset\n";

    # Output DNS Name
    unless ($opt_n) {
	if ($opt_p) {
	    # Check to see if this is a RFC 1918 address.
	    unless (check_rfc1918($asset)) {
		my ($peer_host) = gethostbyaddr(inet_aton($asset), AF_INET());
		print "DNS:      $peer_host\n" if ($peer_host);
	    }
	} else {
	    my ($peer_host) = gethostbyaddr(inet_aton($asset), AF_INET());
	    print "DNS:      $peer_host\n" if ($peer_host);
	}
    }

    # Output MAC Addresses
    $i = 0;
    foreach $_ ( @ { $asset_storage{$asset}->{"ARP"}}) {
	if ($i == 0) {
	    my ($date) = from_unixtime($_->[1]);
	    printf("MAC(s):   %-18s (%-19s)\n", $_->[0], $date);
	    printf("VENDOR:   %-18s\n", $_->[2]) if ($_->[2] ne "unknown");
	    $i++;
	} else {
	    my ($date) = from_unixtime($_->[1]);
	    printf("%-09s %-18s (%-19s)\n", "", $_->[0], $date);
	    printf("%-09s %-18s\n", $_->[2]) if ($_->[2] ne "unknown");
	}
    }

    # Output ICMP Status
    if ($asset_storage{$asset}->{"ICMP"}) {
	print "ICMP:     Enabled\n";
    }

    print "\n";

    # Output TCP Status
    if ($asset_storage{$asset}->{"TCP"}) {
	printf("%-5s %-10s %-30s\n", "Port", "Service", "Application");
	@sorted = sort {$$a[0] <=> $$b[0]} @{$asset_storage{$asset}->{"TCP"}};
    }
    foreach $_ (@sorted) {
	printf("%-5d %-10s %-30s\n", $_->[0], $_->[1], $_->[2])
    }
    if ($asset_storage{$asset}->{"TCP"}) {
	print "\n";
    }

    $id++;
}

# Close output file if specified on the command line.
if ($opt_w) {
    close (STDOUT);
}

# --------------------------------------------
# FUNCTION	: from_unixtime
# DESCRIPTION	: This function will convert
#		: a unix timestamp into a
#		: normal date.
# INPUT		: 0 - UNIX timestamp
# RETURN	: 0 - Formatted Time
# --------------------------------------------
sub from_unixtime {
    my ($unixtime) = $_[0];
    my ($time);

    my ($sec, $min, $hour, $dmon, $mon, $year,
	$wday, $yday, $isdst) = localtime($unixtime);
    $time = sprintf("%04d/%02d/%02d %02d:%02d:%02d",
	$year + 1900, $mon + 1, $dmon, $hour, $min, $sec);

    return $time;

}

# --------------------------------------------
# FUNCTION	: check_rfc1918
# DESCRIPTION	: This function will check to
#		: see if a address is a RFC
#		: 1918 address.
# INPUT		: 0 - IP Address
# RETURN	: 1 - Yes
# --------------------------------------------
sub check_rfc1918 {
    my ($ip) = $_[0];

    return 1 if (check_ip($ip, "10.0.0.0/8"));
    return 1 if (check_ip($ip, "172.16.0.0/12"));
    return 1 if (check_ip($ip, "192.168.0.0/16"));
    return 0;
}

# --------------------------------------------
# FUNCTION	: check_ip
# DESCRIPTION	: This function will check to
#		: see if a address falls
#		: within a network CIDR block.
# INPUT		: 0 - IP Address
#		: 1 - CIDR Network
# RETURN	: 1 - Yes
# --------------------------------------------
sub check_ip {
    my ($i)	= $_[0];
    my ($n)	= $_[1];

    return ($i eq $n) unless $n =~ /^(.*)\/(.*)$/;
    return (((unpack('N',pack('C4',split(/\./,$i))) ^ unpack('N',pack('C4'
			,split(/\./,$1)))) & (0xFFFFFFFF << (32 - $2))) == 0);
}
# --------------------------------------------
# FUNCTION	: usage
# --------------------------------------------
sub usage {
    print <<__EOT__;
Usage:
-r <file>	: PADS Raw Report File
-w <file>	: Output file
-n		: Do not convert IP addresses to names.
-p		: Do not convert RFC 1918 IP addresses to names.

__EOT__
    exit;
}

# --------------------------------------------
# FUNCTION	: print_header
# --------------------------------------------
sub print_header {
    print <<__EOT__;
pads-report - PADS Text Reporting Module
$version - $date
Matt Shelton <matt\@mattshelton.com>

__EOT__
}
