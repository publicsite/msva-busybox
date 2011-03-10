#!/usr/bin/perl
use strict;

use TAP::Harness;
use File::Find;
use FindBin;
my $BINDIR;
BEGIN { $BINDIR = $FindBin::Bin; }

my @dirs = scalar(@ARGV) > 0 ? @ARGV : ($BINDIR);

my @tests;

sub wanted {
  push (@tests,$File::Find::name) if -f && m/.*\.t$/;
}

find(\&wanted, @dirs);

@tests=sort @tests;

print STDERR "found ",scalar(@tests)," tests\n";

my $harness = TAP::Harness->new( { verbosity => 1,
				  lib => [ $BINDIR.'/..'] });

$harness->runtests(@tests);

1;
