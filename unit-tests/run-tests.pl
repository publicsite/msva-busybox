#!/usr/bin/perl
use strict;

use TAP::Harness;
use File::Find;
use FindBin;
use GnuPG::Interface;
use GnuPG::Handles;
use File::Temp qw(tempdir);

my $BINDIR;
BEGIN { $BINDIR = $FindBin::Bin; }


{ 
# Generate Keys from template file

  my $tempdir = tempdir("/tmp/test-gnupgXXXXX", CLEANUP=> 1);
  my $gnupg = new GnuPG::Interface();
  $gnupg->options->hash_init(homedir=>$tempdir,batch=>1);

  my $GPGQR='';
  if (system qw(gpg --quick-random --version) ==0) {
    $GPGQR='--quick-random';
  } elsif (system qw(gpg --debug-quick-random --version) ==0) {
    $GPGQR='--debug-quick-random';
  }

  print STDERR "WARNING: no quick random option found. Tests may hang!\n" 
    unless(scalar $GPGQR);

  my $pid = $gnupg->wrap_call( commands=>[qw(--gen-key --batch),$GPGQR],
			       command_args=>[$BINDIR.'/keys.txt'],
			       handles=>new GnuPG::Handles() );
  waitpid $pid,0;

  $ENV{MSTEST_GNUPGHOME}=$tempdir;
}

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
