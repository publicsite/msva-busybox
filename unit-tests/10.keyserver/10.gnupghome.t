# -*- perl -*-
use Test::More;

use Crypt::Monkeysphere::Keyserver;
use GnuPG::Interface;
use File::Temp qw(tempdir);
use strict;
use warnings;

my $fpr='762B57BB784206AD';
plan tests =>5;

{

  $ENV{HOME}='/nonexistant';
  my $ks = new Crypt::Monkeysphere::Keyserver();

  isa_ok($ks,'Crypt::Monkeysphere::Keyserver');
  is($ks->{keyserver},$Crypt::Monkeysphere::Keyserver::default_keyserver);

}

my $tempdir = tempdir("/tmp/unitXXXXX", CLEANUP=> 1);
my $gnupg = new GnuPG::Interface();
my $testks = 'hkp://keys.gnupg.net';
$gnupg->options->hash_init(homedir=>$tempdir);

is($gnupg->options->homedir,$tempdir);

open GPGCONF, '>', "$tempdir/gpg.conf";
print GPGCONF "keyserver $testks\n";
close GPGCONF;

my $ks=new Crypt::Monkeysphere::Keyserver(gnupg=>$gnupg,
					  loglevel=>'debug');

isa_ok($ks,'Crypt::Monkeysphere::Keyserver');

is($ks->{keyserver},$testks);
