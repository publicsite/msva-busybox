# -*- perl -*-
use Test::More;

use Crypt::Monkeysphere::Keyserver;
use GnuPG::Interface;
use File::Temp qw(tempdir);

use strict;

my $uid='David Bremner <david@tethera.net>';
plan tests =>2;

my $tempdir = tempdir("unitXXXXX", CLEANUP=> 1);
my $gnupg = new GnuPG::Interface();
$gnupg->options->hash_init(homedir=>$tempdir);

my $ks=new Crypt::Monkeysphere::Keyserver(gnupg=>$gnupg,
					  loglevel=>'debug');

isa_ok($ks,'Crypt::Monkeysphere::Keyserver');

$ks->fetch_uid($uid);

my $count=0;
grep { $count += ($_ eq '784206AD') } 
  (map { $_->short_hex_id } ($gnupg->get_public_keys('='.$uid)));

is($count,1);



