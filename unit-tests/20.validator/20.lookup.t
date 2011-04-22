# -*- perl -*-
use Test::More;

use Crypt::Monkeysphere::Validator;
use GnuPG::Interface;
use File::Temp qw(tempdir);
use Data::Dumper;

use strict;

my $uid='David Bremner <david@tethera.net>';
plan tests =>2;

my $keyserver= $ENV{MSTEST_KEYSERVER} || 'hkp://pool.sks-keyservers.net';
my $tempdir = tempdir("unitXXXXX", CLEANUP=> 1);
my $gnupg = new GnuPG::Interface();
$gnupg->options->hash_init(homedir=>$tempdir,
			   extra_args =>[ qw(--trusted-key 762B57BB784206AD)]
			  );

my $validator=new Crypt::Monkeysphere::Validator(gnupg=>$gnupg,
						 keyserver=>$keyserver,
						 loglevel=>'debug');

isa_ok($validator,'Crypt::Monkeysphere::Validator');

my $return=$validator->lookup(uid=>$uid,fpr=>'F8841978E8FA6FC65D3405155A5EA5837BD0B401');

print Dumper($return) if ($ENV{MSTEST_DEBUG});

ok(defined($return->{valid_key}));



