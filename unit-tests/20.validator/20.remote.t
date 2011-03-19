# -*- perl -*-
use Test::More;

use Crypt::Monkeysphere::Validator;
use GnuPG::Interface;
use File::Temp qw(tempdir);
use Data::Dumper;

use strict;

my $uid='David Bremner <david@tethera.net>';
plan tests =>2;

my $tempdir = tempdir("unitXXXXX", CLEANUP=> 1);
my $gnupg = new GnuPG::Interface();
$gnupg->options->hash_init(homedir=>$tempdir,
			   extra_args =>[ qw(--trusted-key 762B57BB784206AD)]
			  );

my $validator=new Crypt::Monkeysphere::Validator(gnupg=>$gnupg,
					  loglevel=>'debug');

isa_ok($validator,'Crypt::Monkeysphere::Validator');

my $return=$validator->query(uid=>$uid);

print Dumper($return);

is(defined($return),1);



