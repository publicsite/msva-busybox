# -*- perl -*-
use Test::More;

use Crypt::Monkeysphere::Validator;
use GnuPG::Interface;
use File::Temp qw(tempdir);
use Data::Dumper;

use strict;


my $gpgdir = $ENV{MSTEST_GNUPGHOME};

unless (defined $gpgdir && -d $gpgdir){
  plan skip_all => "Preseeded GPGHOME not found";
  goto end;
}


my $gnupg = new GnuPG::Interface();
$gnupg->options->hash_init(homedir=>$gpgdir);

my $validator=new Crypt::Monkeysphere::Validator(gnupg=>$gnupg,
						 kspolicy=>'never',
						 loglevel=>'debug');


plan tests =>2;

isa_ok($validator,'Crypt::Monkeysphere::Validator');

my $uid='Joe Tester <joe@example.net>';

my @keys=$validator->findall($uid);



ok(scalar @keys >= 3);


end:
