# -*- perl -*-
use Test::More;

use Crypt::Monkeysphere::Keyserver;
use GnuPG::Interface;
use File::Temp qw(tempdir);

my $fpr='762B57BB784206AD';
plan tests =>2;

my $tempdir = tempdir("unitXXXXX", CLEANUP=> 1);
my $gnupg = new GnuPG::Interface();
$gnupg->options->hash_init(homedir=>$tempdir);

my $ks=new Crypt::Monkeysphere::Keyserver(gnupg=>$gnupg,
					  loglevel=>'debug');

isa_ok($ks,'Crypt::Monkeysphere::Keyserver');

$ks->fetch_fpr($fpr);

is(scalar($gnupg->get_public_keys('0x'.$fpr)),1);




