# -*- perl -*-
use Test::More;

use Crypt::Monkeysphere::OpenPGP;
use Data::Dumper;

use strict;

my $timestamp = 1299825212;
my $key = { modulus => Math::BigInt->new('0xcceb95c3c00b8a12c9de4829a803302f76549a50ee9b7ee58ee3a75ed1839d77d2f57b766e9954581d64eb5599ae98326a028831fbadad8065d63bc5a7b8d831e06d363fd9954f271fda1d746674b0ad6e8dff9fc5ddd4608bdf95760372f50897637a379079f3eb2544099a4511fc8af8e5992e15df8eac619b58a9970a3bdb'),
            exponent => Math::BigInt->new('0x10001'),
          };
plan tests =>1;

is(unpack('H*', Crypt::Monkeysphere::OpenPGP::fingerprint($key, $timestamp)),"10cc971bbbb37b9152e8e759a2882699b47c6497");



