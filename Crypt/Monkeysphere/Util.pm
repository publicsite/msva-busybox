package Crypt::Monkeysphere::Util;

use strict;
use warnings;

use Exporter qw(import);
our @EXPORT_OK=qw(untaint);


# use sparingly!  We want to keep taint mode around for the data we
# get over the network.
sub untaint {
  my $x = shift;
  $x =~ /^(.*)$/ ;
  return $1;
}

1;
