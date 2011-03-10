package Crypt::Monkeysphere::Util;

use strict;
use warnings;

use Exporter qw(import);
our @EXPORT_OK=qw(untaint);


# use sparingly!  We want to keep taint mode around for the data we
# get over the network.  this is only here because we want to treat
# the command line arguments differently for the subprocess.
sub untaint {
  my $x = shift;
  $x =~ /^(.*)$/ ;
  return $1;
}

1;
