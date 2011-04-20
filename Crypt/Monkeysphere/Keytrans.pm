package Crypt::Monkeysphere::Keytrans;

use strict;
use warnings;
use Math::BigInt;
use Carp;
use MIME::Base64;

use Exporter qw(import);
our @EXPORT_OK=qw();


# takes a Math::BigInt and returns it properly packed for openssh output.

sub openssh_mpi_pack {
  my $num = shift;

  my $val = $num->as_hex();
  $val =~ s/^0x//;
  # ensure we've got an even multiple of 2 nybbles here.
  $val = '0'.$val
    if (length($val) % 2);
  $val = pack('H*', $val);
  # packed binary ones-complement representation of the value.

  my $mpilen = length($val);

  my $ret = pack('N', $mpilen);

  # if the first bit of the leading byte is high, we should include a
  # 0 byte:
  if (ord($val) & 0x80) {
    $ret = pack('NC', $mpilen+1, 0);
  }

  return $ret.$val;
}

# this output is not base64-encoded yet.  Pass it through
# encode_base64($output, '') if you want to make a file.

sub openssh_rsa_pubkey_pack {
  my ($modulus, $exponent) = @_;

  return openssh_mpi_pack(Math::BigInt->new('0x'.unpack('H*', "ssh-rsa"))).
      openssh_mpi_pack($exponent).
	openssh_mpi_pack($modulus);
}


sub GnuPGKey_to_OpenSSH_pub {
  my $key = shift;

  croak("not a GnuPG::Key!")
    unless($key->isa('GnuPG::Key'));

  croak("Not an RSA key!")
    unless $key->algo_num == 1;

  use Data::Dumper;

  return encode_base64(openssh_rsa_pubkey_pack(@{$key->pubkey_data}), '');
}

1;
