package Crypt::Monkeysphere::Keytrans;

use strict;
use warnings;
use Math::BigInt;
use Carp;
use MIME::Base64;

use Exporter qw(import);
our @EXPORT_OK=qw(GnuPGKey_to_OpenSSH_pub GnuPGKey_to_OpenSSH_fpr);


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

# calculate/print the fingerprint of an openssh-style keyblob:

sub sshfpr {
  my $keyblob = shift;
  use Digest::MD5;
  return join(':', map({unpack("H*", $_)} split(//, Digest::MD5::md5($keyblob))));
}

=pod

=head2 GnuPGKey_to_OpenSSH_fpr

Find the openssh compatible fingerprint of an (RSA) GnuPG::Key

B<Note> you will need to add add bits and (RSA) to the string to
exactly match the output of ssh-keygen -l.

=head3 Arguments

key - GnuPG::Key object

=cut

sub GnuPGKey_to_OpenSSH_fpr {
  my $key = shift;

  croak("not a GnuPG::Key!")
    unless($key->isa('GnuPG::Key'));

  croak("Not an RSA key!")
    unless $key->algo_num == 1;

  return sshfpr(openssh_rsa_pubkey_pack(@{$key->pubkey_data}), '');
}

=pod

=head2 GnuPGKey_to_OpenSSH_pub

Translate a GnuPG::Key to a string suitable for an OpenSSH .pub file

B<Note> you will need to add "ssh-rsa " to the front to make OpenSSH
recognize it.

=head3 Arguments

key - GnuPG::Key object

=cut

sub GnuPGKey_to_OpenSSH_pub {
  my $key = shift;

  croak("not a GnuPG::Key!")
    unless($key->isa('GnuPG::Key'));

  croak("Not an RSA key!")
    unless $key->algo_num == 1;

  return encode_base64(openssh_rsa_pubkey_pack(@{$key->pubkey_data}), '');
}

1;
