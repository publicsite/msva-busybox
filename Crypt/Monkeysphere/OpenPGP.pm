package Crypt::Monkeysphere::OpenPGP;

use strict;
use warnings;

use Math::BigInt;
use Digest::SHA;

## WARNING!  This entire module has an unstable API at the moment.
## Please do not rely on it, as it may change in the near future.


my $tables = {
              # see RFC 4880 section 9.1 (ignoring deprecated algorithms for now)
              asym_algos => { rsa => 1,
                              elgamal => 16,
                              dsa => 17,
                            },

              # see RFC 4880 section 9.2
              ciphers => { plaintext => 0,
                           idea => 1,
                           tripledes => 2,
                           cast5 => 3,
                           blowfish => 4,
                           aes128 => 7,
                           aes192 => 8,
                           aes256 => 9,
                           twofish => 10,
                         },

              # see RFC 4880 section 9.3
              compression => { uncompressed => 0,
                               zip => 1,
                               zlib => 2,
                               bzip2 => 3,
                             },

              # see RFC 4880 section 9.4
              digests => { md5 => 1,
                           sha1 => 2,
                           ripemd160 => 3,
                           sha256 => 8,
                           sha384 => 9,
                           sha512 => 10,
                           sha224 => 11,
                         },

              # see RFC 4880 section 5.2.3.21
              usage_flags => { certify => 0x01,
                               sign => 0x02,
                               encrypt_comms => 0x04,
                               encrypt_storage => 0x08,
                               encrypt => 0x0c, ## both comms and storage
                               split => 0x10, # the private key is split via secret sharing
                               authenticate => 0x20,
                               shared => 0x80, # more than one person holds the entire private key
                             },

              # see RFC 4880 section 4.3
              packet_types => { pubkey_enc_session => 1,
                                sig => 2,
                                symkey_enc_session => 3,
                                onepass_sig => 4,
                                seckey => 5,
                                pubkey => 6,
                                sec_subkey => 7,
                                compressed_data => 8,
                                symenc_data => 9,
                                marker => 10,
                                literal => 11,
                                trust => 12,
                                uid => 13,
                                pub_subkey => 14,
                                uat => 17,
                                symenc_w_integrity => 18,
                                mdc => 19,
                              },

              # see RFC 4880 section 5.2.1
              sig_types => { binary_doc => 0x00,
                             text_doc => 0x01,
                             standalone => 0x02,
                             generic_certification => 0x10,
                             persona_certification => 0x11,
                             casual_certification => 0x12,
                             positive_certification => 0x13,
                             subkey_binding => 0x18,
                             primary_key_binding => 0x19,
                             key_signature => 0x1f,
                             key_revocation => 0x20,
                             subkey_revocation => 0x28,
                             certification_revocation => 0x30,
                             timestamp => 0x40,
                             thirdparty => 0x50,
                           },

              # see RFC 4880 section 5.2.3.23
              revocation_reasons => { no_reason_specified => 0,
                                      key_superseded => 1,
                                      key_compromised => 2,
                                      key_retired => 3,
                                      user_id_no_longer_valid => 32,
                                    },

              # see RFC 4880 section 5.2.3.1
              subpacket_types => { sig_creation_time => 2,
                                   sig_expiration_time => 3,
                                   exportable => 4,
                                   trust_sig => 5,
                                   regex => 6,
                                   revocable => 7,
                                   key_expiration_time => 9,
                                   preferred_cipher => 11,
                                   revocation_key => 12,
                                   issuer => 16,
                                   notation => 20,
                                   preferred_digest => 21,
                                   preferred_compression => 22,
                                   keyserver_prefs => 23,
                                   preferred_keyserver => 24,
                                   primary_uid => 25,
                                   policy_uri => 26,
                                   usage_flags => 27,
                                   signers_uid => 28,
                                   revocation_reason => 29,
                                   features => 30,
                                   signature_target => 31,
                                   embedded_signature => 32,
                                 },

              # bitstring (see RFC 4880 section 5.2.3.24)
              features => { mdc => 0x01
                          },

              # bitstring (see RFC 4880 5.2.3.17)
              keyserver_prefs => { nomodify => 0x80
                                 },
             };


# takes a Math::BigInt, returns it formatted as OpenPGP MPI
# (RFC 4880 section 3.2)
sub mpi_pack {
  my $num = shift;

  my $hex = $num->as_hex();
  $hex =~ s/^0x//;
  # ensure we've got an even multiple of 2 nybbles here.
  $hex = '0'.$hex
    if (length($hex) % 2);

  my $val = pack('H*', $hex);
  my $mpilen = length($val)*8;

# this is a kludgy way to get the number of significant bits in the
# first byte:
  my $bitsinfirstbyte = length(sprintf("%b", ord($val)));

  $mpilen -= (8 - $bitsinfirstbyte);

  return pack('n', $mpilen).$val;
}

sub make_rsa_pub_key_body {
  my $key = shift;
  my $key_timestamp = shift;

  return
    pack('CN', 4, $key_timestamp).
      pack('C', $tables->{asym_algos}->{rsa}).
	mpi_pack($key->{modulus}).
	  mpi_pack($key->{exponent});
}

sub fingerprint {
  my $key = shift;
  my $key_timestamp = shift;

  my $rsabody = make_rsa_pub_key_body($key, $key_timestamp);

  return Digest::SHA::sha1(pack('Cn', 0x99, length($rsabody)).$rsabody);
}


1;
