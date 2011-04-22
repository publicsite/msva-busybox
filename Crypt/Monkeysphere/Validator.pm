package Crypt::Monkeysphere::Validator;
use Carp;
use strict;
use warnings;

use parent 'Crypt::Monkeysphere::Keyserver';

=pod

=head2 new

Create a new Crypt::Monkeysphere::Validator instance

Arguments

     Param hash, all optional.

     context => 'e-mail|https|ssh|...'
			control what counts as suitable user IDs and key capabilities.

     kspolicy => 'always|never|unlessvalid'
			when to fetch keys and key updates from keyserver.

  (plus arguments for Crypt::Monkeysphere::{Keyserver,Logger}::new )

=head2 lookup

Arguments

    Param hash.

    uid => (mandatory) OpenPGP User ID desired.

    fpr => fingerprint of the key to compare

    key => hash of pubkey parameters as Math::BigInt values

one of either fpr or key must be supplied.

Return Value

    Returns a hashref

    If the lookup succeeded, then the hashref has a key named
    valid_key that points to a hashref { fingerprint => $fpr, val =>
    $validity }.

    If no fully-valid keys+userid were found, but some keys matched
    with less-than-valid user IDs, then the hashref has a key named
    subvalid_keys that points to an arrayref of { fingerprint => $fpr,
    val => $validity } hashrefs.

=cut

sub new {
  my $class=shift;
  my %opts=@_;

  my $self=$class->SUPER::new(%opts);

  $self->{context}=$opts{context} || 'ssh';
  $self->{kspolicy}=$opts{kspolicy} || 'unlessvalid';
  return $self;
}

sub test_capable {
  my $self=shift;
  my $subkey=shift;

  if ($self->{context} eq 'e-mail') {
    if ($subkey->usage_flags =~ /s/) {
      $self->log('verbose', "...and is signing-capable...\n");
      return 1;
    } else {
      $self->log('verbose', "...but is not signing-capable (%s).\n",$subkey->usage_flags);
    }
  } else {
    if ($subkey->usage_flags =~ /a/) {
      $self->log('verbose', "...and is authentication-capable...\n");
      return 1;
    } else {
      $self->log('verbose', "...but is not authentication-capable (%s).\n",$subkey->usage_flags);
    }
  }
  return 0;
}

sub _tryquery {
  my $self=shift;
  my %args=@_;

  my $uid=$args{uid} || croak "uid argument is mandatory";
  my $fpr=$args{fpr};
  my $key=$args{key};
  defined($fpr) || defined($key) || croak "Must supply either a fingerprint or a key";

  my $subvalid_keys = [];

  my $gpgquery = defined($fpr) ? '0x'.$fpr : '='.$uid;

  foreach my $gpgkey ($self->{gnupg}->get_public_keys($gpgquery)) {
    my $validity = '-';
    foreach my $tryuid ($gpgkey->user_ids) {
      if ($tryuid->as_string eq $uid) {
        $validity = $tryuid->validity;
      }
    }
    # treat primary keys just like subkeys:
    foreach my $subkey ($gpgkey, @{$gpgkey->subkeys}) {
      if ((defined($key) && $self->keycomp($key, $subkey)) ||
          (defined($fpr) && ($subkey->fingerprint->as_hex_string eq $fpr))) {
        $self->log('verbose', "key 0x%s matches...\n",$subkey->hex_id);
        if ($self->test_capable($subkey) ) {
          if ($validity =~ /^[fu]$/) {
            $self->log('verbose', "...and is fully valid!\n");
            # we have a key that matches with a valid userid -- no need to look further.
            return {valid_key => { fingerprint => $subkey->fingerprint, val => $validity }};
          } else {
            $self->log('verbose', "...but is not fully valid (%s).\n",$validity);
            push(@{$subvalid_keys},
                 {fingerprint => $subkey->fingerprint, val => $validity });
          }
        }
      }
    }
  }
  return { subvalid_keys => $subvalid_keys };
}

sub lookup {
  my $self=shift;
  my %opts=@_;

  if ($self->{kspolicy} eq 'unlessvalid') {
    my $ret = $self->_tryquery(uid => $opts{uid}, fpr => $opts{fpr}, key => $opts{key});
    return $ret
      if exists($ret->{valid_key});
  };

  if ($self->{kspolicy} ne 'never') {
    if (defined($opts{fpr})) {
      $self->fetch_fpr($opts{fpr});
    } else {
      $self->fetch_uid($opts{uid});
    }
  }
  return $self->_tryquery(uid => $opts{uid}, fpr => $opts{fpr}, key => $opts{key});
}

sub valid_binding {
  my $self = shift;
  my $uid  = shift;
  my $gpgkey = shift;

  my $validity = '-';
  foreach my $tryuid ($gpgkey->user_ids) {
    if ($tryuid->as_string eq $uid) {
      return 1
        if $tryuid->validity =~ /^[fu]$/;
    }
  }
  return 0;
}

=pod

=head2 findall

Find all keys with appropriate capabilities and valid bindings to the given uid.

=cut

sub findall{
  my $self=shift;
  my $uid=shift;

  $self->fetch_uid($uid) if ($self->{kspolicy} eq 'always');

  my @keys = $self->_findall($uid);

  if (scalar(@keys) == 0 and $self->{kspolicy} eq 'unlessvalid'){
    $self->fetch_uid($uid);
    @keys=$self->_findall($uid);
  }

  return @keys;
}

sub _findall {
  my $self=shift;
  my $uid=shift;

  my @keys;
  my $x = 0;

  foreach my $gpgkey ($self->{gnupg}->get_public_keys('='.$uid)) {
    if ($self->valid_binding($uid, $gpgkey)) {
      foreach my $subkey ($gpgkey, @{$gpgkey->subkeys()}) {
	if ($self->test_capable($subkey) ) {
	  $self->log('verbose', "key 0x%s is capable...\n",$subkey->hex_id);

	  push(@keys, $subkey);
	}
      }
    }
  }
  return @keys;
}


sub keycomp {
  my $self=shift;
  my $rsakey = shift;
  my $gpgkey = shift;

  if ($gpgkey->algo_num != 1) {
    my $self->log('verbose', "Monkeysphere only does RSA keys.  This key is algorithm #%d\n", $gpgkey->algo_num);
    } else {
      if ($rsakey->{exponent}->bcmp($gpgkey->pubkey_data->[1]) == 0 &&
          $rsakey->{modulus}->bcmp($gpgkey->pubkey_data->[0]) == 0) {
        return 1;
      }
    }
    return 0;
  }

1;
