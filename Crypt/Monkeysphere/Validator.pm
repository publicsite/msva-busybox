package Crypt::Monkeysphere::Validator;
use Carp;
use strict;
use warnings;

use parent 'Crypt::Monkeysphere::Keyserver';

sub new {
  my $class=shift;
  my %opts=@_;

  my $self=$class->SUPER::new(%opts);

  $self->{findall} = $opts{findall} || 0;
  $self->{context}=$opts{context} || 'ssh';

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

sub query{
  my $self=shift;
  my %opts=@_;

  my $uid=$opts{uid} || croak "uid argument is mandatory";
  my $fpr=$opts{fpr};
  my $key=$opts{key};

  my $gpgquery = defined($fpr) ?  '0x'.$fpr : '='.$uid;

  my $ret= { valid_keys => [],
	     subvalid_keys => [] };

  # setup variables
  my $lastloop = 0;
  my $foundvalid = 0;

  if ($self->{kspolicy} eq 'always') {
    if (defined $fpr) {
      $self->fetch_fpr($fpr);
    } else {
      $self->fetch_uid($uid);
    }
    $lastloop = 1;
  } elsif ($self->{kspolicy} eq 'never') {
    $lastloop = 1;
  }

  while (1) {
    foreach my $gpgkey ($self->{gnupg}->get_public_keys($gpgquery)) {
      my $validity = '-';
      foreach my $tryuid ($gpgkey->user_ids) {
	if ($tryuid->as_string eq $uid) {
	  $validity = $tryuid->validity;
	}
      }
      # treat primary keys just like subkeys:
      foreach my $subkey ($gpgkey, @{$gpgkey->subkeys}) {
          if ((!defined($key) && (!defined($fpr))) ||
	      (defined($key) && $self->keycomp($key, $subkey)) ||
              (defined($fpr) && ($subkey->fingerprint->as_hex_string eq $fpr))) {
	    $self->log('verbose', "key 0x%s matches...\n",$subkey->hex_id);
	    if ($self->test_capable($subkey) ) {
	      if ($validity =~ /^[fu]$/) {
		$foundvalid = 1;
		$self->log('verbose', "...and is fully valid!\n");
		push(@{$ret->{valid_keys}},
		     { fingerprint => $subkey->fingerprint, val => $validity });
		last unless($self->{findall});
	      } else {
		$self->log('verbose', "...but is not fully valid (%s).\n",$validity);
		push(@{$self->{subvalid_keys}},
		     {fingerprint => $subkey->fingerprint, val => $validity }) if $lastloop;
	      }
	    }
	  }
	}
	last if ($foundvalid);
      }
      if ($lastloop || $foundvalid) {
	last;
      } else {
	if (!$foundvalid) {
	  if (defined $fpr) {
	    $self->fetch_fpr($fpr);
	  } else {
	    $self->fetch_uid($uid);
	  }
	}
	$lastloop = 1;
      }
    }

  return $ret;

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
