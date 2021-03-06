package Crypt::Monkeysphere::Keyserver;
use IO::File;
use GnuPG::Handles;
use GnuPG::Interface;
use File::HomeDir;
use Config::General;
use Regexp::Common qw /net/;
use POSIX;

use strict;
use warnings;
use parent qw(Crypt::Monkeysphere::Logger);
use Crypt::Monkeysphere::Util qw(untaint);

our $default_keyserver='hkp://pool.sks-keyservers.net';

=pod 

=head2 new

Create a new Crypt::Monkeysphere::Keyserver instance

Arguments
  Param hash, all optional.

     keyserver => URL
     gnupg => GnuPG::Interface object

  (plus arguments for Crypt::Monkeysphere::Logger::new)

=cut
sub new {
  my $class=shift;
  my %opts=@_;

  my $self=$class->SUPER::new($opts{loglevel} || 'info');

  # gnupg should be initialized first, before figuring out 
  # what keyserver to use.

  $self->{gnupg} = $opts{gnupg} || new GnuPG::Interface();

  $self->{keyserver} = $opts{keyserver} || $self->_get_keyserver();
  return $self;
}

sub _get_keyserver{

  my $self=shift;

  my $gpghome=$self->{gnupg}->options->homedir;

  if (!defined($gpghome)) {
    if (exists $ENV{GNUPGHOME} and $ENV{GNUPGHOME} ne '') {

      # We might be running in taint mode, but we assume that is about
      # data coming from the network, and that the local environment
      # is generally trustworthy.

      $gpghome = untaint($ENV{GNUPGHOME});
    } else {
      my $userhome=File::HomeDir->my_home;
      if (defined($userhome)) {
	$gpghome = File::Spec->catfile($userhome, '.gnupg');
      }
    }
  }

  if (defined $gpghome) {
    return $self->_read_keyserver_from_gpg_conf($gpghome) || $default_keyserver;
  } else {
    return $default_keyserver;
  }

}

sub _read_keyserver_from_gpg_conf() {
  my $self=shift;
  my $gpghome=shift;

  my $gpgconf = File::Spec->catfile($gpghome, 'gpg.conf');
  if (-f $gpgconf) {
    if (-r $gpgconf) {
      my %gpgconfig = Config::General::ParseConfig($gpgconf);
      if (! defined $gpgconfig{keyserver}) {
	$self->log('debug', "No keyserver line found in GnuPG configuration file (%s)\n", $gpgconf);
      } else {
        if (ref($gpgconfig{keyserver}) eq 'ARRAY') {
          # use the last keyserver entry if there is more than one.
          $self->log('debug', "more than one keyserver line found in GnuPG configuration file (%s), using last one found\n", $gpgconf);
          $gpgconfig{keyserver} = pop(@{$gpgconfig{keyserver}});
        }
        if ($gpgconfig{keyserver} =~ /^(((hkps?|hkpms|finger|ldap):\/\/)?$RE{net}{domain})$/) {
          $self->log('debug', "Using keyserver %s from the GnuPG configuration file (%s)\n", $1, $gpgconf);
          return $1;
        } else {
          $self->log('error', "Not a valid keyserver (from gpg config %s):\n  %s\n", $gpgconf, $gpgconfig{keyserver});
        }
      }
    } else {
      $self->log('error', "The GnuPG configuration file (%s) is not readable\n", $gpgconf);
    }
  } else {
    $self->log('info', "Did not find GnuPG configuration file while looking for keyserver '%s'\n", $gpgconf);
  }
  return undef;
}


sub fetch_uid {
  my $self= shift;
  my $uid = shift || croak("uid argument mandatory");

  my $ks=$self->{keyserver};
  my $gnupg=$self->{gnupg};

  my $cmd = IO::Handle::->new();
  my $out = IO::Handle::->new();
  my $nul = IO::File::->new("< /dev/null");

  $self->log('debug', "start ks query to %s for UserID: %s\n", $ks, $uid);
    my $pid = $gnupg->wrap_call
      ( handles => GnuPG::Handles::->new( command => $cmd, stdout => $out, stderr => $nul ),
        command_args => [ '='.$uid ],
        commands => [ '--keyserver',
                      $ks,
                      qw( --no-tty --with-colons --search ) ]
      );
    while (my $line = $out->getline()) {
      $self->log('debug', "from ks query: (%d) %s", $cmd->fileno, $line);
      if ($line =~ /^info:(\d+):(\d+)/ ) {
        $cmd->print(join(' ', ($1..$2))."\n");
        $self->log('debug', 'to ks query: '.join(' ', ($1..$2))."\n");
        last;
      }
    }
    # FIXME: can we do something to avoid hanging forever?
    waitpid($pid, 0);
    $self->log('debug', "ks query returns %d\n", POSIX::WEXITSTATUS($?));
  }

sub fetch_fpr {
  my $self = shift;
  my $fpr = shift || croak("fpr argument mandatory");

  my $ks=$self->{keyserver};
  my $gnupg=$self->{gnupg};

  my $cmd = IO::Handle::->new();
  my $nul = IO::File::->new("< /dev/null");

  $self->log('debug', "start ks query to %s for fingerprint: %s\n", $ks, $fpr);
  my $pid = $gnupg->wrap_call
    ( handles => GnuPG::Handles::->new( command => $cmd, stdout => $nul, stderr => $nul ),
      command_args => [ '0x'.$fpr ],
      commands => [ '--keyserver',
		    $ks,
		    qw( --no-tty --recv-keys ) ]
    );
  # FIXME: can we do something to avoid hanging forever?
  waitpid($pid, 0);
  $self->log('debug', "ks query returns %d\n", POSIX::WEXITSTATUS($?));
}

1;
