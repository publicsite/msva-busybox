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

our $default_keyserver='hkp://pool.sks-keyservers.net';

sub new {
  my $class=shift;
  my %opts=@_;

  my $self=$class->SUPER::new($opts{loglevel} || 'info');

  $self->{keyserver} = $opts{keyserver} || $self->_get_keyserver();
  $self->{gnupg} = $opts{gnupg} || new GnuPG::Interface();
  return $self;
}

sub _get_keyserver{

  my $self=shift;

  my $gpghome;

  if (exists $ENV{GNUPGHOME} and $ENV{GNUPGHOME} ne '') {
    $gpghome = untaint($ENV{GNUPGHOME});
  } else {
    $gpghome = File::Spec->catfile(File::HomeDir->my_home, '.gnupg');
  }
  my $gpgconf = File::Spec->catfile($gpghome, 'gpg.conf');
  if (-f $gpgconf) {
    if (-r $gpgconf) {
      my %gpgconfig = Config::General::ParseConfig($gpgconf);
      if ($gpgconfig{keyserver} =~ /^(((hkps?|hkpms|finger|ldap):\/\/)?$RE{net}{domain})$/) {
	$self->log('debug', "Using keyserver %s from the GnuPG configuration file (%s)\n", $1, $gpgconf);
	return $1;
      } else {
	$self->log('error', "Not a valid keyserver (from gpg config %s):\n  %s\n", $gpgconf, $gpgconfig{keyserver});
      }
    } else {
      $self->log('error', "The GnuPG configuration file (%s) is not readable\n", $gpgconf);
    }
  } else {
    $self->log('info', "Did not find GnuPG configuration file while looking for keyserver '%s'\n", $gpgconf);
  }

  return $default_keyserver;
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
