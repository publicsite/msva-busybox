# Monkeysphere Validation Agent, Perl version
# Copyright © 2010 Daniel Kahn Gillmor <dkg@fifthhorseman.net>,
#                  Jameson Rollins <jrollins@finestructure.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

{ package Crypt::Monkeysphere::MSVA;

  use strict;
  use warnings;
  use vars qw($VERSION);

  use parent qw(HTTP::Server::Simple::CGI);

  use Crypt::Monkeysphere::Validator;

  use Crypt::X509 0.50;
  use Regexp::Common qw /net/;
  use MIME::Base64;
  use IO::Socket;
  use IO::File;
  use Socket;
  use File::Spec;
  use File::HomeDir;
  use Config::General;
  use Crypt::Monkeysphere::MSVA::MarginalUI;
  use Crypt::Monkeysphere::Logger;
  use Crypt::Monkeysphere::Util qw(untaint);
  use Crypt::Monkeysphere::MSVA::Monitor;
  use Crypt::Monkeysphere::OpenPGP;

  use JSON;
  use POSIX qw(strftime);
  # we need the version of GnuPG::Interface that knows about pubkey_data, etc:
  use GnuPG::Interface 0.43;

  $VERSION = '0.9.2';

  my $gnupg = GnuPG::Interface::->new();
  $gnupg->options->quiet(1);
  $gnupg->options->batch(1);

  my %dispatch = (
                  '/' => { handler => \&noop,
                           methods => { 'GET' => 1 },
                         },
                  '/reviewcert' => { handler => \&reviewcert,
                                     methods => { 'POST' => 1 },
                                   },
                  '/extracerts' => { handler => \&extracerts,
                                     methods => { 'POST' => 1 },
                                   },
                 );

  my $default_keyserver_policy = 'unlessvalid';

  my $logger = Crypt::Monkeysphere::Logger->new($ENV{MSVA_LOG_LEVEL});
  sub logger {
    return $logger;
  }

  sub net_server {
    return 'Net::Server::MSVA';
  };

  sub msvalog {
    return $logger->log(@_);
  };

  sub new {
    my $class = shift;

    my $port = 0;
    if (exists $ENV{MSVA_PORT} and $ENV{MSVA_PORT} ne '') {
      msvalog('debug', "MSVA_PORT set to %s\n", $ENV{MSVA_PORT});
      $port = $ENV{MSVA_PORT} + 0;
      die sprintf("not a reasonable port %d", $port) if (($port >= 65536) || $port <= 0);
    }
    # start the server on requested port
    my $self = $class->SUPER::new($port);
    if (! exists $ENV{MSVA_PORT}) {
      # we can't pass port 0 to the constructor because it evaluates
      # to false, so HTTP::Server::Simple just uses its internal
      # default of 8080.  But if we want to select an arbitrary open
      # port, we *can* set it here.
      $self->port(0);
    }

    $self->{allowed_uids} = {};
    if (exists $ENV{MSVA_ALLOWED_USERS} and $ENV{MSVA_ALLOWED_USERS} ne '') {
      msvalog('verbose', "MSVA_ALLOWED_USERS environment variable is set.\nLimiting access to specified users.\n");
      foreach my $user (split(/ +/, $ENV{MSVA_ALLOWED_USERS})) {
        my ($name, $passwd, $uid);
        if ($user =~ /^[0-9]+$/) {
          $uid = $user + 0; # force to integer
        } else {
          ($name,$passwd,$uid) = getpwnam($user);
        }
        if (defined $uid) {
          msvalog('verbose', "Allowing access from user ID %d\n", $uid);
          $self->{allowed_uids}->{$uid} = $user;
        } else {
          msvalog('error', "Could not find user '%d'; not allowing\n", $user);
        }
      }
    } else {
      # default is to allow access only to the current user
      $self->{allowed_uids}->{POSIX::getuid()} = 'self';
    }

    bless ($self, $class);
    return $self;
  }

  sub noop {
    my $self = shift;
    my $cgi = shift;
    return '200 OK', { available => JSON::true,
                       protoversion => 1,
                     };
  }

  # return an arrayref of processes which we can detect that have the
  # given socket open (the socket is specified with its inode)
  sub getpidswithsocketinode {
    my $sockid = shift;

    if (! defined ($sockid)) {
      msvalog('verbose', "No client socket ID to check.  The MSVA is probably not running as a service.\n");
      return [];
    }
    # this appears to be how Linux symlinks open sockets in /proc/*/fd,
    # as of at least 2.6.26:
    my $socktarget = sprintf('socket:[%d]', $sockid);
    my @pids;

    my $procfs;
    if (opendir($procfs, '/proc')) {
      foreach my $pid (grep { /^\d+$/ } readdir($procfs)) {
        my $procdir = sprintf('/proc/%d', $pid);
        if (-d $procdir) {
          my $procfds;
          if (opendir($procfds, sprintf('/proc/%d/fd', $pid))) {
            foreach my $procfd (grep { /^\d+$/ } readdir($procfds)) {
              my $fd = sprintf('/proc/%d/fd/%d', $pid, $procfd);
              if (-l $fd) {
                #my ($dev,$ino,$mode,$nlink,$uid,$gid) = lstat($fd);
                my $targ = readlink($fd);
                push @pids, $pid
                  if ($targ eq $socktarget);
              }
            }
            closedir($procfds);
          }
        }
      }
      closedir($procfs);
    }

    # FIXME: this whole business is very linux-specific, i think.  i
    # wonder how to get this info in other OSes?

    return \@pids;
  }

  # return {uid => X, inode => Y}, meaning the numeric ID of the peer
  # on the other end of $socket, "socket inode" identifying the peer's
  # open network socket.  each value could be undef if unknown.
  sub get_client_info {
    my $socket = shift;

    my $sock = IO::Socket::->new_from_fd($socket, 'r');
    # check SO_PEERCRED -- if this was a TCP socket, Linux
    # might not be able to support SO_PEERCRED (even on the loopback),
    # though apparently some kernels (Solaris?) are able to.

    my $clientid;
    my $remotesocketinode;
    my $socktype = $sock->sockopt(SO_TYPE) or die "could not get SO_TYPE info";
    if (defined $socktype) {
      msvalog('debug', "sockopt(SO_TYPE) = %d\n", $socktype);
    } else {
      msvalog('verbose', "sockopt(SO_TYPE) returned undefined.\n");
    }

    my $peercred = $sock->sockopt(SO_PEERCRED) or die "could not get SO_PEERCRED info";
    my $client = $sock->peername();
    my $family = sockaddr_family($client); # should be AF_UNIX (a.k.a. AF_LOCAL) or AF_INET

    msvalog('verbose', "socket family: %d\nsocket type: %d\n", $family, $socktype);

    if ($peercred) {
      # FIXME: on i386 linux, this appears to be three ints, according to
      # /usr/include/linux/socket.h.  What about other platforms?
      my ($pid, $uid, $gid) = unpack('iii', $peercred);

      msvalog('verbose', "SO_PEERCRED: pid: %u, uid: %u, gid: %u\n",
              $pid, $uid, $gid,
             );
      if ($pid != 0 && $uid != 0) { # then we can accept it:
        $clientid = $uid;
      }
      # FIXME: can we get the socket inode as well this way?
    }

    # another option in Linux would be to parse the contents of
    # /proc/net/tcp to find the uid of the peer process based on that
    # information.
    if (! defined $clientid) {
      msvalog('verbose', "SO_PEERCRED failed, digging around in /proc/net/tcp\n");
      my $proto;
      if ($family == AF_INET) {
        $proto = '';
      } elsif ($family == AF_INET6) {
        $proto = '6';
      }
      if (defined $proto) {
        if ($socktype == &SOCK_STREAM) {
          $proto = 'tcp'.$proto;
        } elsif ($socktype == &SOCK_DGRAM) {
          $proto = 'udp'.$proto;
        } else {
          undef $proto;
        }
        if (defined $proto) {
          my ($port, $iaddr) = unpack_sockaddr_in($client);
          my $iaddrstring = unpack("H*", reverse($iaddr));
          msvalog('verbose', "Port: %04x\nAddr: %s\n", $port, $iaddrstring);
          my $remmatch = lc(sprintf("%s:%04x", $iaddrstring, $port));
          my $infofile = '/proc/net/'.$proto;
          my $f = IO::File::->new();
          if ( $f->open('< '.$infofile)) {
            my @header = split(/ +/, <$f>);
            my ($localaddrix, $uidix, $inodeix);
            my $ix = 0;
            my $skipcount = 0;
            while ($ix <= $#header) {
              $localaddrix = $ix - $skipcount if (lc($header[$ix]) eq 'local_address');
              $uidix = $ix - $skipcount if (lc($header[$ix]) eq 'uid');
              $inodeix = $ix - $skipcount if (lc($header[$ix]) eq 'inode');
              $skipcount++ if (lc($header[$ix]) eq 'tx_queue') or (lc($header[$ix]) eq 'tr'); # these headers don't actually result in a new column during the data rows
              $ix++;
            }
            if (!defined $localaddrix) {
              msvalog('info', "Could not find local_address field in %s; unable to determine peer UID\n",
                      $infofile);
            } elsif (!defined $uidix) {
              msvalog('info', "Could not find uid field in %s; unable to determine peer UID\n",
                      $infofile);
            } elsif (!defined $inodeix) {
              msvalog('info', "Could not find inode field in %s; unable to determine peer network socket inode\n",
                      $infofile);
            } else {
              msvalog('debug', "local_address: %d; uid: %d\n", $localaddrix,$uidix);
              while (my @line = split(/ +/,<$f>)) {
                if (lc($line[$localaddrix]) eq $remmatch) {
                  if (defined $clientid) {
                    msvalog('error', "Warning! found more than one remote uid! (%s and %s\n", $clientid, $line[$uidix]);
                  } else {
                    $clientid = $line[$uidix];
                    $remotesocketinode = $line[$inodeix];
                    msvalog('info', "remote peer is uid %d (inode %d)\n",
                            $clientid, $remotesocketinode);
                  }
                }
              }
            msvalog('error', "Warning! could not find peer information in %s.  Not verifying.\n", $infofile) unless defined $clientid;
            }
          } else { # FIXME: we couldn't read the file.  what should we
                   # do besides warning?
            msvalog('info', "Could not read %s; unable to determine peer UID\n",
                    $infofile);
          }
        }
      }
    }
    return { 'uid' => $clientid,
             'inode' => $remotesocketinode };
  }

  sub handle_request {
    my $self = shift;
    my $cgi  = shift;

    # This is part of a spawned child process.  We don't want the
    # child process to destroy the update monitor when it terminates.
    $self->{updatemonitor}->forget() if exists $self->{updatemonitor} && defined $self->{updatemonitor};
    my $clientinfo = get_client_info(select);
    my $clientuid = $clientinfo->{uid};

    if (defined $clientuid) {
      # test that this is an allowed user:
      if (exists $self->{allowed_uids}->{$clientuid}) {
        msvalog('verbose', "Allowing access from uid %d (%s)\n", $clientuid, $self->{allowed_uids}->{$clientuid});
      } else {
        msvalog('error', "MSVA client connection from uid %d, forbidden.\n", $clientuid);
        printf("HTTP/1.0 403 Forbidden -- peer does not match local user ID\r\nContent-Type: text/plain\r\nDate: %s\r\n\r\nHTTP/1.1 403 Not Found -- peer does not match the local user ID.  Are you sure the agent is running as the same user?\r\n",
               strftime("%a, %d %b %Y %H:%M:%S %z", localtime(time())),);
        return;
      }
    }

    my $path = $cgi->path_info();
    my $handler = $dispatch{$path};

    if (ref($handler) eq "HASH") {
      if (! exists $handler->{methods}->{$cgi->request_method()}) {
        printf("HTTP/1.0 405 Method not allowed\r\nAllow: %s\r\nDate: %s\r\n",
               join(', ', keys(%{$handler->{methods}})),
               strftime("%a, %d %b %Y %H:%M:%S %z", localtime(time())));
      } elsif (ref($handler->{handler}) ne "CODE") {
        printf("HTTP/1.0 500 Server Error\r\nDate: %s\r\n",
               strftime("%a, %d %b %Y %H:%M:%S %z", localtime(time())));
      } else {
        my $data = {};
        my $ctype = $cgi->content_type();
        msvalog('verbose', "Got %s %s (Content-Type: %s)\n", $cgi->request_method(), $path, defined $ctype ? $ctype : '**none supplied**');
        if (defined $ctype) {
          my @ctypes = split(/; */, $ctype);
          $ctype = shift @ctypes;
          if ($ctype eq 'application/json') {
            $data = from_json($cgi->param('POSTDATA'));
          }
        };

        my ($status, $object) = $handler->{handler}($data, $clientinfo);
        if (ref($object) eq 'HASH' &&
            ! defined $object->{server}) {
          $object->{server} = sprintf("MSVA-Perl %s", $VERSION);
        }

        my $ret = to_json($object);
        msvalog('info', "returning: %s\n", $ret);
        printf("HTTP/1.0 %s\r\nDate: %s\r\nContent-Type: application/json\r\n\r\n%s",
               $status,
               strftime("%a, %d %b %Y %H:%M:%S %z", localtime(time())),
               $ret);
      }
    } else {
      printf("HTTP/1.0 404 Not Found -- not handled by Monkeysphere validation agent\r\nContent-Type: text/plain\r\nDate: %s\r\n\r\nHTTP/1.0 404 Not Found -- the path:\r\n   %s\r\nis not handled by the MonkeySphere validation agent.\r\nPlease try one of the following paths instead:\r\n\r\n%s\r\n",
             strftime("%a, %d %b %Y %H:%M:%S %z", localtime(time())),
             $path, ' * '.join("\r\n * ", keys %dispatch) );
    }
  }

  sub get_keyserver_policy {
    if (exists $ENV{MSVA_KEYSERVER_POLICY} and $ENV{MSVA_KEYSERVER_POLICY} ne '') {
      if ($ENV{MSVA_KEYSERVER_POLICY} =~ /^(always|never|unlessvalid)$/) {
        return $1;
      }
      msvalog('error', "Not a valid MSVA_KEYSERVER_POLICY):\n  %s\n", $ENV{MSVA_KEYSERVER_POLICY});
    }
    return $default_keyserver_policy;
  }

  sub get_keyserver {
    # We should read from (first hit wins):
    # the environment
    if (exists $ENV{MSVA_KEYSERVER} and $ENV{MSVA_KEYSERVER} ne '') {
      if ($ENV{MSVA_KEYSERVER} =~ /^(((hkps?|hkpms|finger|ldap):\/\/)?$RE{net}{domain})$/) {
        return $1;
      }
      msvalog('error', "Not a valid keyserver (from MSVA_KEYSERVER):\n  %s\n", $ENV{MSVA_KEYSERVER});
    }

    # FIXME: some msva.conf or monkeysphere.conf file (system and user?)

    # let the keyserver routines choose.
    return undef;
  }


##################################################
## PKC KEY EXTRACTION ############################

  sub pkcextractkey {
    my $data = shift;
    my $key;

    if (lc($data->{pkc}->{type}) eq 'x509der') {
      $key = der2key(join('', map(chr, @{$data->{pkc}->{data}})));
    } elsif (lc($data->{pkc}->{type}) eq 'x509pem') {
      $key = der2key(pem2der($data->{pkc}->{data}));
    } elsif (lc($data->{pkc}->{type}) eq 'opensshpubkey') {
      $key = opensshpubkey2key($data->{pkc}->{data});
    } elsif (lc($data->{pkc}->{type}) eq 'rfc4716') {
      $key = rfc47162key($data->{pkc}->{data});
    } else {
      $key->{error} = sprintf("Don't know this public key carrier type: %s", $data->{pkc}->{type});
    }

    if (exists $key->{error}) {
      return $key;
    }

    # make sure that the returned integers are Math::BigInts:
    $key->{exponent} = Math::BigInt::->new($key->{exponent}) unless (ref($key->{exponent}));
    $key->{modulus} = Math::BigInt::->new($key->{modulus}) unless (ref($key->{modulus}));
    msvalog('debug', "pubkey info:\nmodulus: %s\nexponent: %s\n",
            $key->{modulus}->as_hex(),
            $key->{exponent}->as_hex(),
           );

    if ($key->{modulus}->copy()->blog(2) < 1000) {
      $key->{error} = sprintf('Public key size is less than 1000 bits (was: %d bits)', $key->{modulus}->copy()->blog(2));
    }

    return $key;
  }

  sub der2key {
    my $rawdata = shift;

    my $cert = Crypt::X509::->new(cert => $rawdata);

    my $key = {error => 'I do not know what happened here'};

    if ($cert->error) {
      $key->{error} = sprintf("Error decoding X.509 certificate: %s", $cert->error);
    } else {
      msvalog('verbose', "cert subject: %s\n", $cert->subject_cn());
      msvalog('verbose', "cert issuer: %s\n", (defined $cert->issuer_cn() ? $cert->issuer_cn() : '<none>'));
      msvalog('verbose', "cert pubkey algo: %s\n", $cert->PubKeyAlg());
      msvalog('verbose', "cert pubkey: %s\n", unpack('H*', $cert->pubkey()));

      if ($cert->PubKeyAlg() ne 'RSA') {
        $key->{error} = sprintf('public key was algo "%s" (OID %s).  MSVA.pl only supports RSA',
                                $cert->PubKeyAlg(), $cert->pubkey_algorithm);
      } else {
        msvalog('debug', "decoding ASN.1 pubkey\n");
        $key = $cert->pubkey_components();
        if (! defined $key) {
          msvalog('verbose', "failed to decode %s\n", unpack('H*', $cert->pubkey()));
          $key = {error => 'failed to decode the public key'};
        } else {
          # ensure these are Math::BigInts!
          $key->{exponent} = Math::BigInt::->new($key->{exponent}) unless (ref($key->{exponent}));
          $key->{modulus} = Math::BigInt::->new($key->{modulus}) unless (ref($key->{modulus}));

          my $pgpext = $cert->PGPExtension();
          if (defined $pgpext) {
            $key->{openpgp4fpr} = Crypt::Monkeysphere::OpenPGP::fingerprint($key, $pgpext);
            msvalog('verbose', "OpenPGP Fingerprint (derived from X.509 cert): 0x%s\n", uc(unpack("H*", $key->{openpgp4fpr})));
          }
        }
      }
    }
    return $key;
  }

  sub pem2der {
    my $pem = shift;
    my @lines = split(/\r?\n/, $pem);
    my @goodlines = ();
    my $ready = 0;
    foreach my $line (@lines) {
      if ($line eq '-----END CERTIFICATE-----') {
        last;
      } elsif ($ready) {
        push @goodlines, $line;
      } elsif ($line eq '-----BEGIN CERTIFICATE-----') {
        $ready = 1;
      }
    }
    msvalog('debug', "%d lines of base64:\n%s\n", $#goodlines + 1, join("\n", @goodlines));
    return decode_base64(join('', @goodlines));
  }

  sub opensshpubkey2key {
    my $data = shift;
    # FIXME: do we care that the label matches the type of key?
    my ($label, $prop) = split(/ +/, $data);

    my $out = parse_rfc4716body($prop);

    return $out;
  }

  sub rfc47162key {
    my $data = shift;

    my @goodlines;
    my $continuation = '';
    my $state = 'outside';
    foreach my $line (split(/\n/, $data)) {
      last if ($state eq 'body' && $line eq '---- END SSH2 PUBLIC KEY ----');
      if ($state eq 'outside' && $line eq '---- BEGIN SSH2 PUBLIC KEY ----') {
        $state = 'header';
        next;
      }
      if ($state eq 'header') {
        $line = $continuation.$line;
        $continuation = '';
        if ($line =~ /^(.*)\\$/) {
          $continuation = $1;
          next;
        }
        if (! ($line =~ /:/)) {
          $state = 'body';
        }
      }
      push(@goodlines, $line) if ($state eq 'body');
    }

    msvalog('debug', "Found %d lines of RFC4716 body:\n%s\n",
            scalar(@goodlines),
            join("\n", @goodlines));
    my $out = parse_rfc4716body(join('', @goodlines));

    return $out;
  }

  sub parse_rfc4716body {
    my $data = shift;

    return undef
      unless defined($data);
    $data = decode_base64($data) or return undef;

    msvalog('debug', "key properties: %s\n", unpack('H*', $data));
    my $out = [ ];
    while (length($data) > 4) {
      my $size = unpack('N', substr($data, 0, 4));
      msvalog('debug', "size: 0x%08x\n", $size);
      return undef if (length($data) < $size + 4);
      push(@{$out}, substr($data, 4, $size));
      $data = substr($data, 4 + $size);
    }

    if ($out->[0] ne "ssh-rsa") {
      return {error => 'Not an RSA key'};
    }

    if (scalar(@{$out}) != 3) {
      return {error => 'Does not contain the right number of bigints for RSA'};
    }

    return { exponent => Math::BigInt->from_hex('0x'.unpack('H*', $out->[1])),
             modulus => Math::BigInt->from_hex('0x'.unpack('H*', $out->[2])),
           } ;
  }

## PKC KEY EXTRACTION ############################
##################################################

  sub reviewcert {
    my $data  = shift;
    my $clientinfo  = shift;
    return if !ref $data;

    msvalog('verbose', "reviewing data...\n");

    my $status = '200 OK';
    my $ret =  { valid => JSON::false,
                 message => 'Unknown failure',
               };

    # check that there actually is key data
    if ($data->{pkc}->{data} eq '') {
      $ret->{message} = sprintf("Key data empty.");
      return $status,$ret;
    }

    # check context string
    if ($data->{context} =~ /^(https|ssh|smtp|ike|postgresql|imaps|imap|submission|e-mail)$/) {
	$data->{context} = $1;
    } else {
	msvalog('error', "invalid context: %s\n", $data->{context});
	$ret->{message} = sprintf("Invalid/unknown context: %s", $data->{context});
	return $status,$ret;
    }
    msvalog('verbose', "context: %s\n", $data->{context});

    # checkout peer string
    # old-style just passed a string as a peer, rather than 
    # peer: { name: 'whatever', 'type': 'client' }
    $data->{peer} = { name => $data->{peer} }
      if (ref($data->{peer}) ne 'HASH');

    if (defined($data->{peer}->{type})) {
      if ($data->{peer}->{type} =~ /^(client|server|peer)$/) {
        $data->{peer}->{type} = $1;
      } else {
	msvalog('error', "invalid peer type string: %s\n", $data->{peer}->{type});
	$ret->{message} = sprintf("Invalid peer type string: %s", $data->{peer}->{type});
	return $status,$ret;
      }
    }

    my $prefix = $data->{context}.'://';
    if ($data->{context} eq 'e-mail' ||
       (defined $data->{peer}->{type} &&
        $data->{peer}->{type} eq 'client' &&
        # ike and smtp clients are effectively other servers, so we'll
        # exclude them:
        $data->{context} !~ /^(ike|smtp)$/)) {
      $prefix = '';
      # clients can have any one-line User ID without NULL characters
      # and leading or trailing whitespace
      if ($data->{peer}->{name} =~ /^([^[:space:]][^\n\0]*[^[:space:]]|[^\0[:space:]])$/) {
        $data->{peer}->{name} = $1;
      } else {
        msvalog('error', "invalid client peer name string: %s\n", $data->{peer}->{name});
        $ret->{message} = sprintf("Invalid client peer name string: %s", $data->{peer}->{name});
        return $status,$ret;
      }
    } elsif ($data->{peer}->{name} =~ /^($RE{net}{domain}(:[[:digit:]]+)?)$/) {
      $data->{peer}->{name} = $1;
    } else {
      msvalog('error', "invalid peer name string: %s\n", $data->{peer}->{name});
      $ret->{message} = sprintf("Invalid peer name string: %s", $data->{peer}->{name});
      return $status,$ret;
    }

    msvalog('verbose', "peer: %s\n", $data->{peer}->{name});

    # generate uid string
    my $uid = $prefix.$data->{peer}->{name};
    msvalog('verbose', "user ID: %s\n", $uid);

    # extract key or openpgp fingerprint from PKC
    my $fpr;
    my $key;
    if (lc($data->{pkc}->{type}) eq 'openpgp4fpr') {
      if ($data->{pkc}->{data} =~ /^(0x)?([[:xdigit:]]{40})$/) {
	$data->{pkc}->{data} = uc($2);
	$fpr = $data->{pkc}->{data};
      } else {
	msvalog('error', "invalid OpenPGP v4 fingerprint: %s\n",$data->{pkc}->{data});
	$ret->{message} = sprintf("Invalid OpenPGP v4 fingerprint.");
	return $status,$ret;
      }
    } else {
      # extract key from PKC
      $key = pkcextractkey($data);
      if (exists $key->{error}) {
	$ret->{message} = $key->{error};
	return $status,$ret;
      }
      $fpr = uc(unpack('H*', $key->{openpgp4fpr}))
        if (exists $key->{openpgp4fpr});
    }
    msvalog('verbose', "OpenPGP v4 fingerprint: %s\n",$fpr)
      if defined $fpr;

    # determine keyserver policy
    my $kspolicy;
    if (defined $data->{keyserverpolicy} &&
	$data->{keyserverpolicy} =~ /^(always|never|unlessvalid)$/) {
      $kspolicy = $1;
      msvalog("verbose", "using requested keyserver policy: %s\n", $1);
    } else {
      $kspolicy = get_keyserver_policy();
    }
    msvalog('debug', "keyserver policy: %s\n", $kspolicy);
    # needed because $gnupg spawns child processes
    $ENV{PATH} = '/usr/local/bin:/usr/bin:/bin';

    $ret->{message} = sprintf('Failed to validate "%s" through the OpenPGP Web of Trust.', $uid);

    my $validator=new Crypt::Monkeysphere::Validator(kspolicy=>$kspolicy,
						     context=>$data->{context},
						     keyserver=>get_keyserver(),
						     gnupg=>$gnupg,
						     logger=>$logger);

    my $uid_query=$validator->lookup(uid=>$uid,fpr=>$fpr,key=>$key);

    # only show the marginal UI if the UID of the corresponding
    # key is not fully valid.
    if (defined($uid_query->{valid_key})) {
      $ret->{valid} = JSON::true;
      $ret->{message} = sprintf('Successfully validated "%s" through the OpenPGP Web of Trust.', $uid);
    } else {
      my $resp = Crypt::Monkeysphere::MSVA::MarginalUI->ask_the_user($gnupg,
								     $uid,
								     $uid_query->{subvalid_keys},
								     getpidswithsocketinode($clientinfo->{inode}),
								     $logger);
      msvalog('info', "response: %s\n", $resp);
      if ($resp) {
	$ret->{valid} = JSON::true;
	$ret->{message} = sprintf('Manually validated "%s" through the OpenPGP Web of Trust.', $uid);
      }
    }

    return $status,$ret;
  }

  sub pre_loop_hook {
    my $self = shift;
    my $server = shift;

    $self->spawn_as_child($server);
  }

  sub pre_accept_hook {
    my $self = shift;
    my $server = shift;

    $self->parent_changed($server) if (defined $self->{parent_pid} && getppid() != $self->{parent_pid});
  }

  sub parent_changed {
    my $self = shift;
    my $server = shift;

    msvalog('verbose', "parent %d went away; exiting.\n", $self->{parent_pid});
    $server->set_exit_status(0);
    $server->server_close();
  }

  sub child_dies {
    my $self = shift;
    my $pid = shift;
    my $server = shift;

    msvalog('debug', "Subprocess %d terminated.\n", $pid);

    if (exists $self->{updatemonitor} &&
        defined $self->{updatemonitor}->getchildpid() &&
        $self->{updatemonitor}->getchildpid() == $pid) {
      my $exitstatus = POSIX::WEXITSTATUS($?);
      msvalog('verbose', "Update monitoring process (%d) terminated with code %d.\n", $pid, $exitstatus);
      if (0 == $exitstatus) {
        msvalog('info', "Reloading MSVA due to update request.\n");
        # sending self a SIGHUP:
        kill(1, $$);
      } else {
        msvalog('error', "Update monitoring process (%d) died unexpectedly with code %d.\nNo longer monitoring for updates; please send HUP manually.\n", $pid, $exitstatus);
        # it died for some other weird reason; should we respawn it?

        # FIXME: i'm worried that re-spawning would create a
        # potentially abusive loop, if there are legit, repeatable
        # reasons for the failure.

#        $self->{updatemonitor}->spawn();

        # instead, we'll just avoid trying to kill the next process with this PID:
        $self->{updatemonitor}->forget();
      }
    }
  }

  sub post_bind_hook {
    my $self = shift;
    my $server = shift;

    $server->{server}->{leave_children_open_on_hup} = 1;

    my $socketcount = @{ $server->{server}->{sock} };
    # note: we're assuming here that if there are more than one socket
    # open (e.g. IPv6 and IPv4, or multiple IP addresses of the same
    # family), they all share the same port number as socket 0.
    if ( $socketcount < 1 ) {
      msvalog('error', "%d sockets open; should have been at least 1.\n", $socketcount);
      $server->set_exit_status(10);
      $server->server_close();
    }
    if (!defined($self->port) || $self->port == 0) {
      my $port = @{ $server->{server}->{sock} }[0]->sockport();
      if (! defined($port)) {
        msvalog('error', "got undefined port.\nRecording as 0.\n", $port);
        $port = 0;
      } elsif (($port < 1) || ($port >= 65536)) {
        msvalog('error', "got nonsense port: %d.\nRecording as 0.\n", $port);
        $port = 0;
      } elsif ((exists $ENV{MSVA_PORT}) && (($ENV{MSVA_PORT} + 0) != $port)) {
        msvalog('error', "Explicitly requested port %d, but got port: %d.", ($ENV{MSVA_PORT}+0), $port);
        $server->set_exit_status(13);
        $server->server_close();
      }
      $self->port($port);
    }
  }

  sub spawn_as_child {
    my $self = shift;
    my $server = shift;

    if ((exists $ENV{MSVA_PARENT_PID}) && ($ENV{MSVA_PARENT_PID} ne '')) {
      # this is most likely a re-exec.
      msvalog('info', "This appears to be a re-exec, continuing with parent pid %d\n", $ENV{MSVA_PARENT_PID});
      $self->{parent_pid} = $ENV{MSVA_PARENT_PID} + 0;
     } elsif ($#ARGV >= 0) {
      $self->{parent_pid} = 0; # indicate that we are planning to fork.
      # avoid ignoring SIGCHLD right before we fork.
      $SIG{CHLD} = sub {
        my $val;
        while (defined($val = POSIX::waitpid(-1, POSIX::WNOHANG)) && $val > 0) {
          $self->child_dies($val, $server);
        }
      };
      my $pid = $$;
      my $fork = fork();
      if (! defined $fork) {
        msvalog('error', "could not fork\n");
      } else {
        if (! $fork) {
          msvalog('debug', "daemon has PID %d, parent has PID %d\n", $$, $pid);
          $self->{parent_pid} = $pid;
          # ppid is set in Net::Server::Fork's post_configure; we're
          # past post_configure by here, and we're about to change
          # process IDs before assuming the role of a forking server,
          # so we should set it properly:
          $server->{server}->{ppid} = $$;
          $ENV{MSVA_PARENT_PID} = $pid;
        } else {
          msvalog('verbose', "PID %d executing: \n", $$);
          for my $arg (@ARGV) {
            msvalog('verbose', " %s\n", $arg);
          }
          # untaint the environment for the parent process
          # see: https://labs.riseup.net/code/issues/2461
          foreach my $e (keys %ENV) {
            $ENV{$e} = untaint($ENV{$e});
          }
          my @args;
          foreach (@ARGV) {
            push @args, untaint($_);
          }
          # restore default SIGCHLD handling:
          $SIG{CHLD} = 'DEFAULT';
          $ENV{MONKEYSPHERE_VALIDATION_AGENT_SOCKET} = sprintf('http://127.0.0.1:%d', $self->port);
          exec(@args) or exit 111;
        }
      }
    } else {
      printf("MONKEYSPHERE_VALIDATION_AGENT_SOCKET=http://127.0.0.1:%d;\nexport MONKEYSPHERE_VALIDATION_AGENT_SOCKET;\n", $self->port);
      # FIXME: consider daemonizing here to behave more like
      # ssh-agent.  maybe avoid backgrounding by setting
      # MSVA_NO_BACKGROUND.
    };
    if (exists $ENV{MSVA_MONITOR_CHANGES} &&
        $ENV{MSVA_MONITOR_CHANGES} eq 'true') {
      $self->{updatemonitor} = Crypt::Monkeysphere::MSVA::Monitor::->new($logger);
    } else {
      msvalog('verbose', "Not monitoring for changes\n");
    }
  }

  sub extracerts {
    my $data = shift;

    return '500 not yet implemented', { };
  }

  1;
}
