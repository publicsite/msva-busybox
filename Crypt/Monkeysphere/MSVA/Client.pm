#----------------------------------------------------------------------
# Monkeysphere Validation Agent, Perl version
# Marginal User Interface for reasonable prompting
# Copyright © 2010 Daniel Kahn Gillmor <dkg@fifthhorseman.net>,
#                  Matthew James Goins <mjgoins@openflows.com>,
#                  Jameson Graef Rollins <jrollins@finestructure.net>,
#                  Elliot Winard <enw@caveteen.com>
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
#
#----------------------------------------------------------------------

{ package Crypt::Monkeysphere::MSVA::Client;

  use strict;
  use warnings;
  use JSON;
  use Crypt::Monkeysphere::Logger;
  use LWP::UserAgent;
  use HTTP::Request;
  use Module::Load::Conditional;

  sub log {
    my $self = shift;
    $self->{logger}->log(@_);
  }

  sub agent_info {
    my $self = shift;
    my $requesturl = $self->{socket} . '/';
    my $request = HTTP::Request->new('GET', $requesturl);
    $self->log('debug', "Contacting MSVA at %s\n", $requesturl);
    my $response = $self->{ua}->request($request);
    my $status = $response->status_line;
    my $ret;
    if ($status eq '200 OK') {
      $ret = from_json($response->content);
    }
    return $status, $ret;
  }

  sub query_agent {
    my $self = shift;
    my $context = shift;
    my $peer = shift;
    my $peertype = shift;
    my $pkctype = shift;
    my $pkcdata = shift;
    my $keyserverpolicy = shift;

    my $apd = $self->create_apd($context, $peer, $peertype, $pkctype, $pkcdata, $keyserverpolicy);

    my $apdjson = to_json($apd);

    my $headers = HTTP::Headers->new(
	'Content-Type' => 'application/json',
	'Content-Length' => length($apdjson),
	'Connection' => 'close',
	'Accept' => 'application/json',
	);

    my $requesturl = $self->{socket} . '/reviewcert';

    my $request = HTTP::Request->new(
	'POST',
	$requesturl,
	$headers,
	$apdjson,
	);

    $self->log('debug', "Contacting MSVA at %s\n", $requesturl);
    my $response = $self->{ua}->request($request);

    my $status = $response->status_line;
    my $ret;
    if ($status eq '200 OK') {
      $ret = from_json($response->content);
    }

    return $status, $ret;
  }

  sub create_apd {
    my $self = shift;
    my $context = shift;
    my $peer = shift;
    my $peertype = shift;
    my $pkctype = shift;
    my $pkcdata = shift;
    my $keyserverpolicy = shift;

    $self->log('debug', "context: %s\n", $context);
    $self->log('debug', "peer: %s\n", $peer);
    $self->log('debug', "pkctype: %s\n", $pkctype);

    my $transformed_data;
    if ($pkctype eq 'x509der') {
      # remap raw der data into numeric array
      $transformed_data = [map(ord, split(//,$pkcdata))];
    } else {
      $transformed_data = $pkcdata;
    }

    my $ret = {
               context => $context,
               peer => { name => $peer},
               pkc => {
                       type => $pkctype,
                       data => $transformed_data,
                      },
              };
    $ret->{peer}->{type} = $peertype
      if (defined $peertype);
    $ret->{keyserverpolicy} = $keyserverpolicy
      if (defined $keyserverpolicy);

    return $ret;
  };


  sub new {
    my $class = shift;
    my %args = @_;
    my $self = {};

    $self->{logger} = Crypt::Monkeysphere::Logger->new($args{log_level});
    $self->{socket} = $args{socket};
    $self->{socket} = 'http://127.0.0.1:8901'
      if (! defined $self->{socket} or $self->{socket} eq '');

    # create the user agent
    $self->{ua} = LWP::UserAgent->new;

    bless ($self,$class);
    return $self;
  }

  1;
}
