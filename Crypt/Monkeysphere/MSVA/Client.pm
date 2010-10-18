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

  BEGIN {
    use Exporter   ();
    our (@EXPORT_OK,@ISA);
    @ISA = qw(Exporter);
    @EXPORT_OK = qw( &create_apd );
  }
  our @EXPORT_OK;

  use JSON;
  use Crypt::Monkeysphere::MSVA qw( msvalog );

  sub query_agent {
    use LWP::UserAgent;
    use HTTP::Request;

    my $self = shift;
    my $context = shift;
    my $peer = shift;
    my $pkctype = shift;
    my $pkcdata = shift;
    my $msvasocket = shift;

    if (! defined $msvasocket or $msvasocket eq '') {
      $msvasocket = 'http://localhost:8901';
    }

    my $apd = create_apd($context, $peer, $pkctype, $pkcdata);

    my $apdjson = to_json($apd);

    # create the user agent
    my $ua = LWP::UserAgent->new;

    my $headers = HTTP::Headers->new(
	'Content-Type' => 'application/json',
	'Content-Length' => length($apdjson),
	'Connection' => 'close',
	'Accept' => 'application/json',
	);

    my $requesturl = $msvasocket . '/reviewcert';

    my $request = HTTP::Request->new(
	'POST',
	$requesturl,
	$headers,
	$apdjson,
	);

    msvalog('debug', "Contacting MSVA at %s\n", $requesturl);
    my $response = $ua->request($request);

    my $status = $response->status_line;
    my $ret;
    if ($status eq '200 OK') {
      $ret = from_json($response->content);
    }

    return $status, $ret;
  }

  sub create_apd {
    my $context = shift;
    my $peer = shift;
    my $pkctype = shift;
    my $pkcdata = shift;

    msvalog('debug', "context: %s\n", $context);
    msvalog('debug', "peer: %s\n", $peer);
    msvalog('debug', "pkctype: %s\n", $pkctype);


    if ($pkctype eq 'x509der') {
      my $cert = Crypt::X509->new(cert => $pkcdata);
      if ($cert->error) {
	die;
      };
      msvalog('info', "x509der certificate loaded.\n");
      msvalog('verbose', "cert subject: %s\n", $cert->subject_cn());
      msvalog('verbose', "cert issuer: %s\n", $cert->issuer_cn());
      msvalog('verbose', "cert pubkey algo: %s\n", $cert->PubKeyAlg());
      msvalog('verbose', "cert pubkey: %s\n", unpack('H*', $cert->pubkey()));
    } else {
	msvalog('error', "unknown pkc type '%s'.\n", $pkctype);
    };

    return {
            context => $context,
            peer => $peer,
            pkc => {
                    type => $pkctype,
                    # remap raw pkc data into numeric array
                    data => [map(ord, split(//,$pkcdata))],
                   },
           };
  }

  1;
}
