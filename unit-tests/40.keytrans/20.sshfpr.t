# -*- perl -*-
use Test::More;

use Crypt::Monkeysphere::Keytrans qw(GnuPGKey_to_OpenSSH_fpr);
use GnuPG::Interface;
use File::Temp qw(tempdir);

plan tests => 1;

my $tempdir = tempdir("unitXXXXX", CLEANUP => 1);
my $gnupg = new GnuPG::Interface();
$gnupg->options->hash_init(homedir=>$tempdir);

my $openpgpdata = "
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.11 (GNU/Linux)

mI0ETa5YiwEEALJhsHgLEokvKM+d1oAAy+oaDywLWsbqzuCCqu5h9Hu7MYxeGmTA
tg8fXatgXEBUUe+e1i1aF94kTqcqcS5M+71ce2yHNyxl7U0pGVMOPiFiRVKK8x/7
wE2LTaPHhskc8kkKrxoJMbXmn0Oq5wn8xLkidIsVE+AyQ+HbD9C7UAnhABEBAAG0
NXRlc3Qga2V5IChETyBOT1QgVVNFISkgPHRlc3RAZXhhbXBsZS5uZXQ+IChJTlNF
Q1VSRSEpiL4EEwECACgFAk2uWIsCGwMFCQABUYAGCwkIBwMCBhUIAgkKCwQWAgMB
Ah4BAheAAAoJEEi/A6Yee54PGcID/iL1tRDgFnNaNNdEpChbjrWcoCIQOIw2VvYH
UJY3oiKPWv/f8NMOylFLBG9pjDUd96wkimUvAKccPDwuhwMQq+KTcDPZXm8AeeUX
IMHmPE33qqvifV9dFGlIGa4a3tmGjJvjhKmNSJGJWG9wRK3C2BrJdQVF9sk2FHXd
1nlddMRV
=MxOB
-----END PGP PUBLIC KEY BLOCK-----
";


my $sshdata = "e6:b3:db:be:c6:5d:f7:65:f2:bb:6e:06:69:36:f5:e5";


my $input = IO::Handle->new();
my $output = IO::Handle->new();
my $handles = GnuPG::Handles->new(stdin => $input,
                                  stdout => $output,
                                  stderr => $output);

my $pid = $gnupg->import_keys(handles => $handles);

$input->write($openpgpdata);
$input->close();
waitpid($pid, 0);

my @keys = $gnupg->get_public_keys();

foreach $key (@keys) {
  my $output = GnuPGKey_to_OpenSSH_fpr($key);
  is($sshdata, $output);
}
