# -*- perl -*-
use Test::More;

use strict;
use warnings;

use Crypt::Monkeysphere::Keytrans;
use MIME::Base64;
use File::Temp qw(tempdir);

plan tests =>1;

# this is dkg's ssh pubkey:
my $exp = Math::BigInt->new('0x10001');
my $mod = Math::BigInt->new('0xBC358E82F23E5660301E5DBB370B42FD3EBAFE700B8E82F928798C0BA55DE5F96B984C2EA6D0BA67699E7777DA3FAF9CEA29A2030B81761603F8714E76AA2905A8DA2BAAFB19DEC147032E57585B6F4B3B1A4531942A1B3E635E1328AA50D98FA8CA7B2E64537CC26E0DE94F197A97854FE7C3B4F04F4FD96BCE8A311B2767CB0DB6E3A2D1871EE3B6B6309C0322EFCF9D3D30533575509B9A071C0C03A4B9C480D7B7E628BBF2A6714A54B5AA77F05CA7CDADD45A7C2C070DEB51F15122660B15919D7919A299E38D6BBD762C2E4BB306A0B506C7917DA3C0619E6116ADE290FDB35BA24D279212F24F097D1F70326B9207C27E536A29FEAA022504371CC01B');
my $sshpubkey = 'AAAAB3NzaC1yc2EAAAADAQABAAABAQC8NY6C8j5WYDAeXbs3C0L9Prr+cAuOgvkoeYwLpV3l+WuYTC6m0LpnaZ53d9o/r5zqKaIDC4F2FgP4cU52qikFqNorqvsZ3sFHAy5XWFtvSzsaRTGUKhs+Y14TKKpQ2Y+oynsuZFN8wm4N6U8ZepeFT+fDtPBPT9lrzooxGydnyw2246LRhx7jtrYwnAMi78+dPTBTNXVQm5oHHAwDpLnEgNe35ii78qZxSlS1qnfwXKfNrdRafCwHDetR8VEiZgsVkZ15GaKZ441rvXYsLkuzBqC1BseRfaPAYZ5hFq3ikP2zW6JNJ5IS8k8JfR9wMmuSB8J+U2op/qoCJQQ3HMAb';

my $out = encode_base64(Crypt::Monkeysphere::Keytrans::openssh_rsa_pubkey_pack($mod, $exp), '');

is($out, $sshpubkey);

