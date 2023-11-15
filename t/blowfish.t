use strict;
use warnings;
use Test2::V0;
use Crypt::OpenSSL::Blowfish;

my $cipher = Crypt::OpenSSL::Blowfish->new(pack("H*", "0123456789ABCDEF"));
isa_ok($cipher, 'Crypt::OpenSSL::Blowfish');

my $data = pack("H*", "0000000000000000");

my $out = $cipher->encrypt($data);
ok(uc(unpack("H16", $out)) eq "884659249A365457", "Successfully encrypted data");

$data = $cipher->decrypt($out);
ok(uc(unpack("H*", $data)) eq "0000000000000000", "Successfully decrypted data");

my $key = pack("C*", 0x30,0x31,0x32,0x33,0x30,0x31,0x32,0x33,0x30,0x31,0x32,0x33,0x30,0x31,0x32,0x33);
my $plaintext = pack("C*",0x41,0x42,0x43,0x44,0x41,0x42,0x43,0x44);
my $expected_enc = pack("C*", 0x95, 0xd4, 0x6b, 0x2f, 0x14, 0xe6, 0xe1, 0x6f);

$cipher = Crypt::OpenSSL::Blowfish->new($key, {});
isa_ok($cipher, 'Crypt::OpenSSL::Blowfish');

$out = $cipher->encrypt($plaintext);
ok(uc(unpack("H16", $out)) eq "95D46B2F14E6E16F", "Successfully encrypted data");
done_testing;
