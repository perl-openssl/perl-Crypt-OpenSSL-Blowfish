print "1..3\n";

use Crypt::OpenSSL::Blowfish;

my $cipher = Crypt::OpenSSL::Blowfish->new(pack("H*", "0123456789ABCDEF"));
print "not " unless defined $cipher;
print "ok 1\n";

my $data = pack("H*", "0000000000000000");

my $out = $cipher->encrypt($data);
print "not " if(uc(unpack("H16", $out)) ne "884659249A365457");
print "ok 2\n";

$data = $cipher->decrypt($out);
print "not " if(uc(unpack("H*", $data)) ne "0000000000000000");
print "ok 3\n";

my $key = pack("C*", 0x30,0x31,0x32,0x33,0x30,0x31,0x32,0x33,0x30,0x31,0x32,0x33,0x30,0x31,0x32,0x33);
my $plaintext = pack("C*",0x41,0x42,0x43,0x44,0x41,0x42,0x43,0x44);
my $expected_enc = pack("C*", 0x95, 0xd4, 0x6b, 0x2f, 0x14, 0xe6, 0xe1, 0x6f);

my $cipher = Crypt::OpenSSL::Blowfish->new($key, {});
print "not " unless defined $cipher;
print "ok 4\n";

my $out = $cipher->encrypt($plaintext);
print "not " if(uc(unpack("H16", $out)) ne "95D46B2F14E6E16F");
print "ok 5\n";
