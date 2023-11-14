use Test2::V0;
my $openssl = `openssl version`;
like ($openssl, qr/openssl/i, "Openssl found");
diag($openssl);

done_testing;
