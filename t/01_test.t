# -*- perl -*-

# t/01_test.t - check module loading, etc

use Test::More tests => 2;

BEGIN { use_ok( 'Crypt::MP4Stream' ); }

my $object = new Crypt::MP4Stream;
isa_ok ($object, 'Crypt::MP4Stream');

