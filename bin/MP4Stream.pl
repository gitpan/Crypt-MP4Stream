#!/usr/bin/perl 

use strict;
use warnings;
use Crypt::MP4Stream;

my $cs = Crypt::MP4Stream->new;

if(scalar @ARGV != 2) { die "Usage: perl progname infilename outfilename\n" }
$cs->DeDRMS($ARGV[0], $ARGV[1]);
exit;



