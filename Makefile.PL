use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME         => 'Crypt::MP4Stream',
    VERSION_FROM => 'lib/Crypt/MP4Stream.pm', # finds $VERSION
    AUTHOR       => 'William Hererra (whererra@skylightview.com)',
    ABSTRACT     => 'Perl version of DeDRMS.',
    PREREQ_PM    => { Crypt::Rijndael => 0, Digest::MD5 => 0, Test::More => 0 },
);
