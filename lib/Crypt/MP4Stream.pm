package Crypt::MP4Stream;

require 5.004;
use strict;
use warnings;
use vars qw($VERSION);
$VERSION = '0.02';

use Crypt::Rijndael;
use Digest::MD5 qw(md5);

my ( $AtomDRMS, $AtomMP4A, $AtomSINF, $AtomUSER, $AtomKEY, 
     $AtomIVIV, $AtomNAME, $AtomPRIV, $AtomSTSZ, $AtomMDAT ) =
   ( "drms",    "mp4a",    "sinf",    "user",    "key ", 
     "iviv",    "name",    "priv",    "stsz",    "mdat"    );

sub new {
    my($class, %args) = @_;
	my $self = {};
	bless($self, $class);
    foreach my $k (qw( strHome sPfix dirSep )) 
      { $self->{$k} = $args{$k} if $args{$k} }
    unless($self->{strHome}) {
        no warnings;
        require Win32::TieRegistry;
        $self->{strHome} =
           $Win32::TieRegistry::Registry->
             {"HKEY_CURRENT_USER\\Volatile Environment\\\\APPDATA"} ||
               die "Cannot get the APPDATA file directory.";
    }
    $self->{sPfix} = ($^O =~ /Unix|linux/i) ? '.' : '' unless $self->{sPfix};
    $self->{dirSep} = '/' unless $self->{dirSep};
    return $self;
}

sub GetAtomPos {
    my($self, $atom) = @_;
    my $idx = index($self->{sbuffer}, substr($atom, 0, 4));
    if($idx >= 0) { return $idx } else { die "Atom $atom not found." } 
}

sub GetAtomSize {
    my($self, $pos) = @_;
    return unpack( 'N', substr($self->{sbuffer}, $pos - 4, 4) );
}    

sub GetAtomData {
    my($self, $pos, $bNetToHost) = @_;
    my $buf = substr($self->{sbuffer}, $pos + 4, $self->GetAtomSize($pos) - 8);
    return ($bNetToHost) ? pack('L*', unpack 'N*', $buf) : $buf; 
}

sub Decrypt {
    my($self, $cipherText, $offset, $count, $key, $iv) = @_;
    my $len = int($count / 16) * 16;
    my $alg = new Crypt::Rijndael($key, Crypt::Rijndael::MODE_CBC);
    $alg->set_iv($iv);
    substr( $$cipherText, $offset, $len, 
      $alg->decrypt(substr($$cipherText, $offset, $len)) );
}

sub GetUserKey {
    my($self, $userID, $keyID) = @_;
    my ($userKey, $strFile, $fh);
    $strFile = sprintf("%s%s%sdrms%s%08X.%03d", $self->{strHome}, $self->{dirSep}, 
      $self->{sPfix}, $self->{dirSep}, $userID, $keyID);
    open($fh, '<', $strFile) or die "Cannot open file $strFile: $!";
    binmode $fh;
    read($fh, $userKey, -s $strFile) or die "Cannot read user keyfile: $!";
    return $userKey;
}

sub GetSampleTable {
    my($self) = @_;
    my $adSTSZ = $self->GetAtomData($self->GetAtomPos($AtomSTSZ), 1);
    my $sampleCount = unpack('L', substr($adSTSZ, 8, 4));
    my @samples;
    for(my $i = 0; $i < $sampleCount; $i++) {
        my $s = unpack( 'L', substr($adSTSZ, 12 + ($i * 4), 4) );
        push @samples, $s;
    }
    $self->{sampleTable} = \@samples;
}

sub DeDRMS {
    my ($self, $infile, $outfile) = @_;
    my($iv, $key, $infh, $outfh);
    open($infh, '<', $infile) or die "Cannot read $infile: $!";
    binmode $infh;
    read($infh, $self->{sbuffer}, -s $infile);
    close $infh;
    my $apDRMS = $self->GetAtomPos($AtomDRMS);
    my $apSINF = $self->GetAtomPos($AtomSINF);
    my $apMDAT = $self->GetAtomPos($AtomMDAT);
    $self->GetSampleTable();
    my $adUSER = $self->GetAtomData( $self->GetAtomPos($AtomUSER), 1 );
    my $adKEY  = $self->GetAtomData( $self->GetAtomPos($AtomKEY ), 1 );
    my $adIVIV = $self->GetAtomData( $self->GetAtomPos($AtomIVIV), 0 );
    my $adNAME = $self->GetAtomData( $self->GetAtomPos($AtomNAME), 0 );
    my $adPRIV = $self->GetAtomData( $self->GetAtomPos($AtomPRIV), 0 );
    my $userID  = unpack('L', $adUSER);
    my $keyID   = unpack('L', $adKEY );
    my $strNAME = unpack('a', $adNAME);
    my $userKey = $self->GetUserKey($userID, $keyID);
    my $name_len = index($adNAME, "\0");
    my $md5Hash = new Digest::MD5;
    $md5Hash->add( substr($adNAME, 0, index($adNAME, "\0")), $adIVIV );
    $self->Decrypt(\$adPRIV, 0, length($adPRIV), $userKey, $md5Hash->digest);
    unless($adPRIV =~ /^itun/) { die "Decryption of 'priv' atom failed." }
    $key = substr($adPRIV, 24, 16);
    $iv = substr($adPRIV, 48, 16);
    for(my $i = 0, my $posit = $apMDAT + 4; $i < scalar @{$self->{sampleTable}};
                 $posit += $self->{sampleTable}->[$i], $i++) {
print "i is $i, posit $posit, size " . $self->{sampleTable}->[$i] . " \n";
        $self->Decrypt(\$self->{sbuffer}, $posit, 
          $self->{sampleTable}->[$i], $key, $iv);
    }
    substr($self->{sbuffer}, $apDRMS, length($AtomMP4A), $AtomMP4A);
    substr($self->{sbuffer}, $apSINF, length($AtomSINF), uc $AtomSINF);
    open($outfh, '>', $outfile) or die "Cannot write to $outfile: $!";
    binmode $outfh;
    print $outfh $self->{sbuffer};
}

=head1 NAME

Crypt::MP4Stream -- DRMS decoding of Apple style encrypted MP4 player files

=head1 DESCRIPTION
    
Perl port of the DeDRMS.cs program by Jon Lech Johansen

=head1 SYNOPSIS

use Crypt::MP4Stream;

my $mp4file = 'myfile';
my $outfile = 'mydecodedfile';
my $deDRMS = new Crypt::MP4Stream;
$deDRMS->DeDRMS($mp4file, $outfile);

=head1 METHODS

=over 4

=item B<new>

my $cs = new Crypt::MP4Stream;

my $cs_conparam = Crypt::MP4Stream->new(
  strHome => '/winroot/Documents and Settings/administrator/Application Data',
  sPfix => '.', 
  dirSep => '/'
);

Create the decoding object. strHome is optional, the name of the
directory containing the keyfile. sPfix is '.' for unix, otherwise generally 
nil. dirSep is the char that separates directories, generally / or \.

=item B<DeDRMS>

my $cs = new Crypt::MP4Stream;
$cs->DeDRMS('infilename', 'outfilename');

Decode infilename, write to outfilename. Reading slurps of an entire file,
so output can overwrite the same file without a problem, we hope. Backup first.

=back

=item B<NOTES>

    From Jon Lech Johansen:

        DeDRMS requires that you already have the user key file(s) for
        your files. The user key file(s) can be generated by playing
        your files with the VideoLAN Client [1][2].

        DeDRMS does not remove the UserID, name and email address.
        The purpose of DeDRMS is to enable Fair Use, not facilitate
        copyright infringement.

    [1] http://www.videolan.org/vlc/ [videolan.org]
    [2] http://wiki.videolan.org/tiki-read_article.php?art icleId=5 [videolan.org]


=head1 AUTHOR

Original C# version: Jon Lech Johansen <jon-vl@nanocrew.net>
Perl version: William Herrera (wherrera@skylightview.com).

=head1 SUPPORT

Questions, feature requests and bug reports should go to wherrera@skylightview.com

=head1 COPYRIGHT

 /*****************************************************************************
 * DeDRMS.cs: DeDRMS 0.1
 *****************************************************************************
 * Copyright (C) 2004 Jon Lech Johansen <jon-vl@nanocrew.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111, USA.
 *****************************************************************************/

=over 4

Perl translation with portability modifications Copyright (C) 2004,
by William Herrera. Any and all of Perl code modifications of the original 
also are under GPL copyright.

This module is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself. 

=back

=cut

1;
