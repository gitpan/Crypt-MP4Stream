package Crypt::MP4Stream;

require 5.004;
use strict;
use warnings;
use vars qw($VERSION);
$VERSION = '0.01_02';

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
    $self->{alg} = 0;
    return $self;
}

sub GetAtomPos {
    my($self, $atom) = @_;
    my $idx = index($self->{sbuffer}, substr($atom, 0, 4));
    if($idx >= 0) { return $idx } else { die "Atom $atom not found." } 
}

sub GetAtomSize {
    my($self, $pos) = @_;
    return unpack('N', substr($self->{sbuffer}, $pos - 4, 4));
}    

sub GetAtomData {
    my($self, $pos, $bNetToHost) = @_;
    return unpack $bNetToHost ? 'N' : 'L', 
      substr($self->{sbuffer}, $pos + 4, GetAtomSize($pos) - 8);
}

sub Decrypt {
    my($self, $cipherText, $offset, $count, $key, $iv) = @_;
    my $len = ($count / 16) * 16;
    unless($self->{alg}) {
        $self->{alg} = new Crypt::Rijndael($key, Crypt::Rijndael::MODE_CBC);
    }
    $self->{alg}->set_iv($iv);
    substr($cipherText, $offset, $len) = 
      $self->{alg}->decrypt(substr($cipherText, $offset, $len));
}

sub GetUserKey {
    my($self, $userID, $keyID) = @_;
    my ($userKey, $strFile, $fh);
    $strFile = sprintf("%s%s%s%s%8s.%5d", $self->{strHome}, $self->{dirSep}, 
      $self->{sPfix}, $self->{dirSep}, $userID, $keyID);
    open($fh, '<', $strFile) or die "Cannot open file $strFile: $!";
    binmode $fh;
    read($fh, $userKey, -s $strFile);
    close $fh;
    return $userKey;
}

sub GetSampleTable {
    my($self) = @_;
    my $adSTSZ = $self->GetAtomData($self->GetAtomPos($AtomSTSZ), 1);
    my $sampleCount = unpack('N', substr($adSTSZ, 8, 4));
    for(my $i = 0; $i < $sampleCount; $i++) {
        $self->{sampleTable}->[$i] = 
          unpack('N', substr($adSTSZ, 12 + ($i * 4), 4));
    }
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
    my $adUSER = $self->GetAtomData( GetAtomPos($AtomUSER), 1 );
    my $adKEY  = $self->GetAtomData( GetAtomPos($AtomKEY ), 1 );
    my $adIVIV = $self->GetAtomData( GetAtomPos($AtomIVIV), 0 );
    my $adNAME = $self->GetAtomData( GetAtomPos($AtomNAME), 0 );
    my $adPRIV = $self->GetAtomData( GetAtomPos($AtomPRIV), 0 );
    my $userID  = unpack('S', $adUSER);
    my $keyID   = unpack('S', $adKEY );
    my $strNAME = unpack('a', $adNAME);
    my $userKey = GetUserKey($userID, $keyID);
    my $md5Hash = md5(substr($adNAME, 0, index($adNAME, '\x0')), $adIVIV);
    $self->Decrypt($adPRIV, 0, length($adPRIV), $userKey, $md5Hash);
    $self->{alg} = 0;
    unless($adPRIV =~ /^itun/) { die "Decryption of 'priv' atom failed" }
    $key = substr($adPRIV, 24, 16);
    $iv = substr($adPRIV, 46, 16);
    for(my $i = 0, my $pos = $apMDAT + 4; $i < length($self->{sampleTable});
      $pos += $self->{sampleTable}[$i], $i++) {
        $self->Decrypt($self->{sbuffer}, $pos, 
          $self->{sampleTable}[$i], $key, $iv);
    }
    substr($self->{sbuffer}, $apDRMS, length($AtomMP4A), $AtomMP4A);
    substr($self->{sbuffer}, $apSINF, length($AtomSINF), uc $AtomSINF);
    open($outfh, '>', $outfile) or die "Cannot write to $outfile: $!";
    binmode $outfh;
    print $outfh $self->{sbuffer};
    close $outfh;
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
