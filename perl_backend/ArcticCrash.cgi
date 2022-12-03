#!/usr/bin/perl
use DBI;
use DBD::mysql;
use CGI;
use Time::Piece;
use Date::Calc qw( check_date );
use Net::CIDR;
use Digest::SHA qw(sha256_hex);
print "Content-type: text/html\n\n";

my $THEIP=$ENV{'REMOTE_ADDR'};


#my $THEDATE = DateTime->now->datetime;
my $THEDATE = localtime->strftime('%Y-%m-%d %H:%M:%S');



if($THEIP !~ /^[0-9a-f\x3a\x2e]{7,45}$/)
{
        print "YOU FAIL IP BAD";
        die;
}














my $inputs=new CGI;

my $myst=$inputs->param('myst');

my $myversion=$inputs->param('version');
 if($myversion !~ /^\d{8}[a-z]$/ )
	 {
		 print "FAIL VER";
		 die;
	 }


my $THEUA=$ENV{'HTTP_USER_AGENT'};

        my $COMP="";
        my $USER="";
        if( $THEUA =~ /^([a-zA-Z0-9\x2d]{1,31}):([a-zA-Z0-9\x2d\x20\x2e\x5f\x5b\x5d]{1,31})$/ )
        {

                $COMP=lc($1);
                $USER=lc($2);
                                 my $COMPANDDATE=$COMP . $USER . $myst;
                my $THEHASH=sha256_hex($COMPANDDATE);
                if($THEHASH !~ /^[a-f0-9]{64}$/ )
                {
                        print "FAIL HASH";
                        die;
                }
                my $dsn = "dbi:mysql:seceng:localhost:3306";
                my $dbh = DBI->connect($dsn, 'root', 'jsT01byi1?qrLm2!', { RaiseError => 1 });

                my $query=" INSERT INTO crashops (hash, thedate, compname,username,ip,myst,myversion) VALUES (?, ?, ?, ?, ?, ?, ?)  ON DUPLICATE KEY UPDATE `thedate`=values(`thedate`),  `compname`=values(`compname`),`username`=values(`username`),`ip`=values(`ip`), `myst`=values(`myst`), `myversion`=values(`myversion`);";

                my $query_handle = $dbh->prepare($query);


                $query_handle->execute($THEHASH,$THEDATE,$COMP,$USER,$THEIP,$myst,$myversion);


                $dbh->disconnect();



                }


