#!/usr/bin/perl -w

# CORBA/XML Xmedius fax server client
use strict;
use Socket qw(:DEFAULT :crlf);
use IO::Socket::IP qw(AF_INET);
use IO::Socket::SSL;
use File::Temp;
use Encode qw(from_to);

use constant {
	Request => 0,
	Reply => 1,
	Cancel => 2
};

use constant {
	SYNC_WITH_TARGET => 3
};

use constant {
	KeyAddr => 0
};

use constant {
	FT_GROUP_VERSION => 12,
	FT_REQUEST => 13,
	BI_DIR_IIOP => 5
};

use constant {
	TAG_ORB_TYPE => 0,
	TAG_CODE_SETS => 1,
	TAG_SSL_SEC_TRANS => 20,
};

use constant {
	TAG_INTERNET_IOP => 0
};

my $user = 'user';
my $pass = 'pass';
my $name = 'name';
my $phone = '1(555)555-5555';
my $email = 'email';
my $fax = '15555555555';
my $xml_gateway = 'xmediusfax.com';
my $xml_port = 7809;

sub create_giop_header {
	my ($srv, $payload, $type) = @_;
	my $msg = pack 'x12a*x!8a*', $srv, $payload;
	$msg = substr $msg, 12;
	return pack('a*nCCVa*', 'GIOP', 0x0102, 1, $type, length($msg), $msg);
}

sub create_v4_uuid {
	local *rand16 = sub { rand(65535) % 65536; };
	local *rand12 = sub { rand(4095) % 4096; };
	return pack('SSSSnnnn', rand16(), rand16(), rand16(), 0x4000|rand12(), 0x8000|rand12(), rand16(), rand16(), rand16());
}

sub uuid_to_string {
	my ($uuid) = @_;
	return sprintf('%08X-%04X-%04X-%04X-%08X%04X', unpack('LSSnNn', $uuid));
}

{
	package marshal;

	sub new {
		my $self = {};
		$self->{TYPE} = undef;
		$self->{PARAM} = [];
		bless($self);
		return $self;
	}

	sub m8 {
		my ($self, $char, $pre) = @_;
		if(defined($pre)) {$self->{TYPE} = 'C'.$self->{TYPE}; unshift @{$self->{PARAM}}, $char;}
		else {$self->{TYPE} .= 'C'; push @{$self->{PARAM}}, $char;}
	}

	sub m16 {
		my ($self, $short) = @_;
		$self->{TYPE} .= 'x!2v';
		push @{$self->{PARAM}}, $short;
	}

	sub m32 {
		my ($self, $long) = @_;
		$self->{TYPE} .= 'x!4V';
		push @{$self->{PARAM}}, $long;
	}

	sub mstr {
		my ($self, $string) = @_;
		$self->{TYPE} .= 'x!4Va*';
		push @{$self->{PARAM}}, (length($string), $string);
	}

	sub menc {
		my ($self, $enc) = @_;
		$enc->m8(1, 1);
		$self->mstr($enc->run);
	}

	sub raw {
		my ($self, $data) = @_;
		$self->{TYPE} .= 'a*';
		push @{$self->{PARAM}}, $data;
	}

	sub run {
		my ($self) = @_;
		return pack $self->{TYPE}, @{$self->{PARAM}};
	}
}

sub create_iop_service {
	my ($id, $enc, $orb, $count, $str) = @_;
	$orb->m32($id);
	if(defined($str)) {$orb->mstr($enc)}
	else {$orb->menc($enc)}
	$$count++;
}

sub marshal_IIOP {
	my ($ip, $port, $uuid) = @_;
	my $payload = marshal::new;
	$payload->mstr("IDL:interstarinc.com/Xm/InputStream:1.0\0");
	$payload->m32(1);	#iiop seq length
	$payload->m32(TAG_INTERNET_IOP);
	my $iiop = marshal::new;
	$iiop->m8(1);
	$iiop->m8(2);
	$iiop->mstr($ip);
	$iiop->m16($port-1);
	$iiop->mstr("\x14\x01\x0f\0RST\x4b\x77\xf1\x4b\x21\xc4\x01\0\0\0\0\0\x01\0\0\0\x01\0\0\0");
	$iiop->m32(4);	#iiop tagged components seq len
	$iiop->m32(TAG_ORB_TYPE);
	$iiop->mstr("\1\0\0\0\0OAT");	#menc
	$iiop->m32(TAG_CODE_SETS);
	{
		my $enc = marshal::new;
		$enc->m32(0x10001);
		$enc->m32(0);
		$enc->m32(0x10109);
		$enc->m32(0);
		$iiop->menc($enc);
	}
	$iiop->m32(TAG_SSL_SEC_TRANS);
	{
		my $enc = marshal::new;
		$enc->m16(0xa7);	# supported options
		$enc->m16(0x86);	# required options
		$enc->m16($port);
		$iiop->menc($enc);
	}
	$iiop->m32(0x1010001);	#tag unk
	{
		my $enc = marshal::new;
		$enc->mstr($uuid);
		$iiop->menc($enc);
	}
	$payload->menc($iiop);
	return $payload->run;
}

sub marshal_SubmitXmlFax {
	my $orb = marshal::new;
	my $ip = "192.168.0.1\0";
	my $port = 0x5000;
	my $uuid;
	$orb->m32(1);
	$orb->m8(SYNC_WITH_TARGET);
	$orb->m16(0);
	$orb->m16(0);
	$orb->mstr("\x14\x01\x0f\0NUP\0\0\0\x17\0\0\0\0\x01\0\0\0\0SinkServerPOA\0{E8711BA1-9CDE-4384-AE8C-681EAD1EDAAB}");
	$orb->mstr("SubmitXmlFax\0");
	{
		my $slist = marshal::new;
		my $service_count;
		create_iop_service(0x2eef, 'S-1-0-0', $slist, \$service_count, 1);
		{
			my $service = marshal::new;
			$service->m32('1');
			$service->mstr("en\0");
			create_iop_service(0x01010010, $service, $slist, \$service_count);
		}
		{
			my $service = marshal::new;
			$service->m8(1);
			$service->m8(2);
			$service->mstr("SendFaxDomainId\0");
			$service->raw("\\\0I\0n\0t\0");
			$service->m32(1);
			create_iop_service(FT_GROUP_VERSION, $service, $slist, \$service_count);
		}
		{
			use integer;
			my $service = marshal::new;
			$service->mstr("TAO_Client\0");
			$service->m32(0);
			my $ntime = (0x13814000 + ((time() + 60) * 1e7)) & 0xffffffff;
			$service->m32($ntime);  #0x01b21dd213814000
			$service->m32((0x80000000 & $ntime)?-1:0);
			create_iop_service(FT_REQUEST, $service, $slist, \$service_count);
		}
		{
			$uuid = uuid_to_string(create_v4_uuid())."\0";
			my $service = marshal::new;
			$service->mstr($uuid);
			create_iop_service(0x01010002, $service, $slist, \$service_count);
		}
		{
			my $service = marshal::new;
			$service->m32(1);	#bidir iiop seq length
			$service->mstr($ip);
			$service->m16($port);
			create_iop_service(BI_DIR_IIOP, $service, $slist, \$service_count);
		}
		$orb->m32($service_count);
		$orb->raw($slist->run);
	}
	my $payload = marshal::new;
	$payload->raw(marshal_IIOP($ip, $port, $uuid));
	$payload->m32(1);
	$payload->mstr("\xff\xfe"."a\0t\0t\0a\0c\0h\0m\0e\0n\0t\0.\0t\0i\0f\0f\0");
	$payload->raw(marshal_IIOP($ip, $port, $uuid));
	return create_giop_header($orb->run, $payload->run, Request);
}

sub marshal_ContentType_reply {
	my $reply = marshal::new;
	my ($id) = @_;
	$reply->m32($id);
	$reply->m32(0);
	$reply->m32(0);
	return create_giop_header($reply->run, "\x08\0\0\0\xff\xfex\0m\0l\0", Reply);
}

sub marshal_empty_reply {
	my $reply = marshal::new;
	my ($id) = @_;
	$reply->m32($id);
	$reply->m32(0);
	$reply->m32(0);
	return create_giop_header($reply->run, '', Reply);
}

sub marshal_Read_reply {
	my $reply = marshal::new;
	my ($payload, $id) = @_;
	$reply->m32($id);
	$reply->m32(0);
	$reply->m32(0);
	return create_giop_header($reply->run, pack('Va*', length($payload), $payload), Reply);
} 

sub giop_check_reply {
	my ($socket) = @_;
	my ($data, $id);
	read $socket, $data, 8192;
	my $size = length($data);
	my ($op, $magic, $type, $status, $len, @service);
	($magic, $type, $id, $status, $data) = unpack 'a4 xx x c x4 V V a*', $data;
	if($magic ne 'GIOP') { return; }
	if($type == Reply) {
		if($status) { return; }
		$op = '';
	} elsif($type == Request) {
		my $key;
	       	($key, $op, $data) = unpack 'x4V/a*x!4V/a*x!4a*', $data;
	}
	($len, $data) = unpack 'Va*', $data;
	for(my $i = 0; $i < $len; $i++) {
		my ($s, $st);
		($st, $s, $data) = unpack 'VV/a*x!4a*', $data;
		push @service, ($st, $s);
	}
	if(length($data)) {
		$size = ($size - length($data)) % 8;
		$data = unpack "x$size a*", $data;
	}
	return ($type, $data, $op, $id);
}

sub check_req_reply {
	my ($ex_op, $socket) = @_;
	(my ($type, $payload, $op, $id) = giop_check_reply($socket)) || die 'Bad reply or exception';
	if($op ne $ex_op."\0") { die "Expected $ex_op got $op request"; }
	if(length($payload)) { return $id, $payload; }
	return $id;
}

if($#ARGV < 1) { die 'Insufficient arguments' };
my $input = mktemp('/tmp/tempXXXX');
my $output = mktemp('/tmp/tempXXXX');
system('gs', '-q', '-sDEVICE=tiffg3', '-dNOPAUSE', '-dBATCH', '-dFillOrder=2', "-sOutputFile=$input", $ARGV[0]) == 0 || die "Ghostscript failure $?";
system('tiffcp', '-cg3:1d', $input, $output) == 0 || die 'tiffcp failure';
unlink $input;
open ATTACH, "<$output";

shift @ARGV;
my ($number, $subject, $comment) = @ARGV;

if(defined($comment) && ($comment ne '')) { $comment = "\n    <comment>$comment</comment>"; }
else { $comment = '' };

if(!defined($subject) || ($subject eq '')) { $subject = 'fax'; }

my $socket = IO::Socket::SSL->new(PeerHost=>$xml_gateway, PeerPort=>$xml_port, SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE) || die "Connection failure: $! $SSL_ERROR";
print $socket marshal_SubmitXmlFax;

my ($data, $id, $size);

$id = check_req_reply('ContentType', $socket);
print $socket marshal_ContentType_reply($id);

do {
	($id, $size) = check_req_reply('Read', $socket);
	$size = unpack 'x4V', $size;
	read ATTACH, $data, $size;
	print $socket marshal_Read_reply($data, $id);
} while(!eof(ATTACH));
close ATTACH;
unlink $output;

($data = <<EOF) =~ s/$CR?$LF/$CRLF/g;
<?xml version="1.0" encoding="UTF-8" standalone="no" ?>
<FaxJobs>

  <FaxData>
    <recipient-list>
      <Recipient>
        <fax>$number</fax>
      </Recipient>
    </recipient-list>
    <processing-options>
      <user>$user</user>
      <password>$pass</password>
      <delete-input-files>yes</delete-input-files>
    </processing-options>
    <sender-info>
      <first-name>$name</first-name>
      <phone>$phone</phone>
      <fax>$fax</fax>
      <email>$email</email>
      <billing-code>$fax</billing-code>
    </sender-info>
    <subject>$subject</subject>$comment
    <transmission-settings>
      <notification-address>no_reply\@fax.com</notification-address>
      <gateway>smtp</gateway>
    </transmission-settings>
    <coversheet>
      <type>default</type>
    </coversheet>
    <attachment-list>
      <document>
        <file-name>attachment.tiff</file-name>
      </document>
    </attachment-list>
  </FaxData>

</FaxJobs>
EOF

$id = check_req_reply('Close', $socket);
print $socket marshal_empty_reply($id);

($id, $size) = check_req_reply('Read', $socket);
print $socket marshal_Read_reply($data, $id);

$id = check_req_reply('Close', $socket);
print $socket marshal_empty_reply($id);

my ($payload, $type);
(($type, $payload) = giop_check_reply($socket)) || die 'Bad reply or exception';
if($type != Reply) { die 'Missing expected reply'; }

my($ret, $msg, $err);
($ret, $payload) = unpack 'Va*', $payload;
if($ret) {
	($msg, $err) = unpack 'V/a*x2V/a*', $payload;
} else {
	($msg, $err) = unpack 'V/a*V/a*', $payload;
}
print STDERR "$msg\n$err\n";
from_to($msg, 'UTF-16le', 'UTF-8');
from_to($err, 'UTF-16le', 'UTF-8');
print "$msg\n$err\n";
exit $ret;
