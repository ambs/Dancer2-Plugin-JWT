use strict;
use warnings;

use Test::More import => ['!pass'];
#use Plack::Test;
use  Test::WWW::Mechanize::PSGI;
use HTTP::Request::Common;
use JSON::WebToken;


#plan tests => 5;

{
	use Dancer2;
	use Dancer2::Plugin::JWT;

	set log => 'debug';

	set plugins => { JWT => { secret => 'secret'}};

	hook 'jwt_exception' => sub { 
		use Data::Dumper;
		die Dumper(\@_);
	};

	get '/' => sub {
		"OK";
	}

}

my $app = __PACKAGE__->to_app;
is (ref $app, 'CODE', 'Got the test app');

my $mech =  Test::WWW::Mechanize::PSGI -> new ( app => $app );

my $authorization = 'FDAHFKDAHFKDFKAGFKAHKJAHFKgdhfdhfajkdgdsad';
$mech->add_header("Authorization" => $authorization);
$mech->get_ok("/");



done_testing();