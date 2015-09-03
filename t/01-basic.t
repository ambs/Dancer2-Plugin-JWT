use strict;
use warnings;

use Test::More import => ['!pass'];
use Plack::Test;
use HTTP::Request::Common;
use JSON::WebToken;


plan tests => 6;

{
	use Dancer2;
	use Dancer2::Plugin::JWT;

	set plugins => { JWT => { secret => 'secret'}};

	get '/defined/jwt' => sub {
		defined(jwt) ? "DEFINED" : "UNDEFINED";
	};

	get '/define/jwt' => sub {
		jwt { my => 'data' };
		"OK";
	}
}

my $app = __PACKAGE__->to_app;
is (ref $app, 'CODE', 'Got the test app');

test_psgi $app, sub {
	my $cb = shift;

	is $cb->(GET '/defined/jwt')->content, "UNDEFINED", "by default it is undef";

	my $ans = $cb->(GET '/define/jwt');

	is $ans->content, "OK", "No exceptions on defining jwt";
	my $authorization = $ans->header("Authorization");
	ok($authorization, "We have something");
	my $x = decode_jwt($authorization, "secret");
	is_deeply($x, {my => 'data'}, "Got correct data back");

	is $cb->(HTTP::Request->new(GET => '/defined/jwt',
		HTTP::Headers->new(Authorization => $authorization)))->content, "DEFINED", "we got something";
};