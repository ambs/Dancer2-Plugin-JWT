use strict;
use warnings;
package Dancer2::Plugin::JWT;
# ABSTRACT: JSON Web Token made simple for Dancer2

use Dancer2::Plugin;
use JSON::WebToken;
use Try::Tiny;
use URI;
use URI::QueryParam;

register_hook qw(jwt_exception);

my $config;

sub _get_secret {
	die "JWT cannot be used without a secret!" unless exists $config->{secret};
	return $config->{secret};
}


register jwt => sub {
	my $dsl = shift;
	my @args = @_;

	$config = plugin_setting();

	if (@args) {
		$dsl->app->request->var(jwt => $args[0]);
	}
	else {
		return $dsl->app->request->var('jwt') || undef;
	}
};

on_plugin_import {
	my $dsl = shift;

	$dsl->app->add_hook(
		Dancer2::Core::Hook->new(
			name => 'before',
			code => sub {
				my $encoded = $dsl->app->request->headers->authorization;

				if (!$encoded && $dsl->app->request->param('_jwt')) {
					$encoded = $dsl->app->request->param('_jwt');
				}

				if ($encoded) {
					my $decoded;
					try {
						$decoded = decode_jwt($encoded, _get_secret());
					} catch {
						execute_hook 'jwt_exception' => $_;
					};
					$dsl->app->request->var('jwt', $decoded);
				}
			}
		)
	);

	$dsl->app->add_hook(
		Dancer2::Core::Hook->new(
			name => 'after',
			code => sub {
				my $response = shift;
                my $decoded = $dsl->app->request->var('jwt');
                if (defined($decoded)) {
					my $encoded = encode_jwt($decoded, _get_secret());
					$response->headers->authorization($encoded);
					if ($response->status =~ /^3/) {
	                	my $u = URI->new( $response->header("Location") );
		                $u->query_param( _jwt => $encoded);
	     	            $response->header(Location => $u);
     	     	   }
				}
			}
		)
	);
};



register_plugin;

1;
