use strict;
use warnings;
package Dancer2::Plugin::JWT;
# ABSTRACT: JSON Web Token made simple for Dancer2

use Dancer2::Plugin;
use JSON::WebToken;
use Try::Tiny;
use URI;
use URI::QueryParam;

#register_hook qw(jwt_invalid_signature);

sub _get_secret {
	my $settings = plugin_setting();
	die "JWT cannot be used without a secret!" unless exists $settings->{secret};
	return $settings->{secret};
}


register jwt => sub {
	my $dsl = shift;
	my @args = @_;

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
				my $encoded = $dsl->app->request->header('Authorization');

				if ($encoded) {
					my $decoded;
					try {
						$decoded = decode_jwt($encoded, _get_secret());
					} catch {
						die "Catched something\n";
						# ...
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

					if ($response->status =~ /^2/) {
						my $encoded = encode_jwt($decoded, _get_secret());
						$response->header("Authorization", $encoded);
		     	   }
				}
				# if ($response->status =~ /^3/) {
	   #              my $u = URI->new( $response->header("Location") );
	   #              my $x = $dsl->app->request->var('jwt');
	   #              if (defined($x)) {
		  #               $x = { data => $x } unless (ref($x) || "") eq "HASH";
		  #               $u->query_param( _jwt => encode_jwt($x, _get_secret()));
	   #  	            $response->header(Location => $u);
    # 	     	   }
	   #  	    }
			}
		)
	);
};



register_plugin;

1;
