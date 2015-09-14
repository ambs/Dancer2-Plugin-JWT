use strict;
use warnings;
package Dancer2::Plugin::JWT;
# ABSTRACT: JSON Web Token made simple for Dancer2

use Dancer2::Plugin;
use JSON::WebToken;
use URI;
use URI::QueryParam;

register_hook qw(jwt_exception);

my $config;

sub _get_secret {
	my $dsl = shift;
	$config = $dsl->config->{plugins}{JWT};
	die "JWT cannot be used without a secret!" unless exists $config->{secret};
	return $config->{secret};
}

register jwt => sub {
	my $dsl = shift;
	my @args = @_;

#	$config = plugin_setting();

	if (@args) {
		$dsl->app->request->var(jwt => $args[0]);
	}
	return $dsl->app->request->var('jwt') || undef;
};

on_plugin_import {
	my $dsl = shift;

	$dsl->hook(
		before => sub {
				my $app = shift;
				my $encoded = $app->request->headers->authorization;

				if (!$encoded && $app->request->param('_jwt')) {
					$encoded = $app->request->param('_jwt');
				}

				if ($encoded) {
					my $decoded;
					my $secret = _get_secret($dsl);
					eval {
						$decoded = decode_jwt($encoded, $secret);
					};
					if ($@) {
						$dsl->execute_hook('jwt_exception' => $@);
					};
					$app->request->var('jwt', $decoded);
				}
			}
		);

	$dsl->hook(
		after => sub {
				my $response = shift;
                my $decoded = $dsl->app->request->var('jwt');
                if (defined($decoded)) {
					my $encoded = encode_jwt($decoded, _get_secret($dsl));
					$response->headers->authorization($encoded);
					if ($response->status =~ /^3/) {
	                	my $u = URI->new( $response->header("Location") );
		                $u->query_param( _jwt => $encoded);
	     	            $response->header(Location => $u);
     	     	   }
				}
			}
	);
};



register_plugin;

1;

=encoding UTF-8

=head1 NAME

Dancer2::Plugin::JWT - JSON Web Token made simple for Dancer2

=head1 SYNOPSIS

     use Dancer2;
     use Dancer2::Plugin::JWT;

     post '/login' => sub {
         if (is_valid(param("username"), param("password"))) {
            jwt { username => param("username") };
            template 'index';
         }
         else {
             redirect '/';
         }
     };

     get '/private' => sub {
         my $data = jwt;
         redirect '/ unless exists $data->{username};

         ...
     };

=head1 DESCRIPTION

Registers the C<jwt> keyword that can be used to set or retrieve the payload
of a JSON Web Token.

To this to work it is required to have a secret defined in your config.yml file:

   plugins:
      JWT:
          secret: "my little secret"


=head1 BUGS

I am sure a lot. Please use GitHub issue tracker 
L<here|https://github.com/ambs/Dancer2-Plugin-JWT/>.

=head1 ACKNOWLEDGEMENTS

To Lee Johnson for his talk "JWT JWT JWT" in YAPC::EU::2015.

To Yuji Shimada for JSON::WebToken.

To Nuno Carvalho for brainstorming and help with testing.

=head1 COPYRIGHT AND LICENSE

Copyright 2015 Alberto Simões, all rights reserved.

This module is free software and is published under the same terms as Perl itself.

=head1 AUTHOR

Alberto Simões C<< <ambs@cpan.org> >>

=cut






