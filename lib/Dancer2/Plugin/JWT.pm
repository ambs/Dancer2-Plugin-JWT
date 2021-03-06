use strict;
use warnings;
package Dancer2::Plugin::JWT;
# ABSTRACT: JSON Web Token made simple for Dancer2

use Dancer2::Plugin;
use Crypt::JWT qw(encode_jwt decode_jwt);
use URI;
use URI::QueryParam;

register_hook qw(jwt_exception);

my $fourWeeks = 4 * 24 * 60 * 60;

my $secret;
my $alg;
my $enc;
my $need_iat = undef;
my $need_nbf = undef;
my $need_exp = undef;
my $need_leeway = undef;
my $cookie_domain = undef;

register jwt => sub {
    my $dsl = shift;
    my @args = @_;

    if (@args) {
      $dsl->app->request->var(jwt => $args[0]);
    }
    else {
      if ($dsl->app->request->var('jwt_status') eq "missing") {
	    $dsl->app->execute_hook('plugin.jwt.jwt_exception' => 'No JWT is present');
      }
    }
    return $dsl->app->request->var('jwt') || undef;
};

on_plugin_import {
    my $dsl = shift;

    my $config = plugin_setting;
    die "JWT cannot be used without a secret!" unless (exists $config->{secret} && defined $config->{secret});
    # For RSA and ES algorithms - path to keyfile or JWK string, others algorithms - just secret string
    $secret = $config->{secret};

    $cookie_domain = $config->{cookie_domain};

    $alg = 'HS256';

    if ( exists $config->{alg} && defined $config->{alg} ) {
        my $need_enc = undef;
        my $need_key = undef;

        if ( $config->{alg} =~ /^([EHPR])S(256|384|512)$/ ) {
            my $type = $1;

            if ( $type eq 'P' || $type eq 'R' ) {
                $need_key = 1;
            } elsif ( $type eq 'E' ) {
                $need_key = 2;
            }

            $alg = $config->{alg};
        } elsif ( $config->{alg} =~ /^A(128|192|256)(GCM)?KW$/ ) {
            my $len = $1;

            if ( ( length( unpack( "H*", $secret ) ) * 4 ) != $len ) {
                die "Secret key length must be equal " . $len / 8 . " bytes for selected algoritm";
            }

            $alg = $config->{alg};
            $need_enc = 1;
        } elsif ( $config->{alg} =~ /^PBES2-HS(256|384|512)\+A(128|192|256)KW$/ ) {
            my $hs = $1;
            my $a = $2;

            if ( ( ( $a * 2 ) - $hs ) != 0 ) { 
                die "Incompatible A and HS values";
            }

            $alg = $config->{alg};
            $need_enc = 1;
	} elsif ( $config->{alg} =~ /^RSA((-OAEP(-265)?)|1_5)$/ ) {
            $alg = $config->{alg};
            $need_enc = 1;
            $need_key = 1;
	} elsif ( $config->{alg} =~ /^ECDH-ES(\+A(128|192|256)KW)?$/ ) {
            $alg = $config->{alg};
            $need_enc = 1;
            $need_key = 2;
        } else {
            die "Unknown algoritm";
        }

        if ( $need_enc ) {
            unless ( exists $config->{enc} && defined $config->{enc} ) {
                die "JWE cannot be used with empty encryption method";
            }

            if ( $config->{enc} =~ /^A(128|192|256)GCM$/ ) {
                $enc = $config->{enc};
            } elsif ( $config->{enc} =~ /^A(128|192|256)CBC-HS(256|384|512)$/ ) {
                my $a = $1;
                my $hs = $2;

	        if ( ( ( $a * 2 ) - $hs ) != 0 ) { 
                    die "Incompatible A and HS values";
                }

                $enc = $config->{enc};
            }
        }

	if ( defined $need_key ) {
	    if ( $need_key eq 1 ) {
		# TODO: add code to handle RSA keys or parse JWK hash string:
		##instance of Crypt::PK::RSA
		#my $data = decode_jwt(token=>$t, key=>Crypt::PK::RSA->new('keyfile.pem'));
		#
		##instance of Crypt::X509 (public key only)
		#my $data = decode_jwt(token=>$t, key=>Crypt::X509->new(cert=>$cert));
		#
		##instance of Crypt::OpenSSL::X509 (public key only)
		#my $data = decode_jwt(token=>$t, key=>Crypt::OpenSSL::X509->new_from_file('cert.pem'));
	    } elsif ( $need_key eq 2 ) {
		# TODO: add code to handle ECC keys or parse JWK hash string:
		#instance of Crypt::PK::ECC
		#my $data = decode_jwt(token=>$t, key=>Crypt::PK::ECC->new('keyfile.pem'));
	    }
	}
    }

    if ( exists $config->{need_iat} && defined $config->{need_iat} ) {
        $need_iat = $config->{need_iat};
    }

    if ( exists $config->{need_nbf} && defined $config->{need_nbf} ) { 
        $need_nbf = $config->{need_nbf};
    }

    if ( exists $config->{need_exp} && defined $config->{need_exp} ) { 
        $need_exp = $config->{need_exp};
    }

    if ( exists $config->{need_leeway} && defined $config->{need_leeway} ) { 
        $need_leeway = $config->{need_leeway};
    }

    $dsl->app->add_hook(
        Dancer2::Core::Hook->new(
            name => 'before_template_render',
            code => sub {
                my $tokens = shift;
                $tokens->{jwt} = $dsl->app->request->var('jwt');
            }
        )
    );

    $dsl->app->add_hook(
	Dancer2::Core::Hook->new(
	    name => 'after',
	    code => sub {
		    my $response = shift;
            $response = $response->isa('Dancer2::Core::Response') ? $response : $response->response;
		    $response->push_header('Access-Control-Expose-Headers' => 'Authorization');
	    }
	 )
  );
    
    $dsl->app->add_hook(
        Dancer2::Core::Hook->new(
            name => 'before',
            code => sub {
                my $app = shift;
                my $encoded = $app->request->headers->authorization;

                if( defined $encoded ) {
                    # Remove "Bearer " (sic) from the beginning of the Authorization header if present.
                    # "Bearer" signifies the schema and should be present
                    # but due to backwards compatibility we support also without it.
                    # https://jwt.io/introduction/ (How do JSON Web Tokens work?)
                    $encoded =~ m/^ (?: Bearer [[:space:]]{1} | ) (?<token> [^[:space:]]{0,} ) $/msx;
                    $encoded = $+{token};
                }

                if ($app->request->cookies->{_jwt}) {
                    $encoded = $app->request->cookies->{_jwt}->value ;
                }
                elsif ($app->request->param('_jwt')) {
                    $encoded = $app->request->param('_jwt');
                }

                if ($encoded) {
                    my $decoded;
                    eval {
                        $decoded = decode_jwt( token        => $encoded, 
					       key          => $secret, 
					       verify_iat   => $need_iat,
					       verify_nbf   => $need_nbf,
					       verify_exp   => defined $need_exp ? 1 : 0 ,
					       leeway       => $need_leeway, 
					       accepted_alg => $alg, 
					       accepted_enc => $enc );
                    };
                    if ($@) {
                        $app->execute_hook('plugin.jwt.jwt_exception' => ($a = $@));
                    };
                    $app->request->var('jwt', $decoded);
		    ## no token
		    $app->request->var('jwt_status' => 'present');

                }
		else {
		    ## no token
		    $app->request->var('jwt_status' => 'missing');
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
                    my $encoded = encode_jwt( payload      => $decoded, 
		                                      key          => $secret, 
                      					      alg          => $alg,
                      					      enc          => $enc,
                      					      auto_iat     => $need_iat,
                      					      relative_exp => $need_exp,
                      					      relative_nbf => $need_nbf );
                    $response->headers->authorization($encoded);

                    my %cookie =  (
                    	value     => $encoded,
                    	name      => '_jwt',
                    	expires   => time + ($need_exp // $fourWeeks),
                    	path      => '/',
                    	http_only => 0);
                    $cookie{domain} = $cookie_domain if defined $cookie_domain;
                    $response->push_header('Set-Cookie' => Dancer2::Core::Cookie->new(%cookie)->to_header());

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

     hook 'plugin.jwt.jwt_exception' => sub {
         my $error = shift;
         # do something
     };

=head1 DESCRIPTION

Registers the C<jwt> keyword that can be used to set or retrieve the payload
of a JSON Web Token.

To this to work it is required to have a secret defined in your config.yml file:

   plugins:
      JWT:
          secret: "string or path to private RSA\EC key"
          # default, or others supported by Crypt::JWT
          alg: HS256 
          # required onlt for JWE 
          enc: 
          # add issued at field
          need_iat: 1 
          # check not before field
          need_nbf: 1 
          # in seconds
          need_exp: 600 
          # timeshift for expiration
          need_leeway: 30 
          # JWT cookie domain, in case you need to override it
          cookie_domain: my_domain.com

B<NOTE:> A empty call (without arguments) to jwt will trigger the
exception hook if there is no jwt defined.

=head1 BUGS

I am sure a lot. Please use GitHub issue tracker 
L<here|https://github.com/ambs/Dancer2-Plugin-JWT/>.

=head1 ACKNOWLEDGEMENTS

To Lee Johnson for his talk "JWT JWT JWT" in YAPC::EU::2015.

To Nuno Carvalho for brainstorming and help with testing.

To user2014, thanks for making the module use Crypt::JWT.

=head1 COPYRIGHT AND LICENSE

Copyright 2015-2018 Alberto Simões, all rights reserved.

This module is free software and is published under the same terms as Perl itself.

=head1 AUTHOR

Alberto Simões C<< <ambs@cpan.org> >>

=cut
