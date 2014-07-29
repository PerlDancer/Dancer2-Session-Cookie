use 5.008001;
use strict;
use warnings;

package Dancer2::Session::Cookie;
BEGIN {
  $Dancer2::Session::Cookie::AUTHORITY = 'cpan:YANICK';
}
# ABSTRACT: Dancer 2 session storage in secure cookies
# VERSION
$Dancer2::Session::Cookie::VERSION = '0.006';
use Session::Storage::Secure 0.010 ();

use Moo;
use Dancer2::Core::Types;

#--------------------------------------------------------------------------#
# Attributes
#--------------------------------------------------------------------------#


has secret_key => (
    is       => 'ro',
    isa      => Str,
    required => 1,
);


has default_duration => (
    is        => 'ro',
    isa       => Int,
    predicate => 1,
);

has _store => (
    is      => 'lazy',
    isa     => InstanceOf ['Session::Storage::Secure'],
    handles => {
        '_freeze'   => 'encode',
        '_retrieve' => 'decode',
    },
);

sub _build__store {
    my ($self) = @_;
    my %args = (
        secret_key             => $self->secret_key,
        sereal_encoder_options => { snappy => 1, stringify_unknown => 1 },
        sereal_decoder_options => { validate_utf8 => 1 },
    );
    $args{default_duration} = $self->default_duration
      if $self->has_default_duration;
    return Session::Storage::Secure->new(%args);
}

with 'Dancer2::Core::Role::SessionFactory';

#--------------------------------------------------------------------------#
# Modified SessionFactory methods
#--------------------------------------------------------------------------#

# We don't need to generate an ID.  We'll set it during cookie generation
sub generate_id { '' }

# Cookie generation: serialize the session data into the session ID
# right before the cookie is generated
before 'cookie' => sub {
    my ( $self, %params ) = @_;
    my $session = $params{session};
    return unless ref $session && $session->isa("Dancer2::Core::Session");
    $session->id( $self->_freeze( $session->data, $session->expires ) );
};

#--------------------------------------------------------------------------#
# SessionFactory implementation methods
#--------------------------------------------------------------------------#

# _retrieve handled by _store

# We don't actually flush data; instead we modify cookie generation
sub _flush { return }

# We have nothing to destroy, either; cookie expiration is all that matters
sub _destroy { return }

# There is no way to know about existing sessions when cookies
# are used as the store, so we lie and return an empty list.
sub _sessions { return [] }

1;


# vim: ts=4 sts=4 sw=4 et:

__END__

=pod

=encoding UTF-8

=head1 NAME

Dancer2::Session::Cookie - Dancer 2 session storage in secure cookies

=head1 VERSION

version 0.006

=head1 SYNOPSIS

  # In Dancer 2 config.yml file

  session: Cookie
  engines:
    session:
      Cookie:
        secret_key: your secret passphrase
        default_duration: 604800

=head1 DESCRIPTION

This module implements a session factory for Dancer 2 that stores session state
within a browser cookie.  Features include:

=over

=item *

Data serialization and compression using L<Sereal>

=item *

Data encryption using AES with a unique derived key per cookie

=item * 

Enforced expiration timestamp (independent of cookie expiration)

=item * 

Cookie integrity protected with a message authentication code (MAC)

=back

See L<Session::Storage::Secure> for implementation details and important
security caveats.

=head1 ATTRIBUTES

=head2 secret_key (required)

This is used to secure the cookies.  Encryption keys and message authentication
keys are derived from this using one-way functions.  Changing it will
invalidate all sessions.

=head2 default_duration

Number of seconds for which the session may be considered valid.  If
C<cookie_duration> is not set, this is used instead to expire the session after
a period of time, regardless of the length of the browser session.  It is
unset by default, meaning that sessions expiration is not capped.

=for Pod::Coverage method_names_here
generate_id

=head1 SEE ALSO

CPAN modules providing cookie session storage (possibly for other frameworks):

=over

=item * 

L<Dancer::Session::Cookie> -- Dancer 1 equivalent to this module

=item * 

L<Catalyst::Plugin::CookiedSession> -- encryption only

=item * 

L<HTTP::CryptoCookie> -- encryption only

=item * 

L<Mojolicious::Sessions> -- MAC only

=item * 

L<Plack::Middleware::Session::Cookie> -- MAC only

=item * 

L<Plack::Middleware::Session::SerializedCookie> -- really just a framework and you provide the guts with callbacks

=back

=head1 AUTHOR

David Golden <dagolden@cpan.org>

=head1 COPYRIGHT AND LICENSE

This software is Copyright (c) 2013 by David Golden.

This is free software, licensed under:

  The Apache License, Version 2.0, January 2004

=cut
