use 5.008001;
use strict;
use warnings;

package Dancer::SessionFactory::Cookie;
# ABSTRACT: Dancer 2 session storage in secure cookies
# VERSION

use MIME::Base64    ();
use Sereal::Encoder ();
use Sereal::Decoder ();

use Moo;
use Dancer::Core::Types;

with 'Dancer::Core::Role::SessionFactory';

#--------------------------------------------------------------------------#
# Attributes
#--------------------------------------------------------------------------#

=attr secret_key

  secret_key: your secret pass phrase here

This is used to secure the cookies.  Encryption keys and message authentication
keys are derived from this using one-way functions.  Changing it will
invalidate all sessions.

=cut

has secret_key => (
  is       => 'ro',
  isa      => Str,
  required => 1,
);

has _encoder => (
  is      => 'lazy',
  isa     => InstanceOf ['Sereal::Encoder'],
  handles => { '_encode' => 'encode' },
);

sub _build__encoder {
  my ($self) = @_;
  return Sereal::Encoder->new(
    {
      snappy         => 1,
      croak_on_bless => 1,
    }
  );
}

has _decoder => (
  is      => 'lazy',
  isa     => InstanceOf ['Sereal::Decoder'],
  handles => { '_decode' => 'decode' },
);

sub _build__decoder {
  my ($self) = @_;
  return Sereal::Decoder->new(
    {
      refuse_objects => 1,
      validate_utf8  => 1,
    }
  );
}

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
  return unless ref $session && $session->isa("Dancer::Core::Session");

  if ( $session->expires && $session->expires < time ) {
    $session->id( $self->_encode_b64( {} ) );
  }
  else {
    $session->id( $self->_encode_b64( $session->data ) );
  }
};

#--------------------------------------------------------------------------#
# SessionFactory implementation methods
#--------------------------------------------------------------------------#

# Cookie retrieval: extract, decode and verify data
sub _retrieve {
  my ( $self, $id ) = @_;
  return {} unless length $id;
  return $self->_decode_b64( $id );
}

# We don't actually flush data; instead we modify cookie generation
sub _flush { return }

# We have nothing to destroy, either; cookie expiration is all that matters
sub _destroy { return }

# There is no way to know about existing sessions when cookies
# are used as the store, so we lie and return an empty list.
sub _sessions { return [] }

#--------------------------------------------------------------------------#
# Private methods
#--------------------------------------------------------------------------#

sub _encode_b64 {
  my ( $self, $data ) = @_;
  return MIME::Base64::encode_base64url( $self->_encode($data) );
}

sub _decode_b64 {
  my ( $self, $encoded ) = @_;
  $self->_decode( MIME::Base64::decode_base64url($encoded), my $data );
  return $data;
}

1;

=for Pod::Coverage method_names_here

=head1 SYNOPSIS

  use Dancer::SessionFactory::Cookie;

=head1 DESCRIPTION

This module might be cool, but you'd never know it from the lack
of documentation.

=head1 USAGE

Good luck!

=head1 SEE ALSO

Maybe other modules do related things.

=cut

# vim: ts=2 sts=2 sw=2 et:
