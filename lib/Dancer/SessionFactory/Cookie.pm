use 5.010;
use strict;
use warnings;

package Dancer::SessionFactory::Cookie;
# ABSTRACT: Dancer 2 session storage in secure cookies
# VERSION

use Digest::SHA             ();
use Math::Random::ISAAC::XS ();
use MIME::Base64            ();
use Sereal::Encoder         ();
use Sereal::Decoder         ();

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

=attr max_duration

If C<cookie_duration> is not set, this puts a maximum duration on
the validity of the cookie, regardless of the length of the
browser session.

=cut

has max_duration => (
  is        => 'ro',
  isa       => Int,
  predicate => 1,
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

has _rng => (
  is      => 'lazy',
  isa     => InstanceOf ['Math::Random::ISAAC::XS'],
  handles => { '_irand' => 'irand' },
);

sub _build__rng {
  my ($self) = @_;
  my @seeds;
  if ( -f "/dev/random" ) {
    open my $fh, "<:raw", "/dev/random/";
    my $buf = "";
    while ( length $buf < 1024 ) {
      sysread( $fh, $buf, 1024 - length $buf, length $buf );
    }
    @seeds = unpack( 'l*', $buf );
  }
  else {
    @seeds = map { rand } 1 .. 256;
  }
  return Math::Random::ISAAC::XS->new(@seeds);
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

  # cookie is derived from session data and expiration time
  my $data    = $session->data;
  my $expires = $session->expires;

  # if expiration is set, we want to check and clear data; if not,
  # we might add an expiration based on max_duration
  if ( defined $expires ) {
    $data = {} if $expires < time;
  }
  else {
    $expires = $self->has_max_duration ? time + $self->max_duration : "";
  }

  # random salt used to derive unique encryption/MAC key for each cookie
  my $salt = $self->_irand;
  my $key  = $self->_hmac("$salt~$expires");

  my $msg = join( "~", $salt, $expires, $self->_freeze_b64($data) );
  $session->id( "$msg~" . $self->_hmac( $msg, $key ) );
};

#--------------------------------------------------------------------------#
# SessionFactory implementation methods
#--------------------------------------------------------------------------#

# Cookie retrieval: extract, verify and decode data
sub _retrieve {
  my ( $self, $id ) = @_;
  return {} unless length $id;

  my ( $salt, $expires, $data, $mac ) = split qr/~/, $id;
  my $key = $self->_hmac("$salt~$expires");

  # Check MAC
  my $check_mac = $self->_hmac( join("~", $salt, $expires, $data), $key );
  return {} unless $check_mac eq $mac;

  # Check expiration
  return {} if length($expires) && $expires < time;

  # Extract data
  return $self->_thaw_b64($data);
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

sub _construct_value {
  my ( $self, $data, $expires ) = @_;
}

sub _freeze_b64 {
  my ( $self, $data ) = @_;
  return MIME::Base64::encode_base64url( $self->_encode($data) );
}

sub _thaw_b64 {
  my ( $self, $encoded ) = @_;
  $self->_decode( MIME::Base64::decode_base64url($encoded), my $data );
  return $data;
}

sub _hmac {
  my ( $self, $msg ) = @_;
  return MIME::Base64::encode_base64url(
    Digest::SHA::hmac_sha256( $msg, $self->secret_key ) );
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
