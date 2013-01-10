use 5.010;
use strict;
use warnings;

package Dancer::SessionFactory::Cookie;
# ABSTRACT: Dancer 2 session storage in secure cookies
# VERSION

use Crypt::CBC              ();
use Crypt::Rijndael         ();
use Digest::SHA             (qw/hmac_sha256/);
use Math::Random::ISAAC::XS ();
use MIME::Base64            (qw/encode_base64url decode_base64url/);
use Sereal::Encoder         ();
use Sereal::Decoder         ();
use namespace::clean;

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
  handles => { '_freeze' => 'encode' },
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
  handles => { '_thaw' => 'decode' },
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

  # if expiration is set, we want to check it and possibly clear data;
  # if not set, we might add an expiration based on max_duration
  if ( defined $expires ) {
    $data = {} if $expires < time;
  }
  else {
    $expires = $self->has_max_duration ? time + $self->max_duration : "";
  }

  # random salt used to derive unique encryption/MAC key for each cookie
  my $salt       = $self->_irand;
  my $key        = hmac_sha256( $salt, $self->secret_key );
  my $cbc        = Crypt::CBC->new( -key => $key, -cipher => 'Rijndael' );
  my $ciphertext = encode_base64url( $cbc->encrypt( $self->_freeze($data) ) );
  my $msg        = join( "~", $salt, $expires, $ciphertext );

  $session->id( "$msg~" . encode_base64url( hmac_sha256( $msg, $key ) ) );
};

#--------------------------------------------------------------------------#
# SessionFactory implementation methods
#--------------------------------------------------------------------------#

# Cookie retrieval: extract, verify and decode data
sub _retrieve {
  my ( $self, $id ) = @_;
  return {} unless length $id;

  my ( $salt, $expires, $ciphertext, $mac ) = split qr/~/, $id;
  my $key = hmac_sha256( $salt, $self->secret_key );

  # Check MAC
  my $check_mac = hmac_sha256( join( "~", $salt, $expires, $ciphertext ), $key );
  return {} unless encode_base64url($check_mac) eq $mac;

  # Check expiration
  return {} if length($expires) && $expires < time;

  # Decode data
  my $cbc = Crypt::CBC->new( -key => $key, -cipher => 'Rijndael' );
  $self->_thaw( $cbc->decrypt( decode_base64url($ciphertext) ), my $data );
  return $data;
}

# We don't actually flush data; instead we modify cookie generation
sub _flush { return }

# We have nothing to destroy, either; cookie expiration is all that matters
sub _destroy { return }

# There is no way to know about existing sessions when cookies
# are used as the store, so we lie and return an empty list.
sub _sessions { return [] }

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
