use strict;
use warnings;
use Test::More 0.96 import => ['!pass']; # subtests

use YAML;
use Test::TCP 1.30;
use File::Temp 0.22;
use LWP::UserAgent;
use HTTP::Date qw/str2time/;
use File::Spec;

sub find_cookie {
    my ($res) = @_;
    my @cookies = $res->header('set-cookie');
    for my $c (@cookies) {
        next unless $c =~ /dancer\.session/;
        return $c;
    }
    return;
}

sub extract_cookie {
    my ($res) = @_;
    my $c = find_cookie($res) or return;
    my @parts = split /;\s+/, $c;
    my %hash =
      map { my ( $k, $v ) = split /\s*=\s*/; $v ||= 1; ( lc($k), $v ) } @parts;
    $hash{expires} = str2time( $hash{expires} )
      if $hash{expires};
    return \%hash;
}

my $tempdir = File::Temp::tempdir( CLEANUP => 1, TMPDIR => 1 );

my $secret_key = "handbag imitation doublet sickout"; # Crypt::Diceware :-)

my $engine = "Cookie";

my @configs = (
    {
        label  => "default",
        config => { secret_key => $secret_key, },
    },
    {
        label  => "with default_duration",
        config => {
            secret_key       => $secret_key,
            default_duration => 86400 * 7,
        },
    },
    {
        label  => "with cookie_duration",
        config => {
            secret_key      => $secret_key,
            cookie_duration => 3600,
        },
    },
    {
        label  => "forced_expire",
        config => {
            secret_key       => $secret_key,
            default_duration => -100,
        },
    },
);

for my $c (@configs) {
    my ( $label, $config ) = @{$c}{qw/label config/};
    Test::TCP::test_tcp(
        client => sub {
            my $port = shift;
            subtest $label => sub {
                my $ua = LWP::UserAgent->new;
                $ua->cookie_jar( { file => "$tempdir/.cookies.txt" } );

                # no session cookie set if session not referenced
                my $res = $ua->get("http://127.0.0.1:$port/no_session_data");
                ok $res->is_success, "/no_session_data"
                  or diag explain $res;
                my $cookie = extract_cookie($res);
                ok !$cookie, "no cookie set"
                  or diag explain $cookie;

                # recent Dancer: no session created until session is written
                $res = $ua->get("http://127.0.0.1:$port/read_session");
                ok $res->is_success, "/read_session";
                $cookie = extract_cookie($res);
                ok !$cookie, "no cookie set"
                  or diag explain $cookie;

                # set value into session
                $res = $ua->get("http://127.0.0.1:$port/set_session/larry");
                ok $res->is_success, "/set_session/larry";
                $cookie = extract_cookie($res);
                ok $cookie, "session cookie set"
                  or diag explain $cookie;
                my $sid1 = $cookie->{"dancer.session"};

                # read value back
                $res = $ua->get("http://127.0.0.1:$port/read_session");
                ok $res->is_success, "/read_session";
                $cookie = extract_cookie($res);
                ok $cookie, "session cookie set"
                  or diag explain $cookie;
                if ( $c->{label} eq 'forced_expire' ) {
                    like $res->content, qr/name=''/, "session value reset";
                }
                else {
                    like $res->content, qr/name='larry'/, "session value looks good";
                }

                # session cookie should persist even if we don't touch sessions
                $res = $ua->get("http://127.0.0.1:$port/no_session_data");
                ok $res->is_success, "/no_session_data";
                $cookie = extract_cookie($res);
                ok $cookie, "session cookie set"
                  or diag explain $cookie;

                # destroy session and check that cookies expiration is set
                $res = $ua->get("http://127.0.0.1:$port/destroy_session");
                ok $res->is_success, "/destroy_session";
                $cookie = extract_cookie($res);
                ok $cookie, "session cookie set"
                  or diag explain $cookie;
                ok $cookie->{expires} < time, "session cookie is expired";

                # shouldn't be sent session cookie after session destruction
                $res = $ua->get("http://127.0.0.1:$port/no_session_data");
                ok $res->is_success, "/no_session_data";
                $cookie = extract_cookie($res);
                ok !$cookie, "no cookie set"
                  or diag explain $cookie;

                # set value into session again
                $res = $ua->get("http://127.0.0.1:$port/set_session/curly");
                ok $res->is_success, "/set_session/curly";
                $cookie = extract_cookie($res);
                ok $cookie, "session cookie set"
                  or diag explain $cookie;
                my $sid2 = $cookie->{"dancer.session"};
                isnt( $sid2, $sid1, "changing data changes session ID" )
                  or diag explain $cookie;

                # destroy and create a session in one request
                $res = $ua->get("http://127.0.0.1:$port/churn_session");
                ok $res->is_success, "/churn_session";
                $cookie = extract_cookie($res);
                ok $cookie, "session cookie set"
                  or diag explain $cookie;

                # read value back
                $res = $ua->get("http://127.0.0.1:$port/read_session");
                ok $res->is_success, "/read_session";
                $cookie = extract_cookie($res);
                ok $cookie, "session cookie set"
                  or diag explain $cookie;
                if ( $c->{label} eq 'forced_expire' ) {
                    like $res->content, qr/name=''/, "session value reset";
                }
                else {
                    like $res->content, qr/name='damian'/, "session value looks good";
                }

                # try to manipulate cookie
                my $cookie_array = $ua->cookie_jar->{COOKIES}{"127.0.0.1"}{"/"}{"dancer.session"};
                $cookie_array->[1] =~ s/~\d*~/"~" . (time + 100) . "~"/e;

                # read value back
                $res = $ua->get("http://127.0.0.1:$port/read_session");
                ok $res->is_success, "/read_session";
                $cookie = extract_cookie($res);
                ok $cookie, "session cookie set"
                  or diag explain $cookie;
                like $res->content, qr/name=''/, "session reset after bad MAC";

                File::Temp::cleanup();
            };
        },
        server => sub {
            my $port = shift;

            use Dancer2;

            get '/no_session_data' => sub {
                return "session not modified";
            };

            get '/set_session/*' => sub {
                my ($name) = splat;
                session name => $name;
            };

            get '/read_session' => sub {
                my $name = session('name') || '';
                "name='$name'";
            };

            get '/destroy_session' => sub {
                my $name = session('name') || '';
                app->destroy_session;
                return "destroyed='$name'";
            };

            get '/churn_session' => sub {
                app->destroy_session;
                session name => 'damian';
                return "churned";
            };

            setting appdir => $tempdir;
            setting( engines => { session => { $engine => $config } } );
            setting( session => $engine );

            set(
                show_errors  => 1,
                startup_info => 0,
                environment  => 'production',
                port         => $port
            );

            # we're overiding a RO attribute only for this test!
            Dancer2->runner->{'port'} = $port;
            start;
        },
    );
}

done_testing;

