# Minimal stand-in for CPAN's Conf::Libconfig, just enough for sslh's t/run (upstream's
# end-to-end suite): new, read_file, value(path), lookup_value(path). Conf::Libconfig has no
# Debian package and is an XS module, so mayhem/test.sh puts this pure-Perl reader on PERL5LIB
# instead. It parses the libconfig grammar the t/*.cfg files use: settings `name: value;`
# (or `=`), groups `{}`, lists `()`, arrays `[]`, strings, integers, floats, booleans, and
# `#`, `//`, `/* */` comments. Groups become hashrefs, lists/arrays arrayrefs, as in the real
# module.
package Conf::Libconfig;
use strict;
use warnings;
our $VERSION = '1.0.3';

sub new { my ($class) = @_; return bless { root => {} }, $class; }

sub read_file {
    my ($self, $file) = @_;
    open my $fh, '<', $file or return 0;
    local $/;
    my $text = <$fh>;
    close $fh;
    my $p = { s => $text, pos => 0 };
    $self->{root} = _settings($p, undef);
    return 1;
}

sub _ws {
    my ($p) = @_;
    for (;;) {
        pos($p->{s}) = $p->{pos};
        if ($p->{s} =~ /\G(?:\s+|#[^\n]*|\/\/[^\n]*|\/\*.*?\*\/)/gcs) { $p->{pos} = pos($p->{s}); next; }
        last;
    }
}

sub _tok {    # match regex at current position, return captured groups or ()
    my ($p, $re) = @_;
    _ws($p);
    pos($p->{s}) = $p->{pos};
    if ($p->{s} =~ /\G$re/gc) { my @m = ($&, $1); $p->{pos} = pos($p->{s}); return @m; }
    return ();
}

sub _die { my ($p, $what) = @_; die "Conf::Libconfig: $what at offset $p->{pos}\n"; }

sub _settings {    # until $close (or end of input when undef)
    my ($p, $close) = @_;
    my %h;
    for (;;) {
        _ws($p);
        if (defined $close) { return \%h if _tok($p, qr/\Q$close\E/); }
        elsif ($p->{pos} >= length $p->{s}) { return \%h; }
        my (undef, $name) = _tok($p, qr/([A-Za-z*][-A-Za-z0-9_*]*)/) or _die($p, 'setting name expected');
        _tok($p, qr/[:=]/) or _die($p, "':' expected after $name");
        $h{$name} = _value($p);
        _tok($p, qr/[;,]/);
    }
}

sub _value {
    my ($p) = @_;
    my @m;
    return _settings($p, '}') if _tok($p, qr/\{/);
    return _list($p, ')') if _tok($p, qr/\(/);
    return _list($p, ']') if _tok($p, qr/\[/);
    if (@m = _tok($p, qr/"((?:[^"\\]|\\.)*)"/s)) {
        my $v = $m[1];
        # adjacent string literals concatenate
        while (my @n = _tok($p, qr/"((?:[^"\\]|\\.)*)"/s)) { $v .= $n[1]; }
        $v =~ s/\\(["\\])/$1/g;
        $v =~ s/\\n/\n/g; $v =~ s/\\t/\t/g; $v =~ s/\\r/\r/g;
        $v =~ s/\\x([0-9A-Fa-f]{2})/chr hex $1/ge;
        return $v;
    }
    return 1 if _tok($p, qr/true\b/i);
    return 0 if _tok($p, qr/false\b/i);
    if (@m = _tok($p, qr/(0[xX][0-9A-Fa-f]+)L{0,2}/)) { return hex $m[1]; }
    if (@m = _tok($p, qr/([-+]?(?:\d+\.\d*|\.\d+|\d+)(?:[eE][-+]?\d+)?)L{0,2}/)) { return 0 + $m[1]; }
    _die($p, 'value expected');
}

sub _list {
    my ($p, $close) = @_;
    my @a;
    for (;;) {
        return \@a if _tok($p, qr/\Q$close\E/);
        push @a, _value($p);
        _tok($p, qr/,/);
    }
}

sub value {
    my ($self, $path) = @_;
    my $v = $self->{root};
    for my $k (split /\./, $path) {
        return undef unless ref $v eq 'HASH' && exists $v->{$k};
        $v = $v->{$k};
    }
    return $v;
}

sub lookup_value { my ($self, $path) = @_; return $self->value($path); }

1;
