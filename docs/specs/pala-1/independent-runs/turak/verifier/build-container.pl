#!/usr/bin/perl
# §2.4 file container: records concatenated back-to-back, no file header,
# no framing, no trailing metadata. Built from test-vectors.json by
# concatenating each record's header_hex and, where present, body_hex.
use strict;
use warnings;
use JSON::PP;

my $vectors = shift // 'pala1-package/test-vectors.json';
my $out     = shift // 'chain.pala';

local $/;
open my $fh, '<:raw', $vectors or die "open $vectors: $!";
my $j = JSON::PP->new->decode(<$fh>);
close $fh;

my $data = '';
my $n = 0;
for my $r (@{ $j->{records} }) {
    my $hdr  = pack('H*', $r->{header_hex});
    my $body = exists $r->{body_hex} ? pack('H*', $r->{body_hex}) : '';

    # Cross-check the vectors' own declared lengths against the hex they ship.
    die sprintf("seq %d: header_hex is %d bytes but header_len says %d\n",
                $r->{seq}, length($hdr), $r->{header_len})
        if defined $r->{header_len} && length($hdr) != $r->{header_len};
    die sprintf("seq %d: body_hex is %d bytes but body_len says %d\n",
                $r->{seq}, length($body), $r->{body_len})
        if defined $r->{body_len} && length($body) != $r->{body_len};

    $data .= $hdr . $body;
    $n++;
}

open my $o, '>:raw', $out or die "open $out: $!";
print {$o} $data;
close $o;

printf "built %s: %d records, %d bytes\n", $out, $n, length($data);
