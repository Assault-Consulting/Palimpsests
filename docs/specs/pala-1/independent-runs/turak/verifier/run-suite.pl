#!/usr/bin/perl
# PALA-1 v1.0 — reproduce the §8 "Expected results" block from the container.
# Prints a MATCH/DIVERGE table for the eleven pass-bar values, then extras.
use strict;
use warnings;
use lib 'verifier';
use PALA1;
use JSON::PP;
use Digest::SHA qw(sha256 sha256_hex);

binmode(STDOUT, ':encoding(UTF-8)');

my $container_file = shift // 'chain.pala';
my $vectors_file   = shift // 'pala1-package/test-vectors.json';

local $/;
open my $vf, '<:raw', $vectors_file or die $!;
my $V = JSON::PP->new->decode(<$vf>);
close $vf;
open my $cf, '<:raw', $container_file or die $!;
my $data = <$cf>;
close $cf;

# ---------------------------------------------------------------- §8 values
my $rep = PALA1::verify_chain($data);
my $comp = PALA1::check_completeness($rep, $V->{anchor_head});

my @leaves = map { pack('H*', $_) } @{ $V->{merkle}{leaves} };
my $root_iter = PALA1::merkle_root_iterative(@leaves);
my $root_rfc  = PALA1::merkle_root_rfc6962(@leaves);

my $pidx = $V->{merkle}{proof_index};
my @published_proof = map { [ $_->[0], pack('H*', $_->[1]) ] } @{ $V->{merkle}{proof} };
my $folded = PALA1::merkle_fold_proof($leaves[$pidx], @published_proof);
my @own_proof = PALA1::merkle_proof_iterative($pidx, @leaves);

my $pass = 0;
my $fail = 0;
my @rows;
sub row {
    my ($n, $name, $got, $want, $note) = @_;
    my $ok = (defined $got && defined $want && $got eq $want);
    $ok ? $pass++ : $fail++;
    push @rows, [ $n, $name, ($ok ? 'MATCH' : 'DIVERGE'), $got, $want, $note // '' ];
}

row(1, 'chain_head', $rep->{head}, $V->{chain_head});
row(2, 'chain_ok', ($rep->{chain_ok} ? 'true' : 'false'),
    ($V->{verify}{chain_ok} ? 'true' : 'false'));
row(3, 'record_count', $rep->{count}, $V->{verify}{count});
row(4, 'breaks (empty)', '[' . join(',', @{ $rep->{breaks} }) . ']',
    '[' . join(',', @{ $V->{verify}{breaks} }) . ']');
row(5, 'gaps (empty)', '[' . join(',', @{ $rep->{gaps} }) . ']',
    '[' . join(',', @{ $V->{verify}{gaps} }) . ']');
row(6, 'violations (empty)',
    '[' . join(',', map { "$_->[0]:$_->[1]" } @{ $rep->{violations} }) . ']',
    '[' . join(',', @{ $V->{verify}{violations} }) . ']');
row(7, 'complete_to_anchor', (defined $comp->{complete_to_anchor}
        ? ($comp->{complete_to_anchor} ? 'true' : 'false') : 'not checked'),
    ($V->{verify}{complete_to_anchor} ? 'true' : 'false'),
    'anchor = store current head');
row(8, 'anchor_head', $rep->{head}, $V->{anchor_head}, 'computed head == published anchor_head');
row(9, 'merkle_tree_hash', unpack('H*', $root_iter), $V->{merkle}{tree_hash},
    'recomputed from merkle.leaves');
row(10, 'merkle_leaf_count', scalar(@leaves), $V->{merkle}{leaf_count});
row(11, sprintf('leaf-%d proof verifies (len %d)', $pidx, scalar(@published_proof)),
    (unpack('H*', $folded) eq unpack('H*', $root_iter) && @published_proof == 5
        ? 'true/5' : 'false/' . scalar(@published_proof)),
    'true/5', 'folded against the RECOMPUTED root');

print "=" x 78, "\n";
print "PALA-1 v1.0 - section 8 Expected results (pass bar)\n";
print "container: $container_file (", length($data), " bytes)\n";
print "=" x 78, "\n";
printf "%-3s %-34s %-8s %s\n", '#', 'value', 'result', 'computed';
printf "%-3s %-34s %-8s %s\n", '-' x 3, '-' x 34, '-' x 8, '-' x 20;
for my $r (@rows) {
    printf "%-3s %-34s %-8s %s\n", $r->[0], $r->[1], $r->[2], $r->[3];
    printf "%-3s %-34s %-8s expected: %s\n", '', '', '', $r->[4] if $r->[2] eq 'DIVERGE';
    printf "%-3s %-34s %-8s (%s)\n", '', '', '', $r->[5] if length $r->[5];
}
printf "\n  %d/%d MATCH, %d DIVERGE\n\n", $pass, $pass + $fail, $fail;

# ------------------------------------------------------------------ extras
print "=" x 78, "\n";
print "Extras beyond the pass bar\n";
print "=" x 78, "\n";

# Both §4.3 constructions must agree.
printf "  [%s] both Merkle constructions agree (iterative promotion vs RFC 6962 recursive)\n",
    (unpack('H*', $root_iter) eq unpack('H*', $root_rfc)) ? 'ok' : 'XX';

# Independently regenerated proof must equal the published one.
my $own_hex = join(',', map { $_->[0] . ':' . unpack('H*', $_->[1]) } @own_proof);
my $pub_hex = join(',', map { $_->[0] . ':' . unpack('H*', $_->[1]) } @published_proof);
printf "  [%s] independently generated leaf-%d proof == published merkle.proof (%d entries)\n",
    ($own_hex eq $pub_hex) ? 'ok' : 'XX', $pidx, scalar(@own_proof);

# Every record's record_hash must match the vectors' published value.
my $rh_ok = 0;
my $rh_n  = 0;
for my $i (0 .. $#{ $rep->{records} }) {
    my $vr = $V->{records}[$i] or next;
    next unless defined $vr->{record_hash};
    $rh_n++;
    $rh_ok++ if unpack('H*', $rep->{records}[$i]{record_hash}) eq $vr->{record_hash};
}
printf "  [%s] per-record record_hash = SHA-256(header_bytes) matches published: %d/%d\n",
    ($rh_ok == $rh_n) ? 'ok' : 'XX', $rh_ok, $rh_n;

# body_digest = SHA-256(body_bytes) over exactly body_len bytes (§2.3, §7.5).
my $bd_ok = 0;
my $bd_n  = 0;
for my $rec (@{ $rep->{records} }) {
    my $h = $rec->{header};
    next unless $h->{body_len} > 0;
    $bd_n++;
    $bd_ok++ if sha256($rec->{body_bytes}) eq $h->{body_digest};
}
printf "  [%s] body_digest = SHA-256(body) over exactly body_len bytes: %d/%d bodies\n",
    ($bd_ok == $bd_n) ? 'ok' : 'XX', $bd_ok, $bd_n;

# The MERKLE record's own TLVs must agree with the recomputed tree (§4.3).
my ($mrec) = grep { $_->{header}{record_type} == 0x0020 } @{ $rep->{records} };
if ($mrec) {
    my $tlv_root  = PALA1::tlv_value($mrec, 0x0011);
    my $tlv_count = PALA1::tlv_value($mrec, 0x0012);
    printf "  [%s] MERKLE record TLV 0x0011 MERKLE_TREE_HASH == recomputed root\n",
        (defined $tlv_root && $tlv_root eq $root_iter) ? 'ok' : 'XX';
    printf "  [%s] MERKLE record TLV 0x0012 MERKLE_LEAF_COUNT == %d published leaves\n",
        (defined $tlv_count && unpack('V', $tlv_count) == scalar(@leaves)) ? 'ok' : 'XX',
        scalar(@leaves);
    printf "  [%s] MERKLE record carries no leaves (body_len = 0, section 4.3)\n",
        ($mrec->{header}{body_len} == 0) ? 'ok' : 'XX';
}

# The ANCHOR record's TLV is a historical note that lags the tip (§7.2, §8).
my ($arec) = grep { $_->{header}{record_type} == 0x0050 } @{ $rep->{records} };
if ($arec) {
    my $ah = PALA1::tlv_value($arec, 0x0050);
    my ($r8) = grep { $_->{header}{seq} == 8 } @{ $rep->{records} };
    printf "  [%s] ANCHOR record TLV 0x0050 ANCHOR_HEAD == record_hash at seq 8 (%s)\n",
        (defined $ah && $r8 && $ah eq $r8->{record_hash}) ? 'ok' : 'XX',
        defined $ah ? substr(unpack('H*', $ah), 0, 16) . '...' : 'absent';
    my $stale = PALA1::check_completeness($rep, unpack('H*', $ah));
    printf "  [%s] checking completeness against that stale TLV gives anchor_lag = %s\n",
        (defined $stale->{anchor_lag} && $stale->{anchor_lag} == 3) ? 'ok' : 'XX',
        $stale->{anchor_lag} // 'n/a';
}

printf "  [%s] container has no truncated tail (final record ends exactly at EOF)\n",
    (!defined $rep->{truncated_tail}) ? 'ok' : 'XX';
printf "  [--] uninterpretable records: [%s]\n", join(',', @{ $rep->{uninterpretable} });
print "\n";

exit($fail ? 1 : 0);
