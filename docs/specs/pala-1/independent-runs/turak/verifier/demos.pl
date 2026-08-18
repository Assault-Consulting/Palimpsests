#!/usr/bin/perl
# PALA-1 v1.0 — the seven §8 mutation demos, plus independently constructed
# adversarial cases. Every mutation is applied to the §2.4 container at the
# byte level and fed to the same verifier used for the pass bar.
use strict;
use warnings;
use lib 'verifier';
use PALA1;
use JSON::PP;
use Digest::SHA qw(sha256);

binmode(STDOUT, ':encoding(UTF-8)');

my $container_file = shift // 'chain.pala';
my $vectors_file   = shift // 'pala1-package/test-vectors.json';

local $/;
open my $vf, '<:raw', $vectors_file or die $!; my $V = JSON::PP->new->decode(<$vf>); close $vf;
open my $cf, '<:raw', $container_file or die $!; my $BASE = <$cf>; close $cf;

my ($pass, $fail) = (0, 0);
sub check {
    my ($label, $got, $want) = @_;
    my $ok = (defined $got && defined $want && "$got" eq "$want");
    $ok ? $pass++ : $fail++;
    printf "    [%s] %-58s %s\n", ($ok ? 'ok' : 'XX'), $label,
        $ok ? $got : "got=$got want=$want";
    return $ok;
}
sub hdr { my ($r) = @_; return $r->{header_bytes} }

# ---- a minimal §2.1 header encoder, for the append-based demos -------------
sub encode_header {
    my (%f) = @_;
    my $tlv = $f{tlv} // '';
    my $header_len = 156 + length($tlv);
    my $h = '';
    $h .= 'PALA';                                     #   0 magic
    $h .= pack('v', $f{format_version} // 1);         #   4
    $h .= pack('v', $header_len);                     #   6
    $h .= pack('v', $f{record_type});                 #   8
    $h .= pack('C', $f{assurance_tier} // 0);         #  10
    $h .= pack('C', $f{time_trust}     // 1);         #  11
    $h .= pack('Q<', $f{seq});                        #  12
    $h .= $f{boot_id};                                #  20 (16)
    $h .= $f{prev_hash};                              #  36 (32)
    $h .= $f{span_id}        // ("\x00" x 16);        #  68
    $h .= $f{parent_span_id} // ("\x00" x 16);        #  84
    $h .= pack('Q<', $f{monotonic_ns}  // 0);         # 100
    $h .= pack('q<', $f{wall_clock_ns} // 0);         # 108
    $h .= pack('V', $f{key_id}   // 0);               # 116
    $h .= pack('V', $f{body_len} // 0);               # 120
    $h .= $f{body_digest} // ("\x00" x 32);           # 124 (32)
    die 'fixed header is not 156 bytes' unless length($h) == 156;
    return $h . $tlv;
}

my $base_rep = PALA1::verify_chain($BASE);
my @R = @{ $base_rep->{records} };
my $BOOT_ID = $R[-1]{header}{boot_id};
my $HEAD    = $base_rep->{head_raw};

print "=" x 78, "\n";
print "PALA-1 v1.0 - section 8 mutation demos\n";
print "=" x 78, "\n";

# --------------------------------------------------------- 1. body_bitflip
{
    print "\n  1. body_bitflip - flip one bit in the seq-3 body\n";
    my ($r3) = grep { $_->{header}{seq} == 3 } @R;
    my $body_off = $r3->{offset} + $r3->{header}{header_len};
    my $m = $BASE;
    substr($m, $body_off, 1) = chr(ord(substr($m, $body_off, 1)) ^ 0x01);
    my $rep = PALA1::verify_chain($m);
    my ($m3) = grep { $_->{header}{seq} == 3 } @{ $rep->{records} };
    my $digest_ok = (sha256($m3->{body_bytes}) eq $m3->{header}{body_digest}) ? 1 : 0;
    check('body_digest mismatch detected (section 7.5)', ($digest_ok ? 'no' : 'yes'), 'yes');
    check('chain still verifies (section 1.2 - hash covers header only)',
          ($rep->{chain_ok} ? 'true' : 'false'),
          ($V->{demos}{body_bitflip}{chain_still_verifies} ? 'true' : 'false'));
    check('chain_head unchanged by the body edit', $rep->{head}, $base_rep->{head});
}

# --------------------------------------------------- 2. unknown_record_type
{
    print "\n  2. unknown_record_type - append a record of type 0x7fff\n";
    my $h = encode_header(record_type => 0x7fff, seq => 12, boot_id => $BOOT_ID,
                          prev_hash => $HEAD, time_trust => 1);
    my $rep = PALA1::verify_chain($BASE . $h);
    check('chain_ok', ($rep->{chain_ok} ? 'true' : 'false'),
          ($V->{demos}{unknown_record_type}{chain_ok} ? 'true' : 'false'));
    check('count', $rep->{count}, $V->{demos}{unknown_record_type}{count});
    check('uninterpretable', '[' . join(',', @{ $rep->{uninterpretable} }) . ']',
          '[' . join(',', @{ $V->{demos}{unknown_record_type}{uninterpretable_seqs} }) . ']');
    check('not reported as a break (section 7.6)',
          '[' . join(',', @{ $rep->{breaks} }) . ']', '[]');
}

# -------------------------------------------------------- 3. tail_truncation
{
    print "\n  3. tail_truncation - drop the last record (seq 11)\n";
    my $last = $R[-1];
    my $m = substr($BASE, 0, $last->{offset});
    my $rep = PALA1::verify_chain($m);
    check('dropped_seq', $last->{header}{seq}, $V->{demos}{tail_truncation}{dropped_seq});
    check('chain_ok WITHOUT an anchor (section 7.1 cannot see truncation)',
          ($rep->{chain_ok} ? 'true' : 'false'),
          ($V->{demos}{tail_truncation}{chain_ok_without_anchor} ? 'true' : 'false'));
    my $c = PALA1::check_completeness($rep, $V->{anchor_head});
    check('complete_to_anchor WITH an anchor (section 7.2 can)',
          ($c->{complete_to_anchor} ? 'true' : 'false'),
          ($V->{demos}{tail_truncation}{complete_to_anchor} ? 'true' : 'false'));
    check('diagnosis', $c->{reason}, $V->{demos}{tail_truncation}{anchor_reason});
    check('no truncated-tail report (the file ends on a record boundary)',
          defined $rep->{truncated_tail} ? 'yes' : 'no', 'no');
}

# ----------------------------------------------------------- 4. stale_anchor
{
    print "\n  4. stale_anchor - check against the seq-9 ANCHOR_HEAD TLV\n";
    my ($arec) = grep { $_->{header}{record_type} == 0x0050 } @R;
    my $ah = PALA1::tlv_value($arec, 0x0050);
    my $c = PALA1::check_completeness($base_rep, unpack('H*', $ah));
    check('chain_ok', ($base_rep->{chain_ok} ? 'true' : 'false'),
          ($V->{demos}{stale_anchor}{chain_ok} ? 'true' : 'false'));
    check('complete_to_anchor', ($c->{complete_to_anchor} ? 'true' : 'false'),
          ($V->{demos}{stale_anchor}{complete_to_anchor} ? 'true' : 'false'));
    check('anchor_names_seq', $c->{anchor_names_seq}, $V->{demos}{stale_anchor}{anchor_names_seq});
    check('anchor_lag', $c->{anchor_lag}, $V->{demos}{stale_anchor}{anchor_lag});
    check('diagnosis', $c->{reason}, $V->{demos}{stale_anchor}{anchor_reason});
}

# --------------------------------------------------------------- 5. seq_gap
{
    print "\n  5. seq_gap - append seq 99 after seq 11, hashes valid\n";
    my $h = encode_header(record_type => 0x0012, seq => 99, boot_id => $BOOT_ID,
                          prev_hash => $HEAD, time_trust => 1);
    my $rep = PALA1::verify_chain($BASE . $h);
    check('chain_ok', ($rep->{chain_ok} ? 'true' : 'false'),
          ($V->{demos}{seq_gap}{chain_ok} ? 'true' : 'false'));
    check('gaps', '[' . join(',', @{ $rep->{gaps} }) . ']',
          '[' . join(',', @{ $V->{demos}{seq_gap}{gaps} }) . ']');
    check('breaks empty - the hashes DO link (section 4.1)',
          '[' . join(',', @{ $rep->{breaks} }) . ']', '[]');
}

# ------------------------------------------------------- 6. missing_genesis
{
    print "\n  6. missing_genesis - drop record 0; chain starts at BOOT (seq 1)\n";
    print "     discriminating: the new first record has a NON-ZERO prev_hash\n";
    my $m = substr($BASE, $R[1]{offset});
    my $rep = PALA1::verify_chain($m);
    my ($first) = @{ $rep->{records} };
    check('first record prev_hash is non-zero (case is discriminating)',
          (($first->{header}{prev_hash} ne ("\x00" x 32)) ? 'yes' : 'no'), 'yes');
    check('chain_ok', ($rep->{chain_ok} ? 'true' : 'false'),
          ($V->{demos}{missing_genesis}{chain_ok} ? 'true' : 'false'));
    check('violation count is EXACTLY one', scalar(@{ $rep->{violations} }),
          scalar(@{ $V->{demos}{missing_genesis}{violations} }));
    check('violation is [0, ...]', $rep->{violations}[0][0],
          $V->{demos}{missing_genesis}{violations}[0][0]);
    check('violation text', $rep->{violations}[0][1],
          $V->{demos}{missing_genesis}{violations}[0][1]);
    check('breaks empty - no spurious break at the first record',
          '[' . join(',', @{ $rep->{breaks} }) . ']',
          '[' . join(',', @{ $V->{demos}{missing_genesis}{breaks} }) . ']');
}

# ------------------------------------------------ 7. unknown_time_with_clock
{
    print "\n  7. unknown_time_with_clock - time_trust=UNKNOWN, wall_clock != 0\n";
    my $h = encode_header(record_type => 0x0012, seq => 12, boot_id => $BOOT_ID,
                          prev_hash => $HEAD, time_trust => 0,
                          wall_clock_ns => 1784000010000000000);
    my $rep = PALA1::verify_chain($BASE . $h);
    check('chain_ok', ($rep->{chain_ok} ? 'true' : 'false'),
          ($V->{demos}{unknown_time_with_clock}{chain_ok} ? 'true' : 'false'));
    check('violation count', scalar(@{ $rep->{violations} }),
          scalar(@{ $V->{demos}{unknown_time_with_clock}{violations} }));
    check('violation seq', $rep->{violations}[0][0],
          $V->{demos}{unknown_time_with_clock}{violations}[0][0]);
    check('violation text', $rep->{violations}[0][1],
          $V->{demos}{unknown_time_with_clock}{violations}[0][1]);
    check('wall_clock_ns round-trips past 2^53 exactly (section 1.1)',
          $rep->{records}[-1]{header}{wall_clock_ns}, '1784000010000000000');
}

print "\n", "=" x 78, "\n";
print "Independently constructed cases (beyond the published demos)\n";
print "=" x 78, "\n";

# ---- A. GENESIS at a non-first position (§4.2) ---------------------------
{
    print "\n  A. a second GENESIS appended at seq 12 (section 4.2)\n";
    my $h = encode_header(record_type => 0x0001, seq => 12, boot_id => $BOOT_ID,
                          prev_hash => $HEAD, time_trust => 1);
    my $rep = PALA1::verify_chain($BASE . $h);
    check('chain_ok false', ($rep->{chain_ok} ? 'true' : 'false'), 'false');
    check('violation text', $rep->{violations}[0][1],
          'GENESIS record at a position other than the first');
    check('breaks empty - the link is sound, the KIND is wrong',
          '[' . join(',', @{ $rep->{breaks} }) . ']', '[]');
}

# ---- B. GENESIS first but with a non-zero prev_hash ----------------------
{
    print "\n  B. first record IS a GENESIS but prev_hash is non-zero (section 4.2)\n";
    my $g = encode_header(record_type => 0x0001, seq => 0, boot_id => $BOOT_ID,
                          prev_hash => ("\xaa" x 32), time_trust => 0);
    my $rep = PALA1::verify_chain($g);
    check('chain_ok false', ($rep->{chain_ok} ? 'true' : 'false'), 'false');
    check('violation text', $rep->{violations}[0][1],
          'GENESIS prev_hash is not 32 zero bytes');
    check('exactly one violation', scalar(@{ $rep->{violations} }), 1);
}

# ---- C. TLV that overruns header_len (§2.2) ------------------------------
{
    print "\n  C. a TLV whose length overruns header_len (section 2.2)\n";
    # header_len says 156+8, but the single TLV claims a 40-byte value.
    my $tlv = pack('v', 0x0001) . pack('v', 40) . ('x' x 4);
    my $h = encode_header(record_type => 0x0012, seq => 0, boot_id => $BOOT_ID,
                          prev_hash => ("\x00" x 32), time_trust => 1, tlv => $tlv);
    # make it a GENESIS so the only complaint is the TLV
    $h = encode_header(record_type => 0x0001, seq => 0, boot_id => $BOOT_ID,
                       prev_hash => ("\x00" x 32), time_trust => 1, tlv => $tlv);
    my $rep = PALA1::verify_chain($h);
    check('chain_ok false', ($rep->{chain_ok} ? 'true' : 'false'), 'false');
    check('diagnosed as a TLV overrun',
          (($rep->{violations}[0][1] // '') =~ /overruns header_len/ ? 'yes' : 'no'), 'yes');
}

# ---- D. truncated tail: cut mid-record (§2.4) ----------------------------
{
    print "\n  D. file cut in the middle of the last record (section 2.4)\n";
    my $m = substr($BASE, 0, length($BASE) - 20);
    my $rep = PALA1::verify_chain($m);
    check('reported as a truncated tail, not a break',
          (defined $rep->{truncated_tail} ? 'yes' : 'no'), 'yes');
    check('breaks empty (not a chain break at any earlier record)',
          '[' . join(',', @{ $rep->{breaks} }) . ']', '[]');
    check('records before the cut still parse', $rep->{count}, 11);
}

# ---- E. unknown TLV type must be hashed, never rejected (§2.2, §7.6) -----
{
    print "\n  E. an unknown TLV type 0x7f00 in a known record (section 2.2)\n";
    my $tlv = pack('v', 0x7f00) . pack('v', 4) . 'abcd';
    my $h = encode_header(record_type => 0x0012, seq => 12, boot_id => $BOOT_ID,
                          prev_hash => $HEAD, time_trust => 1, tlv => $tlv);
    my $rep = PALA1::verify_chain($BASE . $h);
    check('chain_ok true - unknown TLV does NOT cause rejection',
          ($rep->{chain_ok} ? 'true' : 'false'), 'true');
    check('record still interpretable (the TYPE is known)',
          '[' . join(',', @{ $rep->{uninterpretable} }) . ']', '[]');
    check('the unknown TLV bytes were hashed into record_hash',
          (unpack('H*', $rep->{records}[-1]{record_hash}) ne
           unpack('H*', sha256(substr($h, 0, 156)))) ? 'yes' : 'no', 'yes');
}

# ---- F. unknown format_version (§7.6) ------------------------------------
{
    print "\n  F. unknown format_version = 2 (section 7.6)\n";
    # time_trust is deliberately illegal (9): section 7.4 MUST NOT be applied.
    my $h = encode_header(record_type => 0x0012, seq => 12, boot_id => $BOOT_ID,
                          prev_hash => $HEAD, format_version => 2, time_trust => 9);
    my $rep = PALA1::verify_chain($BASE . $h);
    check('chain_ok true - MUST NOT reject', ($rep->{chain_ok} ? 'true' : 'false'), 'true');
    check('reported uninterpretable', '[' . join(',', @{ $rep->{uninterpretable} }) . ']', '[12]');
    check('section 7.4 NOT applied to it (illegal time_trust=9 not flagged)',
          scalar(@{ $rep->{violations} }), 0);
}

# ---- G/H/I. the remaining §7.4 checks ------------------------------------
{
    print "\n  G. body_len = 0 but body_digest non-zero (section 2.1)\n";
    my $h = encode_header(record_type => 0x0001, seq => 0, boot_id => $BOOT_ID,
                          prev_hash => ("\x00" x 32), time_trust => 1,
                          body_len => 0, body_digest => ("\x11" x 32));
    my $rep = PALA1::verify_chain($h);
    check('flagged', (($rep->{violations}[0][1] // '') =~ /body_len == 0/ ? 'yes' : 'no'), 'yes');

    print "\n  H. key_id != 0 with body_len = 20 (< 12 nonce + 16 tag) (section 4.4)\n";
    my $body = 'x' x 20;
    my $h2 = encode_header(record_type => 0x0001, seq => 0, boot_id => $BOOT_ID,
                           prev_hash => ("\x00" x 32), time_trust => 1,
                           key_id => 7, body_len => 20, body_digest => sha256($body));
    my $rep2 = PALA1::verify_chain($h2 . $body);
    check('flagged', (($rep2->{violations}[0][1] // '') =~ /< 28/ ? 'yes' : 'no'), 'yes');

    print "\n  I. time_trust = 4, undefined in version 1 (section 5)\n";
    my $h3 = encode_header(record_type => 0x0001, seq => 0, boot_id => $BOOT_ID,
                           prev_hash => ("\x00" x 32), time_trust => 4);
    my $rep3 = PALA1::verify_chain($h3);
    check('flagged', (($rep3->{violations}[0][1] // '') =~ /undefined in version 1/ ? 'yes' : 'no'), 'yes');
}

# ---- J. reordering two records (§4.1) ------------------------------------
{
    print "\n  J. swap records seq 6 and seq 7 (section 4.1)\n";
    my ($a, $b) = ($R[6], $R[7]);
    my $seg_a = substr($BASE, $a->{offset}, $a->{header}{header_len} + $a->{header}{body_len});
    my $seg_b = substr($BASE, $b->{offset}, $b->{header}{header_len} + $b->{header}{body_len});
    my $m = substr($BASE, 0, $a->{offset}) . $seg_b . $seg_a
          . substr($BASE, $b->{offset} + length($seg_b));
    my $rep = PALA1::verify_chain($m);
    check('chain_ok false', ($rep->{chain_ok} ? 'true' : 'false'), 'false');
    check('breaks reported', (scalar(@{ $rep->{breaks} }) > 0 ? 'yes' : 'no'), 'yes');
    check('gaps reported too (seq order disturbed)',
          (scalar(@{ $rep->{gaps} }) > 0 ? 'yes' : 'no'), 'yes');
}

# ---- K. CVE-2012-2459: promotion vs duplication (§4.3) -------------------
{
    print "\n  K. CVE-2012-2459 - promotion must not collide with duplication\n";
    my @abc = map { sha256($_) } qw(a b c);
    my @abcc = (@abc, $abc[2]);
    my $r3 = PALA1::merkle_root_iterative(@abc);
    my $r4 = PALA1::merkle_root_iterative(@abcc);
    check('root([a,b,c]) != root([a,b,c,c])',
          (unpack('H*', $r3) ne unpack('H*', $r4)) ? 'distinct' : 'COLLIDE', 'distinct');
    # what the duplicating (buggy) construction would have produced:
    my $dup = PALA1::mt_node(PALA1::mt_node(PALA1::mt_leaf($abc[0]), PALA1::mt_leaf($abc[1])),
                             PALA1::mt_node(PALA1::mt_leaf($abc[2]), PALA1::mt_leaf($abc[2])));
    check('our 3-leaf root is the PROMOTED one, not the duplicated one',
          (unpack('H*', $r3) ne unpack('H*', $dup)) ? 'promoted' : 'duplicated', 'promoted');
    check('and the duplicated 3-leaf root equals root([a,b,c,c]) - the CVE',
          (unpack('H*', $dup) eq unpack('H*', $r4)) ? 'yes' : 'no', 'yes');
}

# ---- L. the two §4.3 constructions agree, for every n up to 200 ----------
{
    print "\n  L. iterative-promotion vs RFC 6962 recursive, n = 0..200\n";
    my @d = map { sha256("leaf-$_") } 0 .. 199;
    my $disagree = 0;
    my $first_bad;
    for my $n (0 .. 200) {
        my @s = @d[0 .. $n - 1];
        @s = () if $n == 0;
        my $a = PALA1::merkle_root_iterative(@s);
        my $b = PALA1::merkle_root_rfc6962(@s);
        if ($a ne $b) { $disagree++; $first_bad //= $n }
    }
    check('all 201 leaf counts agree', $disagree ? "disagree at n=$first_bad" : 'agree', 'agree');
}

# ---- M. every leaf of the published tree proves, and only the right one --
{
    print "\n  M. inclusion proofs for all 30 published leaves\n";
    my @leaves = map { pack('H*', $_) } @{ $V->{merkle}{leaves} };
    my $root = PALA1::merkle_root_iterative(@leaves);
    my ($good, $bad) = (0, 0);
    for my $i (0 .. $#leaves) {
        my @p = PALA1::merkle_proof_iterative($i, @leaves);
        PALA1::merkle_fold_proof($leaves[$i], @p) eq $root ? $good++ : $bad++;
    }
    check('all 30 leaves verify against the root', "$good/30", '30/30');
    # a proof must not verify a leaf it does not belong to
    my @p7 = PALA1::merkle_proof_iterative(7, @leaves);
    check('leaf 8 folded through leaf 7 proof does NOT reach the root',
          (PALA1::merkle_fold_proof($leaves[8], @p7) eq $root) ? 'VERIFIES' : 'rejected', 'rejected');
    my @plens = map { scalar(PALA1::merkle_proof_iterative($_, @leaves)) } 0 .. $#leaves;
    my %lens; $lens{$_}++ for @plens;
    printf "    [--] proof lengths across 30 leaves: %s\n",
        join(', ', map { "$_ x$lens{$_}" } sort { $a <=> $b } keys %lens);
}

printf "\n  %d checks passed, %d failed\n\n", $pass, $fail;
exit($fail ? 1 : 0);
