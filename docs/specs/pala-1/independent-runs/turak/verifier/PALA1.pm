package PALA1;
# ---------------------------------------------------------------------------
# PALA-1 v1.0 independent verifier — written from docs/specs/pala-1/PALA-1.md
# and its test vectors alone. No code from the Palimpsests repository was read
# or used. Perl 5 core modules only (Digest::SHA).
#
# Section references (§) are to PALA-1.md at tag pala1-v1.0.
# ---------------------------------------------------------------------------
use strict;
use utf8;
use warnings;
use Digest::SHA qw(sha256);

our $HEADER_FIXED = 156;                       # §2.1
our $MAGIC        = "PALA";                    # §2.1
our $ZERO32       = "\x00" x 32;

# §3 record types known to this (version 1) verifier.
our %RECORD_TYPE = (
    0x0001 => 'GENESIS',   0x0002 => 'BOOT',      0x0010 => 'SPAN_START',
    0x0011 => 'SPAN_END',  0x0012 => 'EVENT',     0x0020 => 'MERKLE',
    0x0021 => 'AGGREGATE', 0x0030 => 'SHED',      0x0040 => 'SAFETY',
    0x0050 => 'ANCHOR',    0x0051 => 'WITNESS',   0x0060 => 'KEY_SHRED',
);
our $GENESIS = 0x0001;

# §2.2 TLV types (names only; unknown types stay opaque — §7.6).
our %TLV_TYPE = (
    0x0001 => 'ORIGIN_ROLE',       0x0002 => 'ORIGIN_MODEL_DIGEST',
    0x0003 => 'ORIGIN_CONFIG_DIGEST',
    0x0011 => 'MERKLE_TREE_HASH',  0x0012 => 'MERKLE_LEAF_COUNT',
    0x0020 => 'SHED_CLASS',        0x0021 => 'SHED_COUNT',
    0x0022 => 'SHED_WINDOW_NS',
    0x0030 => 'WITNESS_KIND',      0x0031 => 'WITNESS_RANGE_LO',
    0x0032 => 'WITNESS_RANGE_HI',  0x0033 => 'WITNESS_RECEIPT',
    0x0040 => 'SHRED_KEY_ID',      0x0050 => 'ANCHOR_HEAD',
);

our $FORMAT_VERSION = 1;

# --- §2.1 header decoding -------------------------------------------------
# All multi-byte integers little-endian, packed, no alignment padding.
# Offsets are taken verbatim from the §2.1 table.
sub decode_header {
    my ($buf) = @_;
    return undef if length($buf) < $HEADER_FIXED;
    my %h;
    $h{magic}          = substr($buf,   0, 4);
    $h{format_version} = unpack('v',  substr($buf,   4, 2));
    $h{header_len}     = unpack('v',  substr($buf,   6, 2));
    $h{record_type}    = unpack('v',  substr($buf,   8, 2));
    $h{assurance_tier} = unpack('C',  substr($buf,  10, 1));
    $h{time_trust}     = unpack('C',  substr($buf,  11, 1));
    $h{seq}            = unpack('Q<', substr($buf,  12, 8));
    $h{boot_id}        = substr($buf,  20, 16);
    $h{prev_hash}      = substr($buf,  36, 32);
    $h{span_id}        = substr($buf,  68, 16);
    $h{parent_span_id} = substr($buf,  84, 16);
    $h{monotonic_ns}   = unpack('Q<', substr($buf, 100, 8));
    $h{wall_clock_ns}  = unpack('q<', substr($buf, 108, 8));   # i64, signed
    $h{key_id}         = unpack('V',  substr($buf, 116, 4));
    $h{body_len}       = unpack('V',  substr($buf, 120, 4));
    $h{body_digest}    = substr($buf, 124, 32);
    return \%h;
}

# --- §2.2 TLV parsing -----------------------------------------------------
# type u16 | length u16 | value<length>. An item MUST NOT overrun header_len;
# the last item MUST end exactly at header_len.
sub parse_tlvs {
    my ($hdr_bytes) = @_;                       # exactly header_len bytes
    my @items;
    my $off = $HEADER_FIXED;
    my $end = length($hdr_bytes);
    while ($off < $end) {
        return (undef, "TLV item at offset $off truncated (needs 4 header bytes)")
            if $off + 4 > $end;
        my $type = unpack('v', substr($hdr_bytes, $off,     2));
        my $len  = unpack('v', substr($hdr_bytes, $off + 2, 2));
        return (undef, sprintf('TLV type 0x%04x at offset %d overruns header_len', $type, $off))
            if $off + 4 + $len > $end;
        push @items, { type => $type, len => $len,
                       value => substr($hdr_bytes, $off + 4, $len), offset => $off };
        $off += 4 + $len;
    }
    return (undef, "last TLV item does not end exactly at header_len") if $off != $end;
    return (\@items, undef);
}

# Convenience: first TLV value of a given type in a record, or undef.
sub tlv_value {
    my ($rec, $type) = @_;
    my ($items, $err) = parse_tlvs($rec->{header_bytes});
    return undef if $err;
    for my $it (@$items) { return $it->{value} if $it->{type} == $type }
    return undef;
}

# --- §2.4 container splitting --------------------------------------------
# Records concatenated back-to-back; next record at offset+header_len+body_len.
# A file whose final record ends exactly at EOF is well-formed; anything else
# is a truncated tail and MUST be reported as such (not a chain break).
sub split_container {
    my ($data) = @_;
    my @records;
    my $off = 0;
    my $total = length($data);
    my $truncated_tail = undef;
    my $stop = undef;
    while ($off < $total) {
        if ($total - $off < $HEADER_FIXED) {
            $truncated_tail = sprintf(
                'truncated tail: %d byte(s) at offset %d, less than the %d-byte fixed header',
                $total - $off, $off, $HEADER_FIXED);
            last;
        }
        my $h = decode_header(substr($data, $off, $HEADER_FIXED));
        if ($h->{magic} ne $MAGIC) {
            # §7.1: MUST magic == "PALA" else break, stop.
            $stop = sprintf('bad magic at offset %d', $off);
            last;
        }
        if ($h->{header_len} < $HEADER_FIXED) {
            $stop = sprintf('header_len %d < %d at offset %d',
                            $h->{header_len}, $HEADER_FIXED, $off);
            last;
        }
        if ($off + $h->{header_len} + $h->{body_len} > $total) {
            $truncated_tail = sprintf(
                'truncated tail: record at offset %d declares header_len=%d body_len=%d, but only %d byte(s) remain',
                $off, $h->{header_len}, $h->{body_len}, $total - $off);
            last;
        }
        my $hdr_bytes  = substr($data, $off, $h->{header_len});
        my $body_bytes = substr($data, $off + $h->{header_len}, $h->{body_len});
        push @records, {
            offset       => $off,
            header       => $h,
            header_bytes => $hdr_bytes,
            body_bytes   => $body_bytes,
            record_hash  => sha256($hdr_bytes),          # §4.1
        };
        $off += $h->{header_len} + $h->{body_len};
    }
    return { records => \@records, truncated_tail => $truncated_tail, stop => $stop };
}

# --- §7.4 semantic checks -------------------------------------------------
# Run only on records whose format_version and record_type are known (§7.6).
sub semantic_checks {
    my ($rec) = @_;
    my $h = $rec->{header};
    my @v;
    push @v, 'time_trust=UNKNOWN requires wall_clock_ns=0'
        if $h->{time_trust} == 0 && $h->{wall_clock_ns} != 0;              # §5
    push @v, sprintf('time_trust=%d is undefined in version 1 (MUST be <= 3)', $h->{time_trust})
        if $h->{time_trust} > 3;                                           # §5
    my $zero_digest = ($h->{body_digest} eq $ZERO32) ? 1 : 0;
    my $zero_len    = ($h->{body_len} == 0)          ? 1 : 0;
    push @v, 'body_len == 0 <=> body_digest == 32 zero bytes violated'
        if $zero_len != $zero_digest;                                      # §2.1
    push @v, sprintf('key_id!=0 with body_len=%d < 28 (nonce 12 + tag 16)', $h->{body_len})
        if $h->{key_id} != 0 && $h->{body_len} > 0 && $h->{body_len} < 28; # §4.4
    my ($tlvs, $err) = parse_tlvs($rec->{header_bytes});                    # §2.2
    push @v, $err if defined $err;
    return @v;
}

# --- §7.1 header-only chain verification ---------------------------------
# Transcribed from the §7.1 pseudocode, in its order.
sub verify_chain {
    my ($data) = @_;
    my $split = split_container($data);
    my @recs  = @{ $split->{records} };

    my (@breaks, @gaps, @violations, @uninterpretable);
    my $prev     = undef;        # unset: no link expectation yet
    my $expected = undef;        # unset
    my $index    = 0;

    for my $rec (@recs) {
        my $h = $rec->{header};

        # MUST h.header_len == actual header bytes  else violation
        push @violations, [ $h->{seq}, 'header_len does not equal the actual header bytes' ]
            if $h->{header_len} != length($rec->{header_bytes});

        if ($index == 0) {
            if ($h->{record_type} != $GENESIS) {
                # §7.1: exactly ONE violation, reported at position 0, because
                # it is a property of the chain, not of any record's seq.
                push @violations, [ 0, 'chain does not start with a GENESIS record' ];
            } else {
                push @violations, [ $h->{seq}, 'GENESIS prev_hash is not 32 zero bytes' ]
                    if $h->{prev_hash} ne $ZERO32;                          # §4.2
            }
        } else {
            push @violations, [ $h->{seq}, 'GENESIS record at a position other than the first' ]
                if $h->{record_type} == $GENESIS;                            # §4.2
        }

        # break check compares only records that have a predecessor in the file
        push @breaks, $h->{seq}
            if defined $prev && $h->{prev_hash} ne $prev;
        push @gaps, $h->{seq}
            if defined $expected && $h->{seq} != $expected;                  # §4.1
        $expected = $h->{seq} + 1;

        if ($h->{format_version} != $FORMAT_VERSION
            || !exists $RECORD_TYPE{ $h->{record_type} }) {
            push @uninterpretable, $h->{seq};                                # §7.6 — NOT a break
        } else {
            push @violations, [ $h->{seq}, $_ ] for semantic_checks($rec);   # §7.4
        }

        $prev = $rec->{record_hash};                                         # §4.1
        $index++;
    }

    my $ok = (!@breaks && !@gaps && !@violations) ? 1 : 0;
    return {
        count           => scalar(@recs),
        breaks          => \@breaks,
        gaps            => \@gaps,
        violations      => \@violations,
        uninterpretable => \@uninterpretable,
        head            => defined $prev ? unpack('H*', $prev) : undef,
        head_raw        => $prev,
        chain_ok        => $ok,
        truncated_tail  => $split->{truncated_tail},
        stop            => $split->{stop},
        records         => \@recs,
    };
}

# --- §7.2 completeness against an anchor ---------------------------------
# The anchor is the store's CURRENT head, from outside the log — never an
# in-chain ANCHOR record's TLV (§7.2).
sub check_completeness {
    my ($report, $anchor_hex) = @_;
    unless (defined $anchor_hex && length $anchor_hex) {
        return { complete_to_anchor => undef, reason => 'not checked — no anchor supplied' };
    }
    my $anchor = pack('H*', lc $anchor_hex);
    if (defined $report->{head_raw} && $anchor eq $report->{head_raw}) {
        return { complete_to_anchor => 1, reason => 'complete to the anchor' };
    }
    my @recs = @{ $report->{records} };
    for my $i (0 .. $#recs) {
        next unless $recs[$i]{record_hash} eq $anchor;
        my $lag = $#recs - $i;
        return {
            complete_to_anchor => 0,
            anchor_names_seq   => $recs[$i]{header}{seq},
            anchor_lag         => $lag,
            reason => sprintf(
                'chain extends %d record(s) beyond the anchored head — an unanchored tail, not a replacement',
                $lag),
        };
    }
    return {
        complete_to_anchor => 0,
        reason => 'the anchored head names no record in this chain — the log was replaced, rolled back, or truncated',
    };
}

# --- §4.3 Merkle aggregation ---------------------------------------------
# RFC 6962 tree hash, domain-separated. An unpaired node is PROMOTED, never
# duplicated (CVE-2012-2459).
sub mt_leaf  { return sha256("\x00" . $_[0]) }
sub mt_node  { return sha256("\x01" . $_[0] . $_[1]) }
sub mt_empty { return sha256('') }

# Iterative bottom-up form with promotion of an unpaired node.
sub merkle_root_iterative {
    my (@leaf_digests) = @_;
    return mt_empty() unless @leaf_digests;
    my @level = map { mt_leaf($_) } @leaf_digests;
    while (@level > 1) {
        my @next;
        for (my $i = 0; $i < @level; $i += 2) {
            if ($i + 1 < @level) { push @next, mt_node($level[$i], $level[$i + 1]) }
            else                 { push @next, $level[$i] }        # PROMOTED
        }
        @level = @next;
    }
    return $level[0];
}

# RFC 6962 recursive form: split at the largest power of two below n.
sub merkle_root_rfc6962 {
    my (@d) = @_;
    return mt_empty() unless @d;
    return mt_leaf($d[0]) if @d == 1;
    my $n = scalar @d;
    my $k = 1;
    $k <<= 1 while ($k << 1) < $n;                 # largest power of 2 < n
    return mt_node(merkle_root_rfc6962(@d[0 .. $k - 1]),
                   merkle_root_rfc6962(@d[$k .. $n - 1]));
}

# Inclusion proof, iterative form. Entry ["L", s] means the sibling is the
# LEFT operand: the step computes node(s, h). ["R", s] computes node(h, s).
sub merkle_proof_iterative {
    my ($index, @leaf_digests) = @_;
    my @level = map { mt_leaf($_) } @leaf_digests;
    my @proof;
    my $i = $index;
    while (@level > 1) {
        my @next;
        for (my $j = 0; $j < @level; $j += 2) {
            if ($j + 1 < @level) {
                if    ($j     == $i) { push @proof, [ 'R', $level[$j + 1] ] }
                elsif ($j + 1 == $i) { push @proof, [ 'L', $level[$j] ] }
                push @next, mt_node($level[$j], $level[$j + 1]);
            } else {
                push @next, $level[$j];                       # promoted: no entry
            }
        }
        $i = int($i / 2);
        @level = @next;
    }
    return @proof;
}

# Fold a leaf digest through proof entries and return the resulting root.
sub merkle_fold_proof {
    my ($leaf_digest, @proof) = @_;
    my $h = mt_leaf($leaf_digest);
    for my $step (@proof) {
        my ($side, $sib) = @$step;
        $h = ($side eq 'L') ? mt_node($sib, $h) : mt_node($h, $sib);
    }
    return $h;
}

1;
