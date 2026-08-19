#!/usr/bin/perl
# PALA-1 v1.0 — does the §8 narrative table match the bytes the vectors ship?
# The kit names "a demo that encodes something other than what its prose
# claims" as a defect category, so every claim in the §8 table, and every
# TLV the prose attributes to a record, is checked against the container.
use strict;
use utf8;
use warnings;
use lib 'verifier';
use PALA1;
use JSON::PP;

binmode(STDOUT, ':encoding(UTF-8)');

my $container_file = shift // 'chain.pala';
local $/;
open my $cf, '<:raw', $container_file or die $!; my $data = <$cf>; close $cf;

my $rep = PALA1::verify_chain($data);
my @R = @{ $rep->{records} };
my %BY_SEQ = map { $_->{header}{seq} => $_ } @R;

my ($pass, $fail) = (0, 0);
sub check {
    my ($label, $got, $want) = @_;
    my $ok = (defined $got && defined $want && "$got" eq "$want");
    $ok ? $pass++ : $fail++;
    printf "  [%s] %-58s %s\n", ($ok ? 'ok' : 'XX'), $label, $ok ? $got : "got=$got want=$want";
}
sub tlv { my ($seq, $t) = @_; return PALA1::tlv_value($BY_SEQ{$seq}, $t) }
sub tlv_u16 { my $v = tlv(@_); return defined $v ? unpack('v', $v) : undef }
sub tlv_u32 { my $v = tlv(@_); return defined $v ? unpack('V', $v) : undef }
sub tlv_u64 { my $v = tlv(@_); return defined $v ? unpack('Q<', $v) : undef }
sub tlv_str { my $v = tlv(@_); return undef unless defined $v; utf8::decode($v); return $v }

my %TYPE_NAME = %PALA1::RECORD_TYPE;

print "=" x 78, "\n";
print "§8 narrative table vs. the bytes\n";
print "=" x 78, "\n";

# The §8 table: seq -> type name.
my @narrative = (
    [ 0,  'GENESIS'   ], [ 1,  'BOOT'      ], [ 2,  'SPAN_START' ],
    [ 3,  'EVENT'     ], [ 4,  'MERKLE'    ], [ 5,  'AGGREGATE'  ],
    [ 6,  'SAFETY'    ], [ 7,  'SHED'      ], [ 8,  'SPAN_END'   ],
    [ 9,  'ANCHOR'    ], [ 10, 'WITNESS'   ], [ 11, 'KEY_SHRED'  ],
);
for my $n (@narrative) {
    my ($seq, $want) = @$n;
    my $got = $TYPE_NAME{ $BY_SEQ{$seq}{header}{record_type} } // 'unknown';
    check(sprintf('seq %-2d is a %s', $seq, $want), $got, $want);
}

print "\n  per-record claims in the §8 table\n";
# seq 0: "tier A, time UNKNOWN"
check('seq 0 assurance_tier = A (0)', $BY_SEQ{0}{header}{assurance_tier}, 0);
check('seq 0 time_trust = UNKNOWN (0)', $BY_SEQ{0}{header}{time_trust}, 0);
check('seq 0 prev_hash is 32 zero bytes (§4.2)',
      (($BY_SEQ{0}{header}{prev_hash} eq "\x00" x 32) ? 'yes' : 'no'), 'yes');
# seq 1: "wall_clock_ns = 0, time_trust = UNSYNCED"
check('seq 1 wall_clock_ns = 0', $BY_SEQ{1}{header}{wall_clock_ns}, 0);
check('seq 1 time_trust = UNSYNCED (1)', $BY_SEQ{1}{header}{time_trust}, 1);
# seq 2: "brain" span
check('seq 2 ORIGIN_ROLE = brain (robotics profile §1)', tlv_str(2, 0x0001), 'brain');
check('seq 2 opens a span (span_id non-zero)',
      (($BY_SEQ{2}{header}{span_id} ne "\x00" x 16) ? 'yes' : 'no'), 'yes');
# seq 3: "AES-GCM body, key_id = 7, origin = eyes.tier1 + digests"
check('seq 3 key_id = 7', $BY_SEQ{3}{header}{key_id}, 7);
check('seq 3 ORIGIN_ROLE = eyes.tier1', tlv_str(3, 0x0001), 'eyes.tier1');
check('seq 3 ORIGIN_MODEL_DIGEST present and 32 bytes',
      (defined tlv(3, 0x0002) ? length(tlv(3, 0x0002)) : 'absent'), 32);
check('seq 3 ORIGIN_CONFIG_DIGEST present and 32 bytes',
      (defined tlv(3, 0x0003) ? length(tlv(3, 0x0003)) : 'absent'), 32);
check('seq 3 is in a CHILD span whose parent is the brain span (§2.1)',
      (($BY_SEQ{3}{header}{parent_span_id} eq $BY_SEQ{2}{header}{span_id}) ? 'yes' : 'no'), 'yes');
check('seq 2 brain span is a root span (parent_span_id zero = root, §2.1)',
      (($BY_SEQ{2}{header}{parent_span_id} eq "\x00" x 16) ? 'yes' : 'no'), 'yes');
# seq 4: "30 frame digests"
check('seq 4 MERKLE_LEAF_COUNT = 30', tlv_u32(4, 0x0012), 30);
check('seq 4 MERKLE_TREE_HASH is 32 bytes',
      (defined tlv(4, 0x0011) ? length(tlv(4, 0x0011)) : 'absent'), 32);
check('seq 4 body_len = 0 (commits without carrying, §4.3)',
      $BY_SEQ{4}{header}{body_len}, 0);
# seq 5: "cleartext TLV body, key_id = 0"
check('seq 5 key_id = 0 (cleartext)', $BY_SEQ{5}{header}{key_id}, 0);
check('seq 5 has a body', (($BY_SEQ{5}{header}{body_len} > 0) ? 'yes' : 'no'), 'yes');
# seq 6: "divergence, origin = perception_health"
check('seq 6 ORIGIN_ROLE = perception_health', tlv_str(6, 0x0001), 'perception_health');
# seq 7: "class 1, 400 records, 12 s window"
check('seq 7 SHED_CLASS = 1', tlv_u16(7, 0x0020), 1);
check('seq 7 SHED_COUNT = 400', tlv_u32(7, 0x0021), 400);
check('seq 7 SHED_WINDOW_NS = 12 s', tlv_u64(7, 0x0022), 12_000_000_000);
# seq 8: span close
check('seq 8 closes the same span (span_id matches seq 2)',
      (($BY_SEQ{8}{header}{span_id} eq $BY_SEQ{2}{header}{span_id}) ? 'yes' : 'no'), 'yes');
# seq 9: "carries the head anchored at seq 8"
check('seq 9 ANCHOR_HEAD == record_hash of seq 8',
      ((tlv(9, 0x0050) // '') eq $BY_SEQ{8}{record_hash} ? 'yes' : 'no'), 'yes');
check('seq 9 ANCHOR_HEAD is the value §8 prints',
      unpack('H*', tlv(9, 0x0050) // ''),
      '14434088e5f5866cf0276ba5a9055d8ee0d115a750b2cdf9cc4006d9481b29b4');
# seq 10: "transparency log, covers seq 0-9"
check('seq 10 WITNESS_KIND = 1 (transparency log)', tlv_u16(10, 0x0030), 1);
check('seq 10 WITNESS_RANGE_LO = 0', tlv_u64(10, 0x0031), 0);
check('seq 10 WITNESS_RANGE_HI = 9', tlv_u64(10, 0x0032), 9);
check('seq 10 WITNESS_RECEIPT present',
      (defined tlv(10, 0x0033) ? 'yes' : 'no'), 'yes');
# seq 11: "key 7 destroyed"
check('seq 11 SHRED_KEY_ID = 7', tlv_u32(11, 0x0040), 7);

print "\n  cross-cutting envelope claims\n";
check('all 12 records carry the same boot_id (one boot after GENESIS)',
      (scalar(keys %{ { map { unpack('H*', $_->{header}{boot_id}) => 1 }
                        grep { $_->{header}{seq} >= 1 } @R } }) == 1) ? 'yes' : 'no', 'yes');
check('every record declares format_version = 1',
      (scalar(grep { $_->{header}{format_version} == 1 } @R)), 12);
check('every header_len >= 156 and equals its actual byte count (§2.1)',
      (scalar(grep { $_->{header}{header_len} >= 156
                     && $_->{header}{header_len} == length($_->{header_bytes}) } @R)), 12);
check('seq increases by exactly 1 across the chain (§4.1)',
      (join(',', map { $_->{header}{seq} } @R)), join(',', 0 .. 11));
check('every record after seq 0 links to its predecessor (§4.1)',
      (scalar(grep { $R[$_]{header}{prev_hash} eq $R[$_ - 1]{record_hash} } 1 .. $#R)), 11);
check('the never-shed classes are all present (§3: SHED, SAFETY, ANCHOR, WITNESS, KEY_SHRED)',
      (scalar(grep { my $t = $_->{header}{record_type};
                     grep { $t == $_ } (0x0030, 0x0040, 0x0050, 0x0051, 0x0060) } @R)), 5);
check('monotonic_ns is non-decreasing (§5: authoritative for ordering)',
      (scalar(grep { $R[$_]{header}{monotonic_ns} >= $R[$_ - 1]{header}{monotonic_ns} } 1 .. $#R)),
      11);
check('no record carries a wall clock it cannot justify (§5)',
      (scalar(grep { $_->{header}{time_trust} == 0 && $_->{header}{wall_clock_ns} != 0 } @R)), 0);

print "\n", "=" x 78, "\n";
print "span structure (§3.1) — observation, not a §7 check\n";
print "=" x 78, "\n";
my (%opened, %closed, %referenced);
for my $r (@R) {
    my $h = $r->{header};
    my $sid = unpack('H*', $h->{span_id});
    next if $sid =~ /^0+$/;
    $referenced{$sid}++;
    $opened{$sid} = $h->{seq} if $h->{record_type} == 0x0010;   # SPAN_START
    $closed{$sid} = $h->{seq} if $h->{record_type} == 0x0011;   # SPAN_END
}
for my $sid (sort keys %referenced) {
    printf "  span %s...  referenced by %d record(s), SPAN_START=%s SPAN_END=%s\n",
        substr($sid, 0, 12), $referenced{$sid},
        (exists $opened{$sid} ? "seq $opened{$sid}" : 'NONE'),
        (exists $closed{$sid} ? "seq $closed{$sid}" : 'NONE');
}
my @unopened = grep { !exists $opened{$_} } sort keys %referenced;
printf "  spans referenced with no SPAN_START in the chain: %s\n",
    (@unopened ? join(', ', map { substr($_, 0, 12) . '...' } @unopened) : 'none');
print "  §7 defines no span-pairing check, so a conformant verifier reports nothing here.\n";

printf "\n  %d checks passed, %d failed\n\n", $pass, $fail;
exit($fail ? 1 : 0);
