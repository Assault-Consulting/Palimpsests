#!/usr/bin/perl
# PALA-1 v1.0 §7.5 / §4.4 — body verification and decryption.
# Extras beyond the pass bar: recompute body_digest, decrypt the seq-3 body to
# the published plaintext, demonstrate the AAD position binding, decode the
# cleartext AGGREGATE body as a §3.2 TLV sequence, and crypto-shred.
use strict;
use utf8;
use warnings;
use lib 'verifier';
use PALA1;
use AESGCM;
use JSON::PP;
use Digest::SHA qw(sha256);

binmode(STDOUT, ':encoding(UTF-8)');

my $container_file = shift // 'chain.pala';
my $vectors_file   = shift // 'pala1-package/test-vectors.json';

local $/;
open my $vf, '<:raw', $vectors_file or die $!; my $V = JSON::PP->new->decode(<$vf>); close $vf;
open my $cf, '<:raw', $container_file or die $!; my $data = <$cf>; close $cf;

my ($pass, $fail) = (0, 0);
sub check {
    my ($label, $got, $want) = @_;
    my $ok = (defined $got && defined $want && "$got" eq "$want");
    $ok ? $pass++ : $fail++;
    printf "  [%s] %-56s %s\n", ($ok ? 'ok' : 'XX'), $label, $ok ? $got : "got=$got want=$want";
}

print "=" x 78, "\n";
print "AES-256-GCM self-test (FIPS-197 / SP 800-38D) before any PALA-1 claim\n";
print "=" x 78, "\n";
my @f = AESGCM::self_test();
check('all published NIST vectors pass', (@f ? join('; ', @f) : 'yes'), 'yes');

my $rep = PALA1::verify_chain($data);
my @R = @{ $rep->{records} };

print "\n", "=" x 78, "\n";
print "§7.5 body verification (needs the key)\n";
print "=" x 78, "\n";

# body_digest over exactly body_len bytes, for every record that has a body.
for my $rec (@R) {
    my $h = $rec->{header};
    next unless $h->{body_len} > 0;
    check(sprintf('seq %d: SHA-256(body) == body_digest over %d bytes', $h->{seq}, $h->{body_len}),
          (sha256($rec->{body_bytes}) eq $h->{body_digest}) ? 'match' : 'MISMATCH', 'match');
}

# --- §4.4 decryption of the seq-3 body ------------------------------------
my ($r3) = grep { $_->{header}{seq} == 3 } @R;
my $h3 = $r3->{header};
my $key = pack('H*', $V->{aes_key_hex});

check('seq 3 key_id matches the vectors', $h3->{key_id}, $V->{key_id});

# nonce = 4 zero bytes || seq (u64 LE)
my $nonce = ("\x00" x 4) . pack('Q<', $h3->{seq});
check('derived nonce matches the §8 worked example',
      unpack('H*', $nonce), '000000000300000000000000');
check('the nonce is INSIDE body_len, as the §2.3 warning says',
      (substr($r3->{body_bytes}, 0, 12) eq $nonce) ? 'yes' : 'no', 'yes');

# aad = seq (u64 LE) || boot_id (16) || record_type (u16 LE)
my $aad = pack('Q<', $h3->{seq}) . $h3->{boot_id} . pack('v', $h3->{record_type});
check('aad is 26 bytes (8 + 16 + 2)', length($aad), 26);

my $ct_and_tag = substr($r3->{body_bytes}, 12);
my $ct  = substr($ct_and_tag, 0, length($ct_and_tag) - 16);
my $tag = substr($ct_and_tag, -16);
check('body splits as nonce(12) || ciphertext || tag(16)',
      12 + length($ct) + 16, $h3->{body_len});

my $pt = AESGCM::decrypt($key, $nonce, $ct, $tag, $aad);
check('decrypts and authenticates', (defined $pt ? 'yes' : 'no'), 'yes');
if (defined $pt) {
    my $pt_chars = $pt;
    utf8::decode($pt_chars);
    check('plaintext == the published plaintext_utf8', $pt_chars, $V->{plaintext_utf8});
}

# --- the AAD position binding (§4.4) --------------------------------------
print "\n", "=" x 78, "\n";
print "§4.4 claims, demonstrated rather than assumed\n";
print "=" x 78, "\n";

# "bodies cannot be swapped between records" — decrypt seq 3's body under the
# AAD another record would supply.
my ($r5) = grep { $_->{header}{seq} == 5 } @R;
my $aad5 = pack('Q<', $r5->{header}{seq}) . $r5->{header}{boot_id}
         . pack('v', $r5->{header}{record_type});
check("the seq-3 body does NOT authenticate under seq 5's AAD",
      (defined AESGCM::decrypt($key, $nonce, $ct, $tag, $aad5) ? 'ACCEPTED' : 'rejected'),
      'rejected');

# same body, same key, but the AAD's seq field alone altered
my $aad_seq = pack('Q<', 4) . $h3->{boot_id} . pack('v', $h3->{record_type});
check('altering only the seq inside the AAD breaks authentication',
      (defined AESGCM::decrypt($key, $nonce, $ct, $tag, $aad_seq) ? 'ACCEPTED' : 'rejected'),
      'rejected');

# a one-bit flip in the ciphertext must fail the tag, not silently decrypt
my $ct_bad = $ct;
substr($ct_bad, 0, 1) = chr(ord(substr($ct_bad, 0, 1)) ^ 0x01);
check('a one-bit ciphertext flip is caught by the GCM tag',
      (defined AESGCM::decrypt($key, $nonce, $ct_bad, $tag, $aad) ? 'ACCEPTED' : 'rejected'),
      'rejected');

# crypto-shredding: the wrong key fails to decrypt while the digest still matches
my $wrong = AESGCM::decrypt("\x11" x 32, $nonce, $ct, $tag, $aad);
check('with the key destroyed: body unreadable...', (defined $wrong ? 'READABLE' : 'unreadable'),
      'unreadable');
check('...while body_digest still matches (§4.4)',
      (sha256($r3->{body_bytes}) eq $h3->{body_digest}) ? 'match' : 'MISMATCH', 'match');
check('...and the chain still verifies', ($rep->{chain_ok} ? 'true' : 'false'), 'true');

# re-encrypting the published plaintext must reproduce the published body bytes
if (defined $pt) {
    my ($t2, $c2) = AESGCM::encrypt($key, $nonce, $pt, $aad);
    check('re-encrypting the plaintext reproduces the exact body bytes',
          (($nonce . $c2 . $t2) eq $r3->{body_bytes}) ? 'byte-identical' : 'DIFFERS',
          'byte-identical');
}

# --- §3.2 AGGREGATE body, robotics profile §4 -----------------------------
print "\n", "=" x 78, "\n";
print "§3.2 AGGREGATE body as a TLV sequence (robotics profile §4)\n";
print "=" x 78, "\n";
my %AGG = (0x0001 => 'AGG_WINDOW_NS',        0x0002 => 'AGG_SAMPLE_COUNT',
           0x0003 => 'AGG_FLOW_MIN_MILLI',   0x0004 => 'AGG_FLOW_MAX_MILLI',
           0x0005 => 'AGG_FLOW_MEAN_MILLI');
check('AGGREGATE body is cleartext (key_id = 0, §3.2 SHOULD)', $r5->{header}{key_id}, 0);
my $b = $r5->{body_bytes};
my $off = 0;
my $ok_parse = 1;
while ($off < length($b)) {
    if ($off + 4 > length($b)) { $ok_parse = 0; last }
    my $t = unpack('v', substr($b, $off, 2));
    my $l = unpack('v', substr($b, $off + 2, 2));
    if ($off + 4 + $l > length($b)) { $ok_parse = 0; last }
    my $v = substr($b, $off + 4, $l);
    my $shown = $l == 8 ? unpack('Q<', $v) : $l == 4 ? unpack('V', $v)
              : $l == 2 ? unpack('v', $v) : unpack('H*', $v);
    printf "  [--] 0x%04x %-22s len=%-2d value=%s\n",
        $t, $AGG{$t} // '(profile-defined/unknown)', $l, $shown;
    $off += 4 + $l;
}
check('body TLVs parse and end exactly at body_len (§3.2, §2.2 encoding)',
      ($ok_parse && $off == length($b)) ? 'yes' : 'no', 'yes');

printf "\n  %d checks passed, %d failed\n\n", $pass, $fail;
exit($fail ? 1 : 0);
