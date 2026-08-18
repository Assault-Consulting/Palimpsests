package AESGCM;
# ---------------------------------------------------------------------------
# AES-256-GCM, written from FIPS-197 (AES) and NIST SP 800-38D (GCM) for the
# §4.4 extra of the PALA-1 verification exercise. No crypto library is
# available in this environment, so the cipher is implemented here from the
# standards' definitions. Perl core only.
#
# Correctness is self-checked against the NIST GCM test vectors in
# self_test() before it is used on any PALA-1 body.
# ---------------------------------------------------------------------------
use strict;
use warnings;

# --- GF(2^8) arithmetic, FIPS-197 §4 --------------------------------------
sub _xtime { my $b = shift; $b <<= 1; $b = ($b ^ 0x1b) & 0xff if $b & 0x100; return $b & 0xff }
sub _gmul {
    my ($a, $b) = @_;
    my $p = 0;
    for (1 .. 8) {
        $p ^= $a if $b & 1;
        $a = _xtime($a);
        $b >>= 1;
    }
    return $p & 0xff;
}

# S-box built from its definition (multiplicative inverse + affine map),
# rather than pasted as a table, so it is auditable against FIPS-197 §5.1.1.
my (@SBOX, @INV);
{
    # multiplicative inverses in GF(2^8)
    my @inv = (0) x 256;
    for my $a (1 .. 255) {
        for my $b (1 .. 255) {
            if (_gmul($a, $b) == 1) { $inv[$a] = $b; last }
        }
    }
    for my $i (0 .. 255) {
        my $b = $inv[$i];
        my $s = $b;
        for my $r (1 .. 4) { $s ^= (($b << $r) | ($b >> (8 - $r))) & 0xff }
        $SBOX[$i] = ($s ^ 0x63) & 0xff;
    }
}

sub _sub_word {
    my $w = shift;
    return ($SBOX[($w >> 24) & 0xff] << 24) | ($SBOX[($w >> 16) & 0xff] << 16)
         | ($SBOX[($w >>  8) & 0xff] <<  8) |  $SBOX[$w & 0xff];
}
sub _rot_word { my $w = shift; return (($w << 8) | ($w >> 24)) & 0xffffffff }

# --- AES-256 key expansion, FIPS-197 §5.2 ---------------------------------
sub _expand_key {
    my ($key) = @_;
    die 'AES-256 needs a 32-byte key' unless length($key) == 32;
    my $Nk = 8;
    my $Nr = 14;
    my @w = unpack('N8', $key);
    my @rcon = (0, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
                0x10000000, 0x20000000, 0x40000000);
    for my $i ($Nk .. 4 * ($Nr + 1) - 1) {
        my $t = $w[$i - 1];
        if    ($i % $Nk == 0) { $t = _sub_word(_rot_word($t)) ^ $rcon[$i / $Nk] }
        elsif ($i % $Nk == 4) { $t = _sub_word($t) }
        $w[$i] = $w[$i - $Nk] ^ $t;
    }
    return \@w;
}

# --- AES block encryption, FIPS-197 §5.1 ----------------------------------
sub _encrypt_block {
    my ($w, $in) = @_;
    my @s = unpack('C16', $in);
    my $Nr = 14;

    my $add_round_key = sub {
        my ($round) = @_;
        for my $c (0 .. 3) {
            my $k = $w->[$round * 4 + $c];
            $s[4 * $c + 0] ^= ($k >> 24) & 0xff;
            $s[4 * $c + 1] ^= ($k >> 16) & 0xff;
            $s[4 * $c + 2] ^= ($k >>  8) & 0xff;
            $s[4 * $c + 3] ^=  $k        & 0xff;
        }
    };

    $add_round_key->(0);
    for my $round (1 .. $Nr) {
        @s = map { $SBOX[$_] } @s;                              # SubBytes
        my @t = @s;                                             # ShiftRows
        for my $r (1 .. 3) {
            for my $c (0 .. 3) { $t[4 * $c + $r] = $s[4 * (($c + $r) % 4) + $r] }
        }
        @s = @t;
        if ($round != $Nr) {                                    # MixColumns
            my @u = @s;
            for my $c (0 .. 3) {
                my @a = @s[4 * $c .. 4 * $c + 3];
                $u[4 * $c + 0] = _gmul($a[0], 2) ^ _gmul($a[1], 3) ^ $a[2] ^ $a[3];
                $u[4 * $c + 1] = $a[0] ^ _gmul($a[1], 2) ^ _gmul($a[2], 3) ^ $a[3];
                $u[4 * $c + 2] = $a[0] ^ $a[1] ^ _gmul($a[2], 2) ^ _gmul($a[3], 3);
                $u[4 * $c + 3] = _gmul($a[0], 3) ^ $a[1] ^ $a[2] ^ _gmul($a[3], 2);
            }
            @s = @u;
        }
        $add_round_key->($round);
    }
    return pack('C16', @s);
}

# --- GHASH, SP 800-38D §6.3 -----------------------------------------------
# Blocks are 128-bit strings, bit 0 = most significant bit of byte 0.
sub _gf_mul {
    my ($X, $Y) = @_;
    my @z = (0) x 16;
    my @v = unpack('C16', $Y);
    my @x = unpack('C16', $X);
    for my $i (0 .. 127) {
        if ($x[$i >> 3] & (0x80 >> ($i & 7))) {
            $z[$_] ^= $v[$_] for 0 .. 15;
        }
        my $lsb = $v[15] & 1;
        for (my $j = 15; $j > 0; $j--) {
            $v[$j] = (($v[$j] >> 1) | (($v[$j - 1] & 1) << 7)) & 0xff;
        }
        $v[0] >>= 1;
        $v[0] ^= 0xe1 if $lsb;                    # R = 11100001 || 0^120
    }
    return pack('C16', @z);
}

sub _ghash {
    my ($H, $data) = @_;
    my $Y = "\x00" x 16;
    for (my $i = 0; $i < length($data); $i += 16) {
        my $blk = substr($data, $i, 16);
        $blk .= "\x00" x (16 - length($blk)) if length($blk) < 16;
        $Y = _gf_mul($Y ^ $blk, $H);
    }
    return $Y;
}

sub _inc32 {
    my ($blk) = @_;
    my $ctr = unpack('N', substr($blk, 12, 4));
    return substr($blk, 0, 12) . pack('N', ($ctr + 1) & 0xffffffff);
}

sub _gctr {
    my ($w, $icb, $data) = @_;
    return '' unless length $data;
    my $out = '';
    my $cb = $icb;
    for (my $i = 0; $i < length($data); $i += 16) {
        my $blk = substr($data, $i, 16);
        my $ks  = _encrypt_block($w, $cb);
        $out .= $blk ^ substr($ks, 0, length($blk));
        $cb = _inc32($cb);
    }
    return $out;
}

sub _pad16 { my $n = length($_[0]) % 16; return $n ? "\x00" x (16 - $n) : '' }

# Returns (tag, ciphertext) — SP 800-38D §7.1
sub encrypt {
    my ($key, $iv, $plaintext, $aad) = @_;
    $aad //= '';
    die 'this implementation supports 96-bit IVs only' unless length($iv) == 12;
    my $w = _expand_key($key);
    my $H  = _encrypt_block($w, "\x00" x 16);
    my $J0 = $iv . "\x00\x00\x00\x01";
    my $C  = _gctr($w, _inc32($J0), $plaintext);
    my $S  = _ghash($H, $aad . _pad16($aad) . $C . _pad16($C)
                        . pack('NN', 0, 8 * length($aad))
                        . pack('NN', 0, 8 * length($C)));
    my $T = substr(_gctr($w, $J0, $S), 0, 16);
    return ($T, $C);
}

# Returns plaintext, or undef if the tag does not authenticate — §7.2
sub decrypt {
    my ($key, $iv, $ciphertext, $tag, $aad) = @_;
    $aad //= '';
    die 'this implementation supports 96-bit IVs only' unless length($iv) == 12;
    my $w = _expand_key($key);
    my $H  = _encrypt_block($w, "\x00" x 16);
    my $J0 = $iv . "\x00\x00\x00\x01";
    my $S  = _ghash($H, $aad . _pad16($aad) . $ciphertext . _pad16($ciphertext)
                        . pack('NN', 0, 8 * length($aad))
                        . pack('NN', 0, 8 * length($ciphertext)));
    my $T = substr(_gctr($w, $J0, $S), 0, 16);
    return undef unless $T eq $tag;                       # authenticate first
    return _gctr($w, _inc32($J0), $ciphertext);
}

# --- self-test against published NIST vectors -----------------------------
# Until these pass, nothing this module says about a PALA-1 body is evidence.
sub self_test {
    my @fail;

    # FIPS-197 Appendix C.3 — AES-256 known-answer test.
    my $key = pack('H*', '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    my $pt  = pack('H*', '00112233445566778899aabbccddeeff');
    my $ct  = unpack('H*', _encrypt_block(_expand_key($key), $pt));
    push @fail, "FIPS-197 C.3 AES-256 block: got $ct"
        unless $ct eq '8ea2b7ca516745bfeafc49904b496089';

    # SP 800-38D GCM test case 13 (AES-256, empty P and A).
    my ($t13, $c13) = encrypt("\x00" x 32, "\x00" x 12, '', '');
    push @fail, 'GCM case 13 tag: got ' . unpack('H*', $t13)
        unless unpack('H*', $t13) eq '530f8afbc74536b9a963b4f1c4cb738b';

    # SP 800-38D GCM test case 14 (AES-256, one zero block).
    my ($t14, $c14) = encrypt("\x00" x 32, "\x00" x 12, "\x00" x 16, '');
    push @fail, 'GCM case 14 ct: got ' . unpack('H*', $c14)
        unless unpack('H*', $c14) eq 'cea7403d4d606b6e074ec5d3baf39d18';
    push @fail, 'GCM case 14 tag: got ' . unpack('H*', $t14)
        unless unpack('H*', $t14) eq 'd0d1c8a799996bf0265b98b5d48ab919';

    # SP 800-38D GCM test case 16 (AES-256, with AAD, truncated plaintext).
    my $k16 = pack('H*', 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308');
    my $p16 = pack('H*', 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72'
                       . '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39');
    my $a16 = pack('H*', 'feedfacedeadbeeffeedfacedeadbeefabaddad2');
    my ($t16, $c16) = encrypt($k16, pack('H*', 'cafebabefacedbaddecaf888'), $p16, $a16);
    push @fail, 'GCM case 16 ct: got ' . unpack('H*', $c16)
        unless unpack('H*', $c16) eq
            '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa'
          . '8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662';
    push @fail, 'GCM case 16 tag: got ' . unpack('H*', $t16)
        unless unpack('H*', $t16) eq '76fc6ece0f4e1768cddf8853bb2d551b';

    # Round trip, and a tag that must be rejected.
    my $rt = decrypt($k16, pack('H*', 'cafebabefacedbaddecaf888'), $c16, $t16, $a16);
    push @fail, 'round trip failed' unless defined $rt && $rt eq $p16;
    my $bad = decrypt($k16, pack('H*', 'cafebabefacedbaddecaf888'), $c16, $t16,
                      $a16 . "\x00");
    push @fail, 'a wrong AAD was accepted' if defined $bad;

    return @fail;
}

1;
