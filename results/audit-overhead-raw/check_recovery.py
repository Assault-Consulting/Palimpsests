"""Point 4 behavioural checks: torn-tail recovery vs mid-stream rejection.

- Torn tail: append an incomplete trailing record (b"PALA" + a few bytes) to a
  valid log. open_existing(recover_torn_tail=True) MUST truncate the torn tail
  and record RECOVERY_TRUNCATED_TAIL. Confirmed via recovered_tail_bytes() and by
  scanning the resumed file for the recovery record (independent header parse —
  no reference codec).
- Mid-stream damage: flip a bit *inside* the file (not the tail). open_existing
  MUST refuse (raise), not auto-heal. The actual exception is recorded.
"""

import json
import os
from palimpsests.providers.native import PalaWriter

RAW = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(RAW, "openx_files")
os.makedirs(WORK, exist_ok=True)
D32 = bytes(range(32))
SPAN = b"\x00" * 16

# From the allowed spec/profile docs (not the reference codec):
#   record_type EVENT = 0x0012 (§3); EVENT body is a TLV sequence with
#   EVT_KIND = TLV type 0x0001 (u16); RECOVERY_TRUNCATED_TAIL = EVT_KIND 7
#   (inference profile §3, kind 7). So the recovery record is an EVENT whose
#   body EVT_KIND == 7 — parsed independently below.
RT_EVENT = 0x0012
EVT_KIND_RECOVERY_TRUNCATED_TAIL = 7


def make_valid_log(path, n_sessions=200):
    if os.path.exists(path):
        os.remove(path)
    w = PalaWriter(path)
    w.genesis()
    w.boot()
    w.model_load(D32, D32)
    for i in range(n_sessions):
        w.session_start(f"s{i}")
        w.kv_save(D32, span_id=SPAN)
        w.session_end(SPAN)
    w.close()
    return os.path.getsize(path)


def scan_records(path):
    """Independent walk of a §2.4 container: header_len @ off+6 (u16 LE),
    record_type @ off+8 (u16 LE), body_len @ off+120 (u32 LE). For EVENT records,
    also read EVT_KIND (first body TLV: type 0x0001 u16, value u16). Returns list
    of (record_type, evt_kind_or_None, offset). Not the reference codec."""
    recs = []
    data = open(path, "rb").read()
    off = 0
    while off + 156 <= len(data):
        if data[off : off + 4] != b"PALA":
            break
        header_len = int.from_bytes(data[off + 6 : off + 8], "little")
        rtype = int.from_bytes(data[off + 8 : off + 10], "little")
        body_len = int.from_bytes(data[off + 120 : off + 124], "little")
        evt_kind = None
        if rtype == RT_EVENT and body_len >= 6:
            body = data[off + header_len : off + header_len + body_len]
            t = int.from_bytes(body[0:2], "little")
            length = int.from_bytes(body[2:4], "little")
            if t == 0x0001 and length >= 2:
                evt_kind = int.from_bytes(body[4:6], "little")
        recs.append((rtype, evt_kind, off))
        step = header_len + body_len
        if step <= 0:
            break
        off += step
    return recs


def torn_tail_check():
    path = os.path.join(WORK, "torn.pala")
    make_valid_log(path)
    good_size = os.path.getsize(path)
    good_recs = scan_records(path)
    # append an incomplete trailing record: magic + a few stray bytes
    torn_bytes = b"PALA" + b"\x01\x02\x03\x04\x05"
    with open(path, "ab") as fh:
        fh.write(torn_bytes)
    torn_size = os.path.getsize(path)

    w = PalaWriter.open_existing(path, recover_torn_tail=True)
    recovered = w.recovered_tail_bytes
    # cross-boot resume requires BOOT first; the recovery record is caller-driven
    # (recovery_truncated_tail(), profile §3 kind 7) — written right after BOOT.
    w.boot()
    if recovered:
        w.recovery_truncated_tail()
    head, seq = w.head_hex, w.seq
    w.close()

    after_recs = scan_records(path)
    new_recs = after_recs[len(good_recs) :]
    return {
        "good_size": good_size,
        "torn_added_bytes": torn_size - good_size,
        "recovered_tail_bytes": recovered,
        "recovered_matches_torn": recovered == len(torn_bytes),
        "resumed_head": head,
        "resumed_seq": seq,
        "new_records_after_resume": [(hex(t), k) for t, k, _ in new_recs],
        "recovery_event_present": any(
            t == RT_EVENT and k == EVT_KIND_RECOVERY_TRUNCATED_TAIL for t, k, _ in new_recs
        ),
    }


def mid_stream_check():
    path = os.path.join(WORK, "midstream.pala")
    make_valid_log(path)
    recs = scan_records(path)
    # Corrupt the MAGIC of a mid-stream record: this makes that record
    # structurally incomplete while leaving many valid records AFTER it, so it is
    # not a clean torn tail. open_existing "walks to the last complete record"; a
    # break in the middle with valid data after must be refused, not silently
    # truncated (which would drop the trailing valid records).
    mid = recs[len(recs) // 2]
    pos = mid[2]  # first byte of "PALA" magic of the mid record
    with open(path, "r+b") as fh:
        fh.seek(pos)
        b = fh.read(1)
        fh.seek(pos)
        fh.write(bytes([b[0] ^ 0x01]))
    outcome = {
        "flipped_record_index": len(recs) // 2,
        "flipped_at": pos,
        "records_after_damage": len(recs) - len(recs) // 2 - 1,
    }
    try:
        w = PalaWriter.open_existing(path, recover_torn_tail=True)
        outcome["rejected"] = False
        outcome["resumed_seq"] = w.seq
        outcome["note"] = "open_existing did NOT raise on a broken mid-stream link"
        w.close()
    except Exception as e:  # noqa: BLE001
        outcome["rejected"] = True
        outcome["exception_type"] = type(e).__name__
        outcome["exception_msg"] = str(e)[:200]
    return outcome


def main():
    out = {"torn_tail": torn_tail_check(), "mid_stream": mid_stream_check()}
    with open(os.path.join(RAW, "recovery_checks.json"), "w") as fh:
        json.dump(out, fh, indent=2)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
