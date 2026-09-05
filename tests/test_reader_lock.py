# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""U14 PR-9 — the reader's own lock.

Before: ``verify()`` on a cold reader was "not thread-safe, and the cache
is what makes that matter" — N concurrent callers each ran the whole
pass and each held their own transient state. Now every cache-filling
path (``verify()``, the full decode, the sparse decode) takes one
re-entrant lock: the first caller fills, the rest read. Pinned:

* eight threads calling ``verify()`` on a cold reader get the very
  same ``Verification`` object, and the referential pass ran once;
* eight threads calling ``records()`` get the same list object, decoded
  once;
* mixed callers (``verify``, ``structure``, ``safety_records``,
  ``records``) on one cold reader all agree and none raises;
* a caller already holding the lock can still call in (re-entrancy) —
  which is what ``verify()`` needs when its referential pass decodes
  through ``_record_at``.
"""
from __future__ import annotations

import threading
from palimpsests.audit.pala_writer import DISP_ACKNOWLEDGED, PalaWriter
from palimpsests.audit.reader import AuditReader
from pathlib import Path

OPERATOR = b"\x0e" * 16


def _chain(tmp_path: Path, n: int = 2000) -> Path:
    log = tmp_path / "lock.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        s = w.session_start("s1")
        for i in range(n):
            w.kv_save(bytes([i % 256]) * 32)
            if i % 200 == 0:
                cand = w.incident_candidate(1, 2)
                w.oversight_ack(w.seq - 1, cand, DISP_ACKNOWLEDGED, OPERATOR)
        w.session_end(s)
    return log


def _run_threads(fn, count: int = 8):
    results = [None] * count
    errors = []
    barrier = threading.Barrier(count)

    def worker(i):
        try:
            barrier.wait()
            results[i] = fn()
        except Exception as e:  # pragma: no cover - surfaced by the assert
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not errors, errors
    return results


def test_concurrent_verify_runs_the_pass_once(tmp_path, monkeypatch):
    r = AuditReader.open(_chain(tmp_path))
    calls = {"referential": 0}
    original = AuditReader._referential_advisories

    def counted(self):
        calls["referential"] += 1
        return original(self)

    monkeypatch.setattr(AuditReader, "_referential_advisories", counted)
    results = _run_threads(r.verify)
    assert all(v is results[0] for v in results), "one Verification, shared"
    assert calls["referential"] == 1
    assert results[0].chain.chain_ok
    r.close()


def test_concurrent_records_decodes_once(tmp_path, monkeypatch):
    r = AuditReader.open(_chain(tmp_path))
    calls = {"decode": 0}
    original = AuditReader._decode

    def counted(self, index, hb):
        calls["decode"] += 1
        return original(self, index, hb)

    monkeypatch.setattr(AuditReader, "_decode", counted)
    results = _run_threads(lambda: list(r.records()))
    assert all(v == results[0] for v in results)
    assert calls["decode"] == len(r._headers)
    r.close()


def test_mixed_callers_on_a_cold_reader_agree(tmp_path):
    path = _chain(tmp_path)
    r = AuditReader.open(path)
    fns = [
        lambda: ("verify", r.verify().chain.head),
        lambda: ("structure", len(r.structure()[0]), len(r.structure()[1])),
        lambda: ("safety", sum(1 for _ in r.safety_records())),
        lambda: ("records", sum(1 for _ in r.records())),
    ] * 2
    results = _run_threads(lambda: [f() for f in fns], count=6)
    assert all(v == results[0] for v in results)
    # and equal to a single-threaded reading of the same file
    solo = AuditReader.open(path)
    expected = [
        ("verify", solo.verify().chain.head),
        ("structure", len(solo.structure()[0]), len(solo.structure()[1])),
        ("safety", sum(1 for _ in solo.safety_records())),
        ("records", sum(1 for _ in solo.records())),
    ] * 2
    assert results[0] == expected
    r.close()
    solo.close()


def test_lock_is_reentrant_for_the_holder(tmp_path):
    r = AuditReader.open(_chain(tmp_path))
    with r._lock:
        ver = r.verify()  # verify → referential pass → _record_at, same thread
        assert ver.chain.chain_ok
        assert r._partial  # the sparse cache filled under the held lock
    r.close()
