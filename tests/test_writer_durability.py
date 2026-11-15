# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""When a record is on stable storage (``Durability``).

Until 0.15 the writer handed each record to the operating system and never
asked for it to be written out. A loss of power — an accident, or someone's
hand on the switch — then took the last half-minute of records and left a
shorter chain that verified. No test can cut the power; what is pinned here
is that the writer asks for the sync, when, and before what.

The suite replaces the two sync functions with counters (conftest.py), so
these tests read the counter. One test, marked ``real_sync``, goes to the
disk.
"""
from __future__ import annotations

import os
import pytest
import threading
import time
from palimpsests.audit import pala_writer
from palimpsests.audit.pala_writer import Durability, PalaWriter, RotationPolicy
from palimpsests.audit.reader import AuditReader

D = b"\x11" * 32


# ── the policy ──────────────────────────────────────────────────────────────


def test_the_default_is_every_record(tmp_path):
    with PalaWriter(tmp_path / "w.pala") as w:
        assert w.durability == Durability.RECORD
        w.genesis()
    with PalaWriter.open_existing(tmp_path / "w.pala") as w:
        assert w.durability == Durability.RECORD


def test_a_policy_is_spelled_in_one_way_and_a_typo_is_not_a_weaker_policy():
    assert Durability.parse("record") == Durability.RECORD
    assert Durability.parse(" OS ") == Durability.OS
    assert Durability.parse("group") == Durability.group(0.05)
    assert Durability.parse("group:0.2") == Durability.group(0.2)
    assert Durability.parse(Durability.OS) is Durability.OS
    assert str(Durability.group(0.2)) == "group:0.2" and str(Durability.RECORD) == "record"
    for bad in ("", "none", "off", "fsync", "record:1", "group:0", "group:-1", "group:x", 1):
        with pytest.raises(ValueError):
            Durability.parse(bad)
    with pytest.raises(ValueError):
        Durability("group")  # a group with no bound is not a bound
    with pytest.raises(ValueError):
        Durability("os", 1.0)


# ── every record ────────────────────────────────────────────────────────────


def test_each_record_is_synced_before_its_method_returns(tmp_path, _no_disk_sync):
    calls = _no_disk_sync
    with PalaWriter(tmp_path / "w.pala") as w:
        assert calls["dir"] == 1  # the new file's name, before any record
        for n, write in enumerate((w.genesis, w.boot, w.prefix_warm, w.anchor), 1):
            write()
            assert calls["file"] == n  # one sync per record, not one per batch


def test_the_sync_comes_after_the_bytes_and_before_the_return(tmp_path, monkeypatch):
    """The order that matters: at the moment of the sync the record is already
    in the file, whole — a sync of a file that lacks it would promise nothing."""
    path = tmp_path / "w.pala"
    seen = []
    monkeypatch.setattr(pala_writer, "_sync_file", lambda _fd: seen.append(path.stat().st_size))
    with PalaWriter(path) as w:
        w.genesis()
        after_genesis = path.stat().st_size
        w.tool_call("t", args_digest=D)
        after_call = path.stat().st_size
    assert seen[:2] == [after_genesis, after_call]


def test_a_writer_that_cannot_sync_says_so_and_does_not_fork_the_chain(tmp_path, monkeypatch):
    path = tmp_path / "w.pala"
    w = PalaWriter(path)
    w.genesis()
    w.boot()

    def fail(_fd):
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(pala_writer, "_sync_file", fail)
    with pytest.raises(OSError):
        w.prefix_warm()  # written; its durability not confirmed — the caller is told
    monkeypatch.setattr(pala_writer, "_sync_file", lambda _fd: None)
    w.prefix_warm()  # the writer is past the record it could not sync
    w.close()
    with AuditReader.open(path) as r:
        assert r.is_consistent() and r.record_count == 4


def test_close_syncs_releases_and_can_be_called_again(tmp_path, monkeypatch, _no_disk_sync):
    path = tmp_path / "w.pala"
    w = PalaWriter(path)
    w.genesis()
    before = _no_disk_sync["file"]
    w.close()
    assert _no_disk_sync["file"] == before + 1
    w.close()  # idempotent
    with PalaWriter.open_existing(path) as w2:  # the lock was released
        w2.boot()

    def fail(_fd):
        raise OSError(5, "Input/output error")

    w3 = PalaWriter.open_existing(path)
    w3.boot()
    monkeypatch.setattr(pala_writer, "_sync_file", fail)
    with pytest.raises(OSError):
        w3.close()
    monkeypatch.setattr(pala_writer, "_sync_file", lambda _fd: None)
    with PalaWriter.open_existing(path) as w4:  # a failing disk does not keep the lock
        w4.boot()


# ── the kernel decides ──────────────────────────────────────────────────────


def test_os_durability_never_syncs(tmp_path, _no_disk_sync):
    base = tmp_path / "w.pala"
    with PalaWriter(base, durability="os",
                    rotation=RotationPolicy(max_records=3)) as w:
        w.genesis()
        for _ in range(7):
            w.prefix_warm()
    assert _no_disk_sync == {"file": 0, "dir": 0}
    assert len(list(tmp_path.glob("w.pala.0*"))) >= 2  # it rotated, and still did not


# ── a bounded window ────────────────────────────────────────────────────────


def test_a_group_is_synced_once_within_its_bound_even_if_nothing_follows(
    tmp_path, _no_disk_sync
):
    calls = _no_disk_sync
    w = PalaWriter(tmp_path / "w.pala", durability=Durability.group(0.05))
    for write in (w.genesis, w.boot, w.prefix_warm):
        write()
    assert calls["file"] == 0  # three records, none synced yet
    deadline = time.monotonic() + 5
    while calls["file"] == 0 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert calls["file"] == 1  # one sync for the batch — with no fourth record to trigger it
    time.sleep(0.12)
    assert calls["file"] == 1  # and no timer left running over a clean file
    w.prefix_warm()
    w.close()
    assert calls["file"] == 2  # close does not wait for the timer


def test_a_group_under_load_syncs_far_less_often_than_it_writes(tmp_path, _no_disk_sync):
    w = PalaWriter(tmp_path / "w.pala", durability=Durability.group(0.05))
    w.genesis()
    w.boot()
    stop = time.monotonic() + 0.3
    counts = [0, 0, 0, 0]  # one per thread: no shared counter to race on

    def work(i):
        while time.monotonic() < stop:
            w.tool_call("t", args_digest=D)
            counts[i] += 1

    threads = [threading.Thread(target=work, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    w.close()
    written = sum(counts)
    assert written > 100
    assert _no_disk_sync["file"] <= 12  # ~0.3 s / 0.05 s, plus close; not once per record
    with AuditReader.open(tmp_path / "w.pala") as r:
        assert r.is_consistent() and r.record_count == written + 2


# ── a cut ───────────────────────────────────────────────────────────────────


def test_a_cut_leaves_the_old_segment_and_the_manifest_synced(tmp_path, monkeypatch):
    """The cut's own crash-ordering argument assumes its first step — the
    manifest records the closed segment — is true on disk. It was not synced."""
    events = []
    monkeypatch.setattr(pala_writer, "_sync_file", lambda fd: events.append(("file", fd)))
    monkeypatch.setattr(pala_writer, "_sync_dir",
                        lambda p: events.append(("dir", os.path.basename(p))))
    base = tmp_path / "w.pala"
    with PalaWriter(base, rotation=RotationPolicy(max_records=3)) as w:
        w.genesis()
        w.prefix_warm()
        events.clear()
        w.prefix_warm()  # the third record: the cut follows it
    names = [name for kind, name in events if kind == "dir"]
    assert "w.pala.segments.json" in names  # the manifest's name
    assert "w.pala.00001" in names  # the successor's name
    assert names.index("w.pala.segments.json") < names.index("w.pala.00001")
    assert sum(1 for kind, _ in events if kind == "file") >= 3  # record, manifest, old segment


# ── the disk, once ──────────────────────────────────────────────────────────


@pytest.mark.real_sync
def test_the_real_sync_runs_on_this_platform(tmp_path):
    """Everything above counts calls. This one makes them: the file sync, the
    macOS full sync where there is one, and the directory sync where the
    platform has it — on each operating system CI runs."""
    base = tmp_path / "w.pala"
    for policy in (Durability.RECORD, Durability.group(0.02)):
        path = tmp_path / f"{policy.mode}.pala"
        with PalaWriter(path, durability=policy, rotation=RotationPolicy(max_records=3)) as w:
            w.genesis()
            for _ in range(5):
                w.tool_call("t", args_digest=D)
        whole = b"".join(p.read_bytes() for p in [path, *sorted(tmp_path.glob(f"{path.name}.0*"))])
        with AuditReader.from_bytes(whole) as r:
            assert r.is_consistent() and r.record_count >= 6
    pala_writer._sync_dir(str(base))  # a directory that exists; must not raise
    pala_writer._sync_dir(str(tmp_path / "no" / "such" / "dir" / "x"))  # nor one that does not
