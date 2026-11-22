# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0
"""scripts/compare_dist.py tells compression apart from contents."""

from __future__ import annotations

import importlib.util
import io
import tarfile
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "compare_dist.py"
spec = importlib.util.spec_from_file_location("compare_dist_under_test", SCRIPT)
assert spec is not None and spec.loader is not None
compare_dist = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compare_dist)

FILES = {"pkg/__init__.py": b"x = 1\n" * 200, "pkg/data.txt": b"abc" * 500}


def _wheel(path: Path, files: dict[str, bytes], level: int) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=level) as archive:
        for name, data in files.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 11, 22, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=level)
    return path


def _sdist(path: Path, files: dict[str, bytes], level: int) -> Path:
    with tarfile.open(path, "w:gz", compresslevel=level) as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(data), 1_795_000_000, 0o644
            archive.addfile(info, io.BytesIO(data))
    return path


def test_identical_files_are_the_same_bytes(tmp_path: Path) -> None:
    a = _wheel(tmp_path / "a.whl", FILES, 6)
    assert compare_dist.compare(a, a) == (0, ["same bytes"])


def test_a_wheel_compressed_differently_has_the_same_contents(tmp_path: Path) -> None:
    a = _wheel(tmp_path / "a.whl", FILES, 1)
    b = _wheel(tmp_path / "b.whl", FILES, 9)
    assert a.read_bytes() != b.read_bytes()
    code, lines = compare_dist.compare(a, b)
    assert code == 0
    assert "compression only" in lines[0]


def test_an_sdist_compressed_differently_has_the_same_contents(tmp_path: Path) -> None:
    a = _sdist(tmp_path / "a.tar.gz", FILES, 1)
    b = _sdist(tmp_path / "b.tar.gz", FILES, 9)
    assert a.read_bytes() != b.read_bytes()
    assert compare_dist.compare(a, b)[0] == 0


def test_a_changed_member_is_named(tmp_path: Path) -> None:
    a = _wheel(tmp_path / "a.whl", FILES, 6)
    b = _wheel(tmp_path / "b.whl", {**FILES, "pkg/data.txt": b"abd" * 500}, 6)
    code, lines = compare_dist.compare(a, b)
    assert code == 1
    assert lines[0] == "DIFFERENT CONTENTS"
    assert "  differs: pkg/data.txt" in lines


def test_an_added_member_is_named(tmp_path: Path) -> None:
    a = _sdist(tmp_path / "a.tar.gz", FILES, 6)
    b = _sdist(tmp_path / "b.tar.gz", {**FILES, "pkg/extra.py": b"y = 2\n"}, 6)
    code, lines = compare_dist.compare(a, b)
    assert code == 1
    assert "  only in b.tar.gz: pkg/extra.py" in lines


def test_usage(capsys) -> None:
    assert compare_dist.main([]) == 2
    assert "compare_dist.py" in capsys.readouterr().err
