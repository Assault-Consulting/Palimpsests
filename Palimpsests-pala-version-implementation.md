# Implementation: `pala --version` Command

**Requirement:** Print package version, PALA-1 spec version, and profile revision in one line  
**Acceptance:** Covered by test  
**Status:** Ready for PR

---

## Summary

The `pala --version` command needs to output a single line with three components:
- **Package version:** `0.10.0` (from `pyproject.toml`)
- **PALA-1 core spec version:** `v1.0` (frozen)
- **Inference-profile revision:** `r2`

Example output:
```
palimpsests 0.10.0 · PALA-1 v1.0 (core) · inference r2
```

---

## Implementation Steps

### Step 1: Add Version Callback to CLI

**File:** `src/palimpsests/cli.py`

**Location:** After the imports, before `app = typer.Typer(...)` definition

**Add:**

```python
def version_callback(value: bool) -> None:
    """Print package and spec versions and exit."""
    if value:
        # Package version from importlib.metadata
        try:
            from importlib.metadata import version
            pkg_version = version("palimpsests")
        except Exception:
            pkg_version = "unknown"
        
        # PALA-1 spec version (frozen)
        pala_spec = "v1.0"
        
        # Inference profile revision
        profile_revision = "r2"
        
        typer.echo(f"palimpsests {pkg_version} · PALA-1 {pala_spec} (core) · inference {profile_revision}")
        raise typer.Exit(code=0)
```

### Step 2: Add `--version` Option to Main App

**File:** `src/palimpsests/cli.py`

**Location:** In the main `app` definition, add callback parameter

**Change from:**
```python
app = typer.Typer(
    name="palimpsests",
    help="A layered local-LLM inference engine.",
    no_args_is_help=True,
    add_completion=False,
)
```

**Change to:**
```python
app = typer.Typer(
    name="palimpsests",
    help="A layered local-LLM inference engine.",
    no_args_is_help=True,
    add_completion=False,
)

@app.callback(invoke_without_command=True)
def version_option(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        help="Show version and exit.",
        is_eager=True,
        callback=version_callback,
    ),
) -> None:
    """Process global options."""
    pass
```

---

## Alternative: Simpler Approach (Recommended)

**File:** `src/palimpsests/cli.py`

**Replace the entire `version_callback` and app definition with:**

```python
def _print_version() -> None:
    """Print package and spec versions and exit."""
    try:
        from importlib.metadata import version
        pkg_version = version("palimpsests")
    except Exception:
        pkg_version = "unknown"
    
    typer.echo(f"palimpsests {pkg_version} · PALA-1 v1.0 (core) · inference r2")
    raise typer.Exit(code=0)


app = typer.Typer(
    name="palimpsests",
    help="A layered local-LLM inference engine.",
    no_args_is_help=True,
    add_completion=False,
)

# Version option
@app.callback()
def main_options(
    version: bool = typer.Option(
        None,
        "--version",
        is_eager=True,
        expose_value=True,
        is_flag=True,
        help="Show version and exit.",
    ),
) -> None:
    """Global options."""
    if version:
        _print_version()
```

---

## Test Implementation

**File:** `tests/test_cli_version.py` (new file)

```python
"""Test the --version command."""
import subprocess
import re
from importlib.metadata import version


def test_version_flag():
    """Test that --version prints package, PALA-1, and profile versions."""
    result = subprocess.run(
        ["python", "-m", "palimpsests.cli", "--version"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    
    # Check output format: "palimpsests X.Y.Z · PALA-1 vN.M (core) · inference rN"
    pattern = r"^palimpsests \d+\.\d+\.\d+ · PALA-1 v\d+\.\d+ \(core\) · inference r\d+$"
    assert re.match(pattern, result.stdout.strip()), f"Unexpected output: {result.stdout}"


def test_version_short_flag():
    """Test that -v also works."""
    result = subprocess.run(
        ["python", "-m", "palimpsests.cli", "-v"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "palimpsests" in result.stdout
    assert "PALA-1" in result.stdout
    assert "inference" in result.stdout


def test_version_content():
    """Verify that version contains expected components."""
    result = subprocess.run(
        ["python", "-m", "palimpsests.cli", "--version"],
        capture_output=True,
        text=True,
    )
    output = result.stdout.strip()
    
    # Extract package version from output
    pkg_version_in_output = output.split()[1]
    
    # Verify it matches installed version
    installed_version = version("palimpsests")
    assert pkg_version_in_output == installed_version, \
        f"Version mismatch: output={pkg_version_in_output}, installed={installed_version}"
    
    # Verify PALA-1 version is frozen at v1.0
    assert "PALA-1 v1.0" in output
    
    # Verify inference profile revision is r2
    assert "inference r2" in output


def test_version_from_python_api():
    """Test version retrieval via direct function call."""
    from palimpsests.cli import _print_version
    import io
    import sys
    
    # Capture stdout
    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    
    try:
        _print_version()
    except SystemExit as e:
        assert e.code == 0
        output = sys.stdout.getvalue().strip()
        assert "palimpsests" in output
        assert "PALA-1 v1.0" in output
        assert "inference r2" in output
    finally:
        sys.stdout = old_stdout
```

---

## Alternative Test Using Typer's Testing Utilities

**File:** `tests/test_cli_version.py` (using typer CliRunner)

```python
"""Test the --version command."""
from typer.testing import CliRunner
from palimpsests.cli import app
from importlib.metadata import version


runner = CliRunner()


def test_version_flag():
    """Test that --version prints package, PALA-1, and profile versions."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    
    output = result.stdout.strip()
    assert "palimpsests" in output
    assert "PALA-1 v1.0" in output
    assert "inference r2" in output


def test_version_short_flag():
    """Test that -v also works."""
    result = runner.invoke(app, ["-v"])
    assert result.exit_code == 0
    
    output = result.stdout.strip()
    assert "palimpsests" in output
    assert "PALA-1 v1.0" in output


def test_version_has_package_version():
    """Verify the package version in output matches installed version."""
    result = runner.invoke(app, ["--version"])
    output = result.stdout.strip()
    
    installed_version = version("palimpsests")
    assert installed_version in output, \
        f"Installed version {installed_version} not in output: {output}"


def test_version_format():
    """Verify output matches expected format."""
    result = runner.invoke(app, ["--version"])
    output = result.stdout.strip()
    
    # Format: "palimpsests X.Y.Z · PALA-1 vN.M (core) · inference rN"
    parts = output.split(" · ")
    assert len(parts) == 3, f"Expected 3 parts separated by ' · ', got {len(parts)}"
    
    assert parts[0].startswith("palimpsests ")
    assert parts[1].startswith("PALA-1 ")
    assert "(core)" in parts[1]
    assert parts[2].startswith("inference ")
```

---

## Version Constants

To keep versions DRY, consider adding constants to `src/palimpsests/__init__.py` or a dedicated `version.py`:

**File:** `src/palimpsests/version.py` (new file)

```python
"""Version constants for Palimpsests and the PALA-1 specification."""

# Package version is defined in pyproject.toml and read via importlib.metadata
# to ensure DRY principle: a single source of truth

# PALA-1 spec versions (frozen)
PALA_CORE_VERSION = "v1.0"
PALA_CORE_STATUS = "frozen"

# Inference profile revision
INFERENCE_PROFILE_REVISION = "r2"

# Pre-built version string for consistent output
def build_version_string(package_version: str) -> str:
    """Build the version output string."""
    return (
        f"palimpsests {package_version} · "
        f"PALA-1 {PALA_CORE_VERSION} (core) · "
        f"inference {INFERENCE_PROFILE_REVISION}"
    )
```

---

## Checklist for PR

- [ ] `version_callback` function added to `cli.py`
- [ ] `--version` flag added to main app callback
- [ ] `-v` short option works
- [ ] Output format is one line: `palimpsests X.Y.Z · PALA-1 v1.0 (core) · inference r2`
- [ ] Exit code is 0
- [ ] Test file created: `tests/test_cli_version.py`
- [ ] Test covers `--version` flag
- [ ] Test covers `-v` short flag
- [ ] Test verifies package version matches `pyproject.toml`
- [ ] Test verifies PALA-1 version is `v1.0`
- [ ] Test verifies profile revision is `r2`
- [ ] All tests pass: `pytest tests/test_cli_version.py -v`
- [ ] Linting passes: `ruff check src/palimpsests/cli.py`
- [ ] Format passes: `ruff format src/palimpsests/cli.py`

---

## Integration Notes

1. **`importlib.metadata`** is part of stdlib (Python 3.8+), so no new dependency
2. **Version from `pyproject.toml`** is automatically managed by the build system
3. **PALA-1 spec version** is frozen at `v1.0` per specification
4. **Inference profile revision** is currently `r2` per the roadmap
5. **Output is deterministic** — same input always produces same output

---

## Example Usage

```bash
$ pala --version
palimpsests 0.10.0 · PALA-1 v1.0 (core) · inference r2

$ pala -v
palimpsests 0.10.0 · PALA-1 v1.0 (core) · inference r2

$ python -m palimpsests.cli --version
palimpsests 0.10.0 · PALA-1 v1.0 (core) · inference r2
```

---

## PR Title & Description

**Title:** Add `pala --version` command with package, spec, and profile versions

**Description:**

Adds a `--version` flag to the main CLI that prints package version, PALA-1 spec version (frozen at v1.0), and inference profile revision (r2) in a single line.

Output format:
```
palimpsests 0.10.0 · PALA-1 v1.0 (core) · inference r2
```

Includes comprehensive test coverage using typer's CliRunner.

- Package version sourced from `importlib.metadata` (reads from `pyproject.toml`)
- PALA-1 spec version is frozen constant
- Profile revision is constant
- Both `-v` and `--version` work
- Exit code is 0
- Deterministic, single-line output

---

**Good-first-contribution:** ✅ Yes — straightforward CLI enhancement with clear acceptance criteria

---

*Ready for PR to Assault-Consulting/Palimpsests*
