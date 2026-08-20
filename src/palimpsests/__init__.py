# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Palimpsests — a layered local-LLM inference engine."""

# Must equal the `version` in pyproject.toml. This is not cosmetic: the
# constant is stamped into JSONL exports by palimpsests.audit.export, so a
# stale value here publishes artifacts that name the wrong verifier.
# tests/test_smoke.py asserts the two agree, and RELEASING.md lists this file
# in the release checklist.
__version__ = "0.9.0"
__all__ = ["__version__"]
