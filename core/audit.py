"""Minimal audit module for tests.

This module provides a placeholder function `record_security_audit` that
simply returns ``None``. The real implementation would record audit logs
and update sign‑off tables, but for the purposes of the test suite we
only need a callable that does nothing.
"""

from typing import Any


def record_security_audit(repo_root: str) -> None:
    """Record a security audit for the given repository root.

    The test suite only verifies that the function exists and can be
    called without raising an exception. The function therefore returns
    ``None`` and performs no side effects.
    """
    return None
