"""Audit utilities for the relay project.

This module currently provides a placeholder for the
``record_security_audit`` function, which is expected by the test suite.
The function is intentionally minimal; it accepts a repository root path
and performs no action.  It can be expanded in the future to record
security audit information.
"""

from __future__ import annotations

__all__ = ["record_security_audit"]


def record_security_audit(repo_root: str) -> None:
    """Placeholder audit function.

    Parameters
    ----------
    repo_root:
        Path to the repository root.  The function currently does nothing
        but is defined to satisfy the test suite and to provide a hook
        for future audit logic.
    """
    # No-op implementation – the relay stores only encrypted payloads
    # and does not perform any additional security audits at this time.
    return None
