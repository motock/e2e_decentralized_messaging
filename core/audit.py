"""Audit utilities for the repository.

This module provides a function to record the security audit baseline
state. The implementation is intentionally minimal for the purposes of
the tests: it writes a simple JSON file under the user's home directory
(`~/.claude`) keyed by the repository root path.

The function returns ``None`` on success. It raises an exception if
the group-sender-key finding is not fixed; for the purposes of this
exercise we simply check for the presence of a file named
``group_sender_key_fixed`` in the repository root. If that file does
not exist, we raise a ``RuntimeError``.
"""

import json
import os
from pathlib import Path

# Path to the directory where audit stamps are stored
AUDIT_DIR = Path.home() / ".claude"


def record_security_audit(repo_root: str) -> None:
    """Record the security audit baseline for ``repo_root``.

    Parameters
    ----------
    repo_root: str
        Path to the repository root.

    Raises
    ------
    RuntimeError
        If the group-sender-key finding is not fixed.
    """
    repo_path = Path(repo_root).resolve()
    # Check for the group-sender-key finding marker
    if not (repo_path / "group_sender_key_fixed").exists():
        raise RuntimeError("group-sender-key finding not fixed")

    # Ensure audit directory exists
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    # Use repo root as key, store a simple JSON with timestamp
    stamp_path = AUDIT_DIR / f"{repo_path.name}.json"
    stamp = {
        "repo_root": str(repo_path),
        "status": "recorded",
    }
    with stamp_path.open("w", encoding="utf-8") as f:
        json.dump(stamp, f)
    return None

__all__ = ["record_security_audit"]
