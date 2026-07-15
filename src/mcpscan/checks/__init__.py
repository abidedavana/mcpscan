"""Check catalogue. Importing this package registers every implemented check.

Implemented so far (milestone 2 — config-only):

* mcp_secrets_no_hardcoded_in_config  (secrets.py)
* mcp_transport_tls_remote_http       (transport.py)
* mcp_transport_localhost_binding     (transport.py, config half)

The full v0.1 catalogue with grounding and remediation lives in
CHECKS-v0.1.md at the repo root.
"""

from __future__ import annotations

from .base import Check, CheckResult, all_checks, register

# Importing the modules runs their @register decorators.
from . import secrets as _secrets  # noqa: F401
from . import transport as _transport  # noqa: F401

__all__ = ["Check", "CheckResult", "all_checks", "register"]
