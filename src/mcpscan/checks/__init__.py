"""Check catalogue. Importing this package registers every implemented check.

Implemented (8 of the 13 in CHECKS-v0.1.md):

static (config-only):
* mcp_secrets_no_hardcoded_in_config          (secrets.py)
* mcp_transport_tls_remote_http               (transport.py)
* mcp_transport_localhost_binding             (transport.py, config half)

live (one observation-only snapshot: initialize + tools/list, --live):
* mcp_secrets_not_in_tool_surface             (secrets.py)
* mcp_tools_capability_annotation_consistency (toolscope.py)
* mcp_schema_inputschema_valid                (schemas.py)
* mcp_schema_unconstrained_input_to_sink      (schemas.py)
* mcp_transport_stdio_stdout_clean            (transport.py)

Remaining for the probe engine (milestone 4): unauthenticated invocation,
PRM discovery, token-in-URL, Origin validation, session-ID quality.
"""

from __future__ import annotations

from .base import Check, CheckResult, all_checks, register

# Importing the modules runs their @register decorators; order here is
# catalogue category order (secrets, tool scope, schemas, transport).
from . import secrets as _secrets  # noqa: F401
from . import toolscope as _toolscope  # noqa: F401
from . import schemas as _schemas  # noqa: F401
from . import transport as _transport  # noqa: F401

__all__ = ["Check", "CheckResult", "all_checks", "register"]
