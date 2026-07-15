"""Check catalogue. Importing this package registers every implemented check.

All 13 v0.1 checks (CHECKS-v0.1.md) are implemented.

static (config-only, no server contacted):
* mcp_secrets_no_hardcoded_in_config          (secrets.py)
* mcp_auth_token_not_in_url                    (auth.py)
* mcp_transport_tls_remote_http               (transport.py)
* mcp_transport_localhost_binding             (transport.py, config half)

live-snapshot (stdio: initialize + tools/list; http: also filled by the probe):
* mcp_secrets_not_in_tool_surface             (secrets.py)
* mcp_tools_capability_annotation_consistency (toolscope.py)
* mcp_schema_inputschema_valid                (schemas.py)
* mcp_schema_unconstrained_input_to_sink      (schemas.py)
* mcp_transport_stdio_stdout_clean            (transport.py)

live-probe (http observation-only requests: unauth, foreign Origin, well-known):
* mcp_auth_unauthenticated_invocation         (auth.py)
* mcp_auth_prm_discoverable                    (auth.py)
* mcp_transport_origin_validation             (transport.py)
* mcp_transport_session_id_quality            (transport.py)
"""

from __future__ import annotations

from .base import Check, CheckResult, all_checks, register

# Importing the modules runs their @register decorators; order here is
# catalogue category order (auth, secrets, tool scope, schemas, transport).
from . import auth as _auth  # noqa: F401
from . import secrets as _secrets  # noqa: F401
from . import toolscope as _toolscope  # noqa: F401
from . import schemas as _schemas  # noqa: F401
from . import transport as _transport  # noqa: F401

__all__ = ["Check", "CheckResult", "all_checks", "register"]
