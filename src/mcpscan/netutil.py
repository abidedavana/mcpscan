"""Small network helpers shared across checks and the probe engine."""

from __future__ import annotations

import ipaddress


def is_loopback_host(host: str) -> bool:
    """True for 127.0.0.0/8, ::1, localhost, and *.localhost."""
    h = host.strip().lower().strip("[]")
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return h == "localhost" or h.endswith(".localhost")
