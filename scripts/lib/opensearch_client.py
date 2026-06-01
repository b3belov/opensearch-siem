from __future__ import annotations

import os


def opensearch_auth() -> tuple[str, str]:
    user = os.environ.get("OPENSEARCH_USER")
    password = os.environ.get("OPENSEARCH_PASSWORD")
    if not user or not password:
        raise SystemExit(
            "ERROR: OPENSEARCH_USER and OPENSEARCH_PASSWORD must be set. Example:\n"
            "  set -a; . ./.env; set +a\n"
            "  OPENSEARCH_USER=admin OPENSEARCH_PASSWORD=\"$OPENSEARCH_ADMIN_PASSWORD\" ..."
        )
    return user, password


def opensearch_verify():
    """Return a CA bundle path for TLS verification, or False to disable (pre-Phase-I)."""
    return os.environ.get("OPENSEARCH_CA") or False
