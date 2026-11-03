from __future__ import annotations

import re
from collections.abc import Callable
from urllib.parse import urlsplit

import requests

from .endpoint_validation import validate_https_endpoint


def purge_customer_streams(
    env: dict[str, str], names: set[str], confirm: Callable[[str], bool],
) -> None:
    """Delete only the caller's customer-owned streams that the operator confirms."""
    if any(not re.fullmatch(r"(?:logs|alerts)-[a-z0-9-]+", name) for name in names):
        raise ValueError("Cannot purge data streams without exact customer stream names")

    base_url = env.get("OPENSEARCH_URL", "")
    validate_https_endpoint(base_url, field_name="OPENSEARCH_URL")
    endpoint = urlsplit(base_url)
    if "?" in base_url or "#" in base_url or endpoint.username is not None:
        raise ValueError("OPENSEARCH_URL must omit user information, query and fragment for a purge")
    ca = env.get("OPENSEARCH_CA")
    user = env.get("OPENSEARCH_USER")
    password = env.get("OPENSEARCH_PASSWORD")
    if not ca or not user or not password:
        raise ValueError("OpenSearch TLS CA and credentials are required for a purge")

    def request(method: str, name: str) -> dict | None:
        try:
            response = requests.request(
                method, f"{base_url.rstrip('/')}/_data_stream/{name}",
                auth=(user, password), verify=ca, timeout=30, allow_redirects=False,
            )
            if method == "GET" and response.status_code == 404:
                return None
            if response.status_code != 200:
                raise ValueError(f"OpenSearch {method} for {name} returned HTTP {response.status_code}")
            result = response.json()
        except requests.RequestException:
            raise ValueError(f"OpenSearch {method} for {name} failed") from None
        if not isinstance(result, dict):
            raise ValueError(f"OpenSearch {method} for {name} returned an unexpected response")
        return result

    present = []
    for name in sorted(names):
        result = request("GET", name)
        if result is None:
            continue
        streams = result.get("data_streams")
        if (
            not isinstance(streams, list)
            or len(streams) != 1
            or not isinstance(streams[0], dict)
            or streams[0].get("name") != name
            or streams[0].get("system")
        ):
            raise ValueError(f"OpenSearch did not verify exactly one customer data stream named {name}")
        present.append(name)

    if not present:
        print("No matching customer data streams were found in OpenSearch.")
        return

    print(f"\nOpenSearch at {base_url} will permanently delete these data streams and their backing indexes:")
    for name in present:
        print(f"  {name}")
    print("If a deletion fails, earlier deletions remain in effect. Verify your backups first.")
    if not confirm("Permanently delete the listed OpenSearch data streams? [y/N]: "):
        print("OpenSearch data deletion skipped.")
        return

    for name in present:
        result = request("DELETE", name)
        if result is None or result.get("acknowledged") is not True:
            raise ValueError(f"OpenSearch did not acknowledge deletion of {name}")
        print(f"Deleted OpenSearch data stream {name}.")
