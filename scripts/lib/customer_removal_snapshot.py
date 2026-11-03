from __future__ import annotations

import re
from datetime import datetime, timezone
from time import monotonic, sleep
from urllib.parse import urlsplit
from uuid import uuid4

import requests

from .endpoint_validation import validate_https_endpoint


SNAPSHOT_WAIT_SECONDS = 300
SNAPSHOT_POLL_SECONDS = 5


def create_customer_snapshot(env: dict[str, str], streams: set[str], repository: str) -> str:
    """Start a scoped snapshot and return its name only after verifying completion."""
    if not streams or any(not re.fullmatch(r"(?:logs|alerts)-[a-z0-9-]+", name) for name in streams):
        raise ValueError("A customer snapshot requires exact data stream names")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", repository):
        raise ValueError("Set SNAPSHOT_REPOSITORY to one registered repository name")

    base_url = env.get("OPENSEARCH_URL", "")
    validate_https_endpoint(base_url, field_name="OPENSEARCH_URL")
    endpoint = urlsplit(base_url)
    if "?" in base_url or "#" in base_url or endpoint.username is not None:
        raise ValueError("OPENSEARCH_URL must omit user information, query and fragment for a snapshot")
    ca = env.get("OPENSEARCH_CA")
    user = env.get("OPENSEARCH_USER")
    password = env.get("OPENSEARCH_PASSWORD")
    if not ca or not user or not password:
        raise ValueError("OpenSearch TLS CA and credentials are required for a snapshot")

    def request(method: str, path: str, *, allow_missing: bool = False, **kwargs) -> dict | None:
        try:
            response = requests.request(
                method, f"{base_url.rstrip('/')}{path}", auth=(user, password),
                verify=ca, timeout=30, allow_redirects=False, **kwargs,
            )
            if allow_missing and response.status_code == 404:
                return None
            if response.status_code != 200:
                raise ValueError(f"OpenSearch snapshot {method} {path} returned HTTP {response.status_code}")
            result = response.json()
        except requests.RequestException:
            raise ValueError(f"OpenSearch snapshot {method} {path} failed") from None
        if not isinstance(result, dict):
            raise ValueError(f"OpenSearch snapshot {method} {path} returned an unexpected response")
        return result

    repository_path = f"/_snapshot/{repository}"
    registered = request("GET", repository_path, allow_missing=True)
    if registered is None or not isinstance(registered.get(repository), dict):
        raise ValueError(f"Snapshot repository {repository} is not registered or readable")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    name = f"customer-removal-{timestamp}-{uuid4().hex[:12]}"
    snapshot_path = f"{repository_path}/{name}"
    print(f"Starting customer snapshot {repository}/{name}.", flush=True)
    ordered_streams = sorted(streams)
    response = request(
        "PUT", snapshot_path, params={"wait_for_completion": "false"},
        json={
            "indices": ",".join(ordered_streams),
            "ignore_unavailable": False,
            "include_global_state": False,
            "partial": False,
        },
    )
    if response is None or response.get("accepted") is not True:
        raise ValueError(f"OpenSearch did not accept snapshot {repository}/{name}")

    deadline = monotonic() + SNAPSHOT_WAIT_SECONDS
    while monotonic() < deadline:
        response = request("GET", snapshot_path, allow_missing=True)
        if response is not None:
            snapshots = response.get("snapshots")
            if (
                not isinstance(snapshots, list)
                or len(snapshots) != 1
                or not isinstance(snapshots[0], dict)
                or snapshots[0].get("snapshot") != name
            ):
                raise ValueError(f"OpenSearch did not identify snapshot {repository}/{name}")
            snapshot = snapshots[0]
            if snapshot.get("state") == "SUCCESS":
                actual_streams = snapshot.get("data_streams")
                shards = snapshot.get("shards")
                if (
                    not isinstance(actual_streams, list)
                    or not all(isinstance(stream, str) for stream in actual_streams)
                    or sorted(actual_streams) != ordered_streams
                    or snapshot.get("include_global_state") is not False
                    or snapshot.get("failures") != []
                    or not isinstance(shards, dict)
                    or shards.get("failed") != 0
                    or type(shards.get("total")) is not int
                    or shards["total"] < 1
                    or shards.get("successful") != shards["total"]
                ):
                    raise ValueError(f"Snapshot {repository}/{name} did not verify complete customer data")
                return name
            if snapshot.get("state") != "IN_PROGRESS":
                raise ValueError(f"Snapshot {repository}/{name} did not complete successfully")
        sleep(min(SNAPSHOT_POLL_SECONDS, max(0, deadline - monotonic())))
    raise ValueError(f"Snapshot {repository}/{name} is unverified after timeout and may still be running")
