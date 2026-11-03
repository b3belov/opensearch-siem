from __future__ import annotations

import re
from collections.abc import Callable
from urllib.parse import urlsplit

import requests

from .endpoint_validation import validate_https_endpoint


def _cleanup_client(env: dict[str, str]) -> tuple[str, Callable[[str, str], dict | None]]:
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

    def request(method: str, path: str) -> dict | None:
        try:
            response = requests.request(
                method, f"{base_url.rstrip('/')}{path}",
                auth=(user, password), verify=ca, timeout=30, allow_redirects=False,
            )
            if method == "GET" and response.status_code == 404:
                return None
            if response.status_code != 200:
                raise ValueError(f"OpenSearch {method} {path} returned HTTP {response.status_code}")
            result = response.json()
        except requests.RequestException:
            raise ValueError(f"OpenSearch {method} {path} failed") from None
        if not isinstance(result, dict):
            raise ValueError(f"OpenSearch {method} {path} returned an unexpected response")
        return result

    return base_url, request


def _validate_stream_names(names: set[str]) -> None:
    if any(not re.fullmatch(r"(?:logs|alerts)-[a-z0-9-]+", name) for name in names):
        raise ValueError("OpenSearch cleanup requires exact customer stream names")


def purge_customer_streams(
    env: dict[str, str], names: set[str], confirm: Callable[[str], bool],
    backup: Callable[[set[str]], bool], *, allow_delete: bool = True,
) -> bool:
    """Return whether all targeted streams are absent after review."""
    _validate_stream_names(names)
    base_url, request = _cleanup_client(env)
    present = {}
    for name in sorted(names):
        result = request("GET", f"/_data_stream/{name}")
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
        present[name] = result

    if not present:
        print("No matching customer data streams were found in OpenSearch.")
        return True

    print(f"\nVerified customer data streams at {base_url}:")
    for name in present:
        print(f"  {name}")
    if not allow_delete:
        print("Streams were kept. Apply the deployment preview during this run to enable permanent deletion.")
        return False
    if not confirm("Prepare permanent deletion of the listed data streams? [y/N]: "):
        print("OpenSearch data deletion skipped.")
        return False
    if not backup(set(present)):
        return False
    print("Permanent deletion also removes the backing indexes.")
    print("If a deletion fails, earlier deletions remain in effect. Verify your backups first.")
    if not confirm("Permanently delete the listed OpenSearch data streams? [y/N]: "):
        print("OpenSearch data deletion skipped.")
        return False

    all_clear = True
    for name, original in present.items():
        path = f"/_data_stream/{name}"
        current = request("GET", path)
        if current is None:
            continue
        if current != original:
            print(f"Keeping OpenSearch data stream {name}: it changed after review.")
            all_clear = False
            continue
        result = request("DELETE", path)
        if result is None or result.get("acknowledged") is not True:
            raise ValueError(f"OpenSearch did not acknowledge deletion of {name}")
        print(f"Deleted OpenSearch data stream {name}.")
    return all_clear


def _stream_dependencies(response: dict | None) -> tuple[set[str], set[str]]:
    streams = response.get("data_streams") if response is not None else None
    if not isinstance(streams, list):
        raise ValueError("OpenSearch did not return a data stream inventory")

    names = set()
    templates = set()
    for stream in streams:
        if not isinstance(stream, dict):
            raise ValueError("OpenSearch returned invalid data stream metadata")
        name = stream.get("name")
        template = stream.get("template")
        if not isinstance(name, str) or not name or not isinstance(template, str) or not template:
            raise ValueError("OpenSearch did not identify the template for every data stream")
        names.add(name)
        templates.add(template)
    return names, templates


def _customer_template(response: dict, name: str, stream: str) -> bool:
    templates = response.get("index_templates")
    if not isinstance(templates, list) or len(templates) != 1:
        return False
    entry = templates[0]
    if not isinstance(entry, dict) or entry.get("name") != name:
        return False
    template = entry.get("index_template")
    return (
        isinstance(template, dict)
        and template.get("index_patterns") == [stream]
        and isinstance(template.get("data_stream"), dict)
    )


def review_customer_templates(
    env: dict[str, str], streams: set[str], confirm: Callable[[str], bool],
    backup: Callable[[dict[str, dict]], bool],
) -> bool:
    """Return whether all targeted templates are absent after review."""
    _validate_stream_names(streams)
    base_url, request = _cleanup_client(env)
    names_in_use, templates_in_use = _stream_dependencies(request("GET", "/_data_stream"))
    removable = {}
    all_clear = True
    for stream in sorted(streams):
        if not stream.startswith("logs-"):
            continue
        name = f"{stream}-template"
        result = request("GET", f"/_index_template/{name}")
        if result is None:
            continue
        if not _customer_template(result, name, stream):
            print(f"Keeping OpenSearch template {name}: its definition could not be verified.")
            all_clear = False
        elif stream in names_in_use or name in templates_in_use:
            print(f"Keeping OpenSearch template {name}: a data stream still uses or matches it.")
            all_clear = False
        else:
            removable[name] = (stream, result)

    if not removable:
        print("No verified unused customer templates to remove.")
        return all_clear

    print(f"Unused customer templates at {base_url}:")
    for name in removable:
        print(f"  {name}")
    if not confirm("Prepare removal of the listed unused index templates? [y/N]: "):
        print("OpenSearch template removal skipped.")
        return False
    definitions = {
        name: original["index_templates"][0]["index_template"]
        for name, (_, original) in removable.items()
    }
    if not backup(definitions):
        return False
    if not confirm("Remove the listed unused OpenSearch index templates? [y/N]: "):
        print("OpenSearch template removal skipped.")
        return False

    for name, (stream, original) in removable.items():
        path = f"/_index_template/{name}"
        current = request("GET", path)
        if current is None:
            continue
        if current != original:
            print(f"Keeping OpenSearch template {name}: it changed after review.")
            all_clear = False
            continue
        names_in_use, templates_in_use = _stream_dependencies(request("GET", "/_data_stream"))
        if stream in names_in_use or name in templates_in_use:
            print(f"Keeping OpenSearch template {name}: a data stream now uses or matches it.")
            all_clear = False
            continue
        result = request("DELETE", path)
        if result is None or result.get("acknowledged") is not True:
            raise ValueError(f"OpenSearch did not acknowledge template removal for {name}")
        print(f"Removed OpenSearch template {name}.")
    return all_clear
