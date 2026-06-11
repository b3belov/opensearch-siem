from __future__ import annotations

import copy
from pathlib import Path

import pytest

from scripts.lib import gitops_config


def test_source_catalog_contains_v1_sources() -> None:
    catalog = gitops_config.load_source_catalog()
    assert sorted(catalog) == ["generic-syslog", "windows-ad", "windows-sysmon"]
    assert catalog["windows-ad"].dataset == "windows-ad"
    assert catalog["windows-ad"].parser == "windows-ad-json"
    assert catalog["windows-sysmon"].dataset == "windows-sysmon"
    assert catalog["windows-sysmon"].parser == "windows-sysmon-json"
    assert catalog["generic-syslog"].dataset == "generic-syslog"
    assert catalog["generic-syslog"].parser == "generic-syslog"


def test_catalog_rejects_duplicate_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    original = gitops_config.read_yaml

    def fake_read_yaml(path: Path) -> dict:
        doc = original(path)
        if path.name == "sources.yml" and path.parent.name == "source-catalog":
            doc = copy.deepcopy(doc)
            doc["sources"].append(copy.deepcopy(doc["sources"][0]))
        return doc

    monkeypatch.setattr(gitops_config, "read_yaml", fake_read_yaml)
    with pytest.raises(ValueError, match="duplicate source catalog id"):
        gitops_config.load_source_catalog()


def test_catalog_rejects_duplicate_datasets(monkeypatch: pytest.MonkeyPatch) -> None:
    original = gitops_config.read_yaml

    def fake_read_yaml(path: Path) -> dict:
        doc = original(path)
        if path.name == "sources.yml" and path.parent.name == "source-catalog":
            doc = copy.deepcopy(doc)
            doc["sources"][1]["dataset"] = doc["sources"][0]["dataset"]
        return doc

    monkeypatch.setattr(gitops_config, "read_yaml", fake_read_yaml)
    with pytest.raises(ValueError, match="duplicate source catalog dataset"):
        gitops_config.load_source_catalog()


def test_gitops_source_must_match_catalog(monkeypatch: pytest.MonkeyPatch) -> None:
    catalog = gitops_config.load_source_catalog()
    customers = gitops_config.load_customers()
    retention_names = gitops_config.load_retention_policy_names()
    original = gitops_config.read_yaml

    def fake_read_yaml(path: Path) -> dict:
        doc = original(path)
        if path.name == "generic-syslog.yml":
            doc = copy.deepcopy(doc)
            doc["dataset"] = "firewall"
        return doc

    monkeypatch.setattr(gitops_config, "read_yaml", fake_read_yaml)
    with pytest.raises(ValueError, match="catalog dataset"):
        gitops_config.load_sources(customers, retention_names, catalog)
