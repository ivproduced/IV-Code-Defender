# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Provider resolution + compliance mapping tests."""
import json

import pytest

from harness import providers, compliance


def test_default_provider():
    assert providers.resolve_provider(None) == "anthropic"


def test_explicit_over_env(monkeypatch):
    monkeypatch.setenv("VULN_PIPELINE_PROVIDER", "bedrock")
    assert providers.resolve_provider("vertex") == "vertex"
    assert providers.resolve_provider(None) == "bedrock"


def test_bedrock_env(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "us-west-2")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "k")
    pe = providers.resolve_provider_env("bedrock")
    assert pe.env["CLAUDE_CODE_USE_BEDROCK"] == "1"
    assert "bedrock-runtime.us-west-2.amazonaws.com:443" in pe.egress_hosts


def test_vertex_env(monkeypatch):
    monkeypatch.setenv("CLOUD_ML_REGION", "europe-west4")
    pe = providers.resolve_provider_env("vertex")
    assert pe.env["CLAUDE_CODE_USE_VERTEX"] == "1"
    assert "europe-west4-aiplatform.googleapis.com:443" in pe.egress_hosts


@pytest.mark.parametrize("p", ["openai", "azure", "ollama"])
def test_static_providers_reject(p):
    with pytest.raises(ValueError, match="cannot host"):
        providers.resolve_provider_env(p)


def test_unknown_provider():
    with pytest.raises(ValueError):
        providers.resolve_provider("nope")


def test_map_crash_uaf():
    cwe, ctrls = compliance.map_crash("heap-use-after-free")
    assert cwe == "CWE-416" and "SI-16" in ctrls


def test_enrich():
    r = compliance.enrich({"signature": {"crash_type": "stack-overflow"}})
    assert r["compliance"]["cwe"] == "CWE-674"
    assert any(c["control_id"] == "SC-5" for c in r["compliance"]["nist_800_53"])


def test_build_oscal(tmp_path):
    bd = tmp_path / "reports" / "bug_01"
    bd.mkdir(parents=True)
    (bd / "report.json").write_text(json.dumps(
        {"signature": {"crash_type": "double-free", "top_frame": "f"},
         "bug_id": 1, "verdict": {"severity_rating": "CRITICAL"}}))
    doc = compliance.build_oscal(tmp_path)
    f = doc["assessment-results"]["results"][0]["findings"]
    assert len(f) == 1 and f[0]["props"][1]["value"] == "CWE-415"
