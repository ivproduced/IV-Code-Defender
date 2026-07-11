# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""NIST SP 800-53 Rev 5 control mapping + OSCAL export for verified crashes.

The harness verifies memory-safety crashes, so the mapping keys off the ASAN
crash type and the report severity. Each finding ties to the controls a fix
satisfies (SA-11 testing, SI-16 memory protection, SI-10 input validation,
SI-2 flaw remediation, SC-5 DoS). enrich() stamps a compliance block onto each
report.json; build_oscal() rolls a results dir into an OSCAL assessment-results
document for FedRAMP tooling.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

NIST_CONTROLS = {
    "SA-11": ("Developer Security and Privacy Testing", "System and Services Acquisition"),
    "SI-16": ("Memory Protection", "System and Information Integrity"),
    "SI-10": ("Information Input Validation", "System and Information Integrity"),
    "SI-2": ("Flaw Remediation", "System and Information Integrity"),
    "SC-5": ("Denial-of-Service Protection", "System and Communications Protection"),
    "CM-7": ("Least Functionality", "Configuration Management"),
}

# ASAN crash type → (CWE, [NIST controls]). SA-11 (this pipeline is the test)
# and SI-2 (a fix is remediation) apply to every memory-safety finding.
_BASE = ["SA-11", "SI-2", "SI-16"]
_CRASH_MAP = {
    "heap-buffer-overflow": ("CWE-122", _BASE + ["SI-10"]),
    "stack-buffer-overflow": ("CWE-121", _BASE + ["SI-10"]),
    "global-buffer-overflow": ("CWE-787", _BASE + ["SI-10"]),
    "heap-use-after-free": ("CWE-416", _BASE),
    "use-after-free": ("CWE-416", _BASE),
    "double-free": ("CWE-415", _BASE),
    "stack-overflow": ("CWE-674", _BASE + ["SC-5"]),
    "allocation-size-too-big": ("CWE-789", _BASE + ["SI-10", "SC-5"]),
    "negative-size-param": ("CWE-191", _BASE + ["SI-10"]),
    "SEGV": ("CWE-476", _BASE),
    "FPE": ("CWE-369", _BASE + ["SI-10"]),
}
_DEFAULT = ("CWE-119", _BASE)


def map_crash(crash_type: str | None) -> tuple[str, list[str]]:
    """Return (CWE, [control ids]) for an ASAN crash type."""
    for key, val in _CRASH_MAP.items():
        if crash_type and key in crash_type:
            return val
    return _DEFAULT


def control_detail(ids: list[str]) -> list[dict]:
    out = []
    for cid in ids:
        title, family = NIST_CONTROLS.get(cid, ("Unknown Control", "Unknown Family"))
        out.append({"control_id": cid, "title": title, "family": family})
    return out


def enrich(report: dict) -> dict:
    """Stamp a `compliance` block onto a report dict (crash_type-driven)."""
    crash_type = (report.get("signature") or {}).get("crash_type")
    cwe, controls = map_crash(crash_type)
    report["compliance"] = {
        "cwe": cwe,
        "nist_800_53": control_detail(controls),
        "framework": "NIST SP 800-53 Rev 5",
    }
    return report


def build_oscal(results_dir: Path) -> dict:
    """Aggregate every reports/bug_*/report.json into one OSCAL
    assessment-results document."""
    reports = sorted((results_dir / "reports").glob("bug_*/report.json"))
    findings = []
    for rp in reports:
        try:
            r = json.loads(rp.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        sig = r.get("signature") or {}
        comp = r.get("compliance") or enrich(r)["compliance"]
        verdict = r.get("verdict") or {}
        findings.append({
            "uuid": f"bug-{r.get('bug_id', 0):02d}",
            "title": f"{sig.get('crash_type', 'crash')} @ {sig.get('top_frame', '?')}",
            "target-status": {"state": "open"},
            "props": [
                {"name": "severity", "value": verdict.get("severity_rating", "NOT_STATED")},
                {"name": "cwe", "value": comp["cwe"]},
            ],
            "related-controls": {
                "control-selections": [
                    {"include-controls": [{"control-id": c["control_id"]}
                                          for c in comp["nist_800_53"]]}
                ]
            },
        })
    return {
        "assessment-results": {
            "uuid": "ivcd-assessment",
            "metadata": {
                "title": "IV-Code-Defender assessment results",
                "last-modified": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "version": "1.0", "oscal-version": "1.1.2",
            },
            "results": [{
                "uuid": "ivcd-result",
                "title": "Execution-verified memory-safety findings",
                "start": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "findings": findings,
            }],
        }
    }
