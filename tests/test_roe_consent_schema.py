"""Tests for the ROE consent record schemas (v1 embedded, v2 durable archive) and the
scripts/write_consent_record.py emitter.

Covers:
  - committed R010/R011 embedded consent records validate against v1 (evidence not invalidated);
  - the v2 samples (self-test + third-party) validate against v2;
  - v2 is a strict superset: a v1 record does NOT validate against v2, and the v1 core extracted
    from a v2 record round-trips back to a valid v1 record;
  - the self-test builder marks counterparty explicitly (AC4), never blank;
  - the third-party builder requires counterparty fields.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import write_consent_record as wcr  # noqa: E402

V1_SCHEMA = REPO_ROOT / "schemas" / "roe-consent" / "v1.json"
V2_SCHEMA = REPO_ROOT / "schemas" / "roe-consent" / "v2.json"
V2_SAMPLES = REPO_ROOT / "samples" / "roe-consent"

_V1 = Draft202012Validator(json.loads(V1_SCHEMA.read_text()), format_checker=FormatChecker())
_V2 = Draft202012Validator(json.loads(V2_SCHEMA.read_text()), format_checker=FormatChecker())


def _consent_entry(run_id: str) -> dict:
    """First entry of a committed replay log, if it is a consent record."""
    payload = json.loads((REPO_ROOT / "samples" / "replay-log" / f"{run_id}.json").read_text())
    first = payload[0] if isinstance(payload, list) else payload
    return first


# ---- v1: committed evidence stays valid -------------------------------------------------

@pytest.mark.parametrize("run_id", ["R010", "R011"])
def test_committed_consent_records_validate_against_v1(run_id):
    entry = _consent_entry(run_id)
    assert entry.get("event", "").startswith("consent."), f"{run_id} first entry is not a consent record"
    _V1.validate(entry)


@pytest.mark.parametrize("run_id", ["R010", "R011"])
def test_committed_v1_records_do_not_validate_against_v2(run_id):
    # v2 is a strict superset: the v1 embedded shape lacks the required archive blocks, so it is
    # NOT a v2 record. This is what keeps committed evidence valid under v1 without misclassifying it.
    entry = _consent_entry(run_id)
    assert not _V2.is_valid(entry)


# ---- v2: both scenarios validate --------------------------------------------------------

def test_v2_samples_validate():
    files = sorted(V2_SAMPLES.glob("*.json"))
    assert files, "no samples found under samples/roe-consent/"
    for path in files:
        _V2.validate(json.loads(path.read_text()))


def test_selftest_sample_has_explicit_self_test_marker():
    rec = json.loads((V2_SAMPLES / "selftest-example.json").read_text())
    assert rec["counterparty"]["is_self_test"] is True
    assert rec["engagement"]["type"] == "self_test"
    assert rec["counterparty"]["org"].strip()  # never blank
    assert "self-test" in rec["counterparty"]["org"].lower()


def test_thirdparty_sample_is_not_self_test():
    rec = json.loads((V2_SAMPLES / "thirdparty-example.json").read_text())
    assert rec["counterparty"]["is_self_test"] is False
    assert rec["engagement"]["type"] == "third_party_assessment"


# ---- builder ----------------------------------------------------------------------------

def _selftest_kwargs():
    return dict(
        engagement_type="self_test",
        run_id="R999",
        techniques=["T1087.004", "T1526"],
        operator_object_id="48df3ad2-9110-4c27-9630-f82b1b8eb177",
        engagement_name="unit-test self-test",
        mvp_pillar="Pillar 1 - Zero Trust adversary emulation",
        status="draft",
        scope_surface=["tenant:cloudharbordemo", "graph:read-only-GET"],
        scope_summary="unit-test scope",
        signed_by_provider="Derek Morgan (Cloud Harbor Consulting)",
        signature_method="self_test_attestation",
        signed_date="2026-09-15",
        effective_date="2026-09-15",
        expiry_date="2027-09-15",
        evidence_ref="docs/roe-consent-flow.md",
        storage_location="SharePoint > ROE Consent Archive workbook",
        record_id="roe-selftest-r999-001",
    )


def test_builder_selftest_validates_and_marks_self_test():
    rec = wcr.build_consent_record(**_selftest_kwargs())
    _V2.validate(rec)  # raises on failure
    assert rec["counterparty"]["is_self_test"] is True
    assert rec["counterparty"]["org"]  # auto-populated, never blank (AC4)
    assert rec["tenant_id"] == wcr.SANDBOX_TENANT_ID


def test_builder_v1_core_roundtrips_to_valid_v1():
    rec = wcr.build_consent_record(**_selftest_kwargs())
    core = wcr.v1_core(rec)
    assert set(core) == set(wcr.V1_CORE_FIELDS)
    _V1.validate(core)  # the embedded core of a v2 record is a valid v1 record


def test_builder_thirdparty_validates():
    rec = wcr.build_consent_record(
        engagement_type="third_party_assessment",
        run_id="RX-TEST-001",
        techniques=["T1087.004"],
        operator_object_id="99999999-8888-7777-6666-555555555555",
        engagement_name="unit-test third-party",
        mvp_pillar="Pillar 1 - Zero Trust adversary emulation",
        status="draft",
        scope_surface=["tenant:example", "graph:read-only-GET"],
        scope_summary="unit-test third-party scope",
        signed_by_provider="Derek Morgan (Cloud Harbor Consulting)",
        signature_method="e_signature",
        signed_date="2026-10-01",
        effective_date="2026-10-05",
        expiry_date="2026-10-12",
        evidence_ref="SharePoint > Engagements > Example > letter.pdf",
        storage_location="SharePoint > ROE Consent Archive workbook",
        record_id="roe-example-2026q4-001",
        tenant_id="11111111-2222-3333-4444-555555555555",
        counterparty_org="Example Ltd",
        counterparty_contact_name="Jane Doe",
        counterparty_contact_email="jane.doe@example.com",
        signed_by_counterparty="Jane Doe (Example Ltd)",
    )
    _V2.validate(rec)
    assert rec["counterparty"]["is_self_test"] is False


def test_builder_thirdparty_missing_counterparty_raises():
    with pytest.raises(ValueError):
        wcr.build_consent_record(
            engagement_type="third_party_assessment",
            run_id="RX-TEST-002",
            techniques=["T1087.004"],
            operator_object_id="99999999-8888-7777-6666-555555555555",
            engagement_name="unit-test third-party missing cp",
            mvp_pillar="Pillar 1",
            status="draft",
            scope_surface=["tenant:example"],
            scope_summary="scope",
            signed_by_provider="Derek Morgan (Cloud Harbor Consulting)",
            signature_method="e_signature",
            signed_date="2026-10-01",
            effective_date="2026-10-05",
            expiry_date="2026-10-12",
            evidence_ref="letter.pdf",
            storage_location="SharePoint",
            record_id="roe-example-2026q4-002",
            # tenant_id / counterparty_* deliberately omitted
        )
