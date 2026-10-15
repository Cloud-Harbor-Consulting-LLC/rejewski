"""Tests for scripts/roe_gate.py: the G-1 consent-bound tenant lock (ADR 0008).

The gate lets a run target any tenant, but only the tenant its consent record names.
Every check here can only deny. Also covers the two enforcement points that call it:
identity.acquire_token (before any network call) and replay_log.write_entry (backstop).
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from unittest import mock

import pytest

import identity
import roe_gate
from replay_log import ReplayLogEntry, write_entry

SANDBOX = roe_gate.SANDBOX_TENANT_ID
OTHER = "11111111-2222-4333-8444-555555555555"
RUN = "R-GATE"
TODAY = date(2026, 10, 15)


def _v1(run_id=RUN, tenant_id=SANDBOX):
    return {"event": "consent.granted", "run_id": run_id, "tenant_id": tenant_id}


def _v2(run_id=RUN, tenant_id=OTHER, *, status="active", etype="third_party_assessment",
        is_self_test=False, method="DocuSign", start="2026-10-01", end="2026-10-31"):
    rec = _v1(run_id, tenant_id)
    rec.update({
        "schema_version": "2.0",
        "engagement": {"name": "Example", "type": etype, "mvp_pillar": "Multiple pillars", "status": status},
        "counterparty": {"is_self_test": is_self_test, "org": "Example Org",
                         "contact_name": "Example Contact", "contact_email": "contact@example.test"},
        "scope": {"surface": ["M365 tenant"], "summary": "Read-only discovery"},
        "authorization": {"signed_by_provider": "CHC", "signed_by_counterparty": "Example Contact",
                          "signature_method": method, "signed_date": start,
                          "effective_date": start, "expiry_date": end, "evidence_ref": "letter.pdf"},
        "archive": {"record_id": "roe-example", "storage_location": "archive", "created_utc": "2026-10-01T00:00:00Z"},
    })
    return rec


def _put(d: Path, rec: dict, name: str = "consent.json") -> None:
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(json.dumps(rec), encoding="utf-8")


def _authorize(d: Path, tenant=SANDBOX, run_id=RUN):
    return roe_gate.authorize_run(run_id=run_id, tenant_id=tenant, log_dir=d, today=TODAY)


# --- the gate ---------------------------------------------------------------------


def test_sandbox_with_v1_record_is_authorized(tmp_path):
    _put(tmp_path, _v1())
    assert _authorize(tmp_path)["run_id"] == RUN


def test_other_tenant_with_active_in_window_v2_is_authorized(tmp_path):
    _put(tmp_path, _v2())
    assert _authorize(tmp_path, tenant=OTHER)["tenant_id"] == OTHER


def test_self_test_v2_on_operator_owned_tenant_is_authorized(tmp_path):
    _put(tmp_path, _v2(etype="self_test", is_self_test=True, method="self_test_attestation"))
    assert _authorize(tmp_path, tenant=OTHER)["tenant_id"] == OTHER


@pytest.mark.parametrize("run_id", [None, ""])
def test_missing_run_id_is_refused(tmp_path, run_id):
    _put(tmp_path, _v1())
    with pytest.raises(roe_gate.ConsentError, match="run ID is required"):
        _authorize(tmp_path, run_id=run_id)


def test_no_consent_record_is_refused(tmp_path):
    with pytest.raises(roe_gate.ConsentError, match="no consent.granted record"):
        _authorize(tmp_path)


def test_record_for_another_run_does_not_count(tmp_path):
    _put(tmp_path, _v1(run_id="R-OTHER"))
    with pytest.raises(roe_gate.ConsentError, match="no consent.granted record"):
        _authorize(tmp_path)


def test_tenant_mismatch_is_refused(tmp_path):
    _put(tmp_path, _v1(tenant_id=SANDBOX))
    with pytest.raises(roe_gate.ConsentError, match="is consented for tenant"):
        _authorize(tmp_path, tenant=OTHER)


def test_conflicting_records_for_one_run_are_refused(tmp_path):
    _put(tmp_path, _v1(tenant_id=SANDBOX), "a.json")
    _put(tmp_path, _v2(tenant_id=OTHER), "b.json")
    with pytest.raises(roe_gate.ConsentError, match="more than one tenant"):
        _authorize(tmp_path, tenant=OTHER)


def test_other_tenant_with_only_v1_record_is_refused(tmp_path):
    _put(tmp_path, _v1(tenant_id=OTHER))
    with pytest.raises(roe_gate.ConsentError, match="v2 durable"):
        _authorize(tmp_path, tenant=OTHER)


@pytest.mark.parametrize("status", ["draft", "completed", "expired", "revoked"])
def test_other_tenant_needs_active_status(tmp_path, status):
    _put(tmp_path, _v2(status=status))
    with pytest.raises(roe_gate.ConsentError, match="must be 'active'"):
        _authorize(tmp_path, tenant=OTHER)


@pytest.mark.parametrize("start,end", [("2026-10-16", "2026-10-31"), ("2026-09-01", "2026-10-14")])
def test_other_tenant_outside_window_is_refused(tmp_path, start, end):
    _put(tmp_path, _v2(start=start, end=end))
    with pytest.raises(roe_gate.ConsentError, match="outside the authorization window"):
        _authorize(tmp_path, tenant=OTHER)


def test_window_bounds_are_inclusive(tmp_path):
    _put(tmp_path, _v2(start="2026-10-15", end="2026-10-15"))
    assert _authorize(tmp_path, tenant=OTHER)


def test_third_party_cannot_self_attest(tmp_path):
    _put(tmp_path, _v2(method="self_test_attestation"))
    with pytest.raises(roe_gate.ConsentError, match="counter-signed"):
        _authorize(tmp_path, tenant=OTHER)


def test_third_party_needs_is_self_test_false(tmp_path):
    _put(tmp_path, _v2(is_self_test=True))
    with pytest.raises(roe_gate.ConsentError, match="is_self_test false"):
        _authorize(tmp_path, tenant=OTHER)


@pytest.mark.parametrize("tenant", ["", "not-a-guid", None])
def test_non_guid_tenant_is_refused(tmp_path, tenant):
    with pytest.raises(roe_gate.ConsentError, match="tenant GUID"):
        _authorize(tmp_path, tenant=tenant)


def test_replay_entries_are_not_mistaken_for_consent(tmp_path):
    entry = _v1()
    entry["kind"] = "graph_call"  # an entry with a kind is never a consent record
    _put(tmp_path, entry)
    with pytest.raises(roe_gate.ConsentError, match="no consent.granted record"):
        _authorize(tmp_path)


def test_require_sandbox_refuses_other_tenants():
    roe_gate.require_sandbox(SANDBOX, "demo")
    with pytest.raises(roe_gate.ConsentError, match="sandbox-only"):
        roe_gate.require_sandbox(OTHER, "demo")


# --- enforcement point 1: identity.acquire_token (before any network call) --------


def test_acquire_token_refuses_without_consent_before_msal(tmp_path, monkeypatch):
    monkeypatch.setenv(identity.ENV_CACHE_PATH, str(tmp_path / "cache.bin"))
    with mock.patch.object(identity.msal, "PublicClientApplication") as pca:
        with pytest.raises(roe_gate.ConsentError):
            identity.acquire_token(actor_upn="a@x.test", tenant_id=OTHER,
                                   replay_log_dir=tmp_path, run_id=RUN, password="pw")
    pca.assert_not_called()
    assert list(tmp_path.glob("*.json")) == [], "a refused run writes no evidence"


def test_acquire_token_refuses_tenant_switch_mid_run(tmp_path, monkeypatch):
    """A run consented for the sandbox cannot be pointed at another tenant."""
    monkeypatch.setenv(identity.ENV_CACHE_PATH, str(tmp_path / "cache.bin"))
    _put(tmp_path, _v1())
    with mock.patch.object(identity.msal, "PublicClientApplication") as pca:
        with pytest.raises(roe_gate.ConsentError, match="is consented for tenant"):
            identity.acquire_token(actor_upn="a@x.test", tenant_id=OTHER,
                                   replay_log_dir=tmp_path, run_id=RUN, password="pw")
    pca.assert_not_called()


# --- enforcement point 2: replay_log.write_entry (backstop) ------------------------


def _entry(tenant, run_id=RUN):
    return ReplayLogEntry(
        kind="graph_call", tool="tool_test", technique_id="T1087.004",
        technique_name="Account Discovery: Cloud Account", tenant_id=tenant,
        borrowed_client_id="14d82eec-204b-4c2f-b7e8-296a70dab67e", actor_upn="a@x.test",
        started_at_utc="2026-10-15T00:00:00Z", completed_at_utc="2026-10-15T00:00:01Z",
        request={"method": "GET", "url": "https://graph.microsoft.com/v1.0/users"},
        response={"status_code": 200, "page_count": 1, "row_count": 1, "row_cap": 1000,
                  "row_cap_hit": False, "retry_count": 0},
        outcome="success", run_id=run_id,
    )


def test_write_entry_refuses_unconsented_other_tenant(tmp_path):
    with pytest.raises(ValueError, match="tenant lock"):
        write_entry(_entry(OTHER), log_dir=tmp_path)


def test_write_entry_accepts_consented_other_tenant(tmp_path):
    _put(tmp_path, _v2(start="2026-01-01", end="2099-12-31"))
    path = write_entry(_entry(OTHER), log_dir=tmp_path)
    assert json.loads(path.read_text(encoding="utf-8"))["tenant_id"] == OTHER


def test_write_entry_refuses_non_guid_tenant(tmp_path):
    with pytest.raises(ValueError, match="tenant GUID"):
        write_entry(_entry(""), log_dir=tmp_path)
