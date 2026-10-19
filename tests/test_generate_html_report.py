"""Tests for scripts/generate_html_report.py (Sprint 5 W17 template; W18 ROI section).

Renders against a self-contained fixture set (incl. a consent record) and against the
committed R012 sample, asserting the key content appears — technique IDs, severity badges,
control-mapping references, and the computed ROI / business-impact section (S5 W18). The ROI
tests cover: the §6 bridge parser (all 11 techniques, dollar figures confined to the reviewed
cells), a finding whose technique IS in the bridge (renders its risk category + direction),
and a finding whose technique is NOT in the bridge (renders the explicit not-modeled line, no
fabricated figure). Also guards that the generator never modifies docs/replay-report-r011.html.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_html_report as gen  # noqa: E402


def _write(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")


@pytest.fixture
def fixture_set(tmp_path):
    """A minimal replay-log + finding-triage + finding-to-control fixture for run R900."""
    tenant = "76b87c33-6178-4ff9-94a7-164792c8e4c6"
    replay = tmp_path / "R900.json"
    _write(replay, [
        {
            "event": "consent.granted", "run_id": "R900", "tenant_id": tenant,
            "operator_object_id": "48df3ad2-9110-4c27-9630-f82b1b8eb177",
            "techniques": ["T1087.004"], "confirmed_at": "2026-09-01T00:00:00Z",
        },
        {
            "kind": "token_event", "run_id": "R900", "tenant_id": tenant,
            "actor_upn": "tester@cloudharbor-demo.com", "started_at_utc": "2026-09-01T00:00:01Z",
            "outcome": "success", "schema_version": "0.5",
            "technique": {"id": "T1550.001", "name": "Application Access Token"},
        },
        {
            "kind": "graph_call", "run_id": "R900", "tenant_id": tenant,
            "actor_upn": "tester@cloudharbor-demo.com", "started_at_utc": "2026-09-01T00:00:02Z",
            "tool": "tool_list_users", "outcome": "success", "schema_version": "0.5",
            "request": {"method": "GET", "url": "https://graph.microsoft.com/v1.0/users?$top=999"},
            "response": {"status_code": 200, "row_count": 5},
            "technique": {"id": "T1087.004", "name": "Account Discovery: Cloud Account"},
        },
    ])
    finding_dir = tmp_path / "finding-triage"
    _write(finding_dir / "t1087.004-r900.json", {
        "finding_id": "ft-t1087-004-r900", "technique_id": "T1087.004",
        "technique_name": "Account Discovery: Cloud Account", "run_id": "R900",
        "severity": "medium", "confidence": "high",
        "control_mapping_id": "ftX-ca-test-001", "evidence": [], "triage_status": "open",
        "triage_metadata": {"created_utc": "2026-09-01T00:00:00Z", "author": "rejewski", "schema_version": "0.1"},
    })
    mapping_dir = tmp_path / "finding-to-control"
    _write(mapping_dir / "t1087.004-ca-test.json", {
        "mapping_id": "ftX-ca-test-001",
        "finding": {"technique_id": "T1087.004", "technique_name": "Account Discovery: Cloud Account",
                    "observed_in": [], "severity": "medium", "rationale": "test"},
        "control": {"control_family": "conditional_access", "control_id": "CA-TEST-001",
                    "control_type": "preventive", "microsoft_pillar": "Identities",
                    "nist_800_207_tenets": ["T4"], "reference_url": "https://learn.microsoft.com/x"},
        "mapping_metadata": {"created_utc": "2026-09-01T00:00:00Z", "author": "rejewski",
                             "schema_version": "0.1", "status": "active"},
    })
    return replay, finding_dir, mapping_dir


def test_fixture_render_key_content(fixture_set, tmp_path):
    replay, finding_dir, mapping_dir = fixture_set
    out = tmp_path / "out.html"
    rc = gen.main([
        "--replay-log", str(replay), "--finding-dir", str(finding_dir),
        "--mapping-dir", str(mapping_dir), "--output", str(out),
    ])
    assert rc == 0
    html = out.read_text(encoding="utf-8")
    # technique IDs
    assert "T1087.004" in html and "T1550.001" in html
    # severity badge for the finding
    assert 'class="badge-medium"' in html
    # control-mapping reference
    assert "CA-TEST-001" in html
    # ROI section computed from the §6 bridge; T1087.004 is in the bridge, so its
    # reviewed risk category renders (no placeholder any more).
    assert "ROI / business impact" in html
    assert "Account enumeration" in html
    assert gen.ROI_NOT_MODELED not in html  # every fixture finding is in the bridge
    # consent record rendered
    assert 'class="consent granted"' in html and "consent.granted" in html
    # well-formed enough to have the doctype/title
    assert html.startswith("<!DOCTYPE html>") and "Rejewski Run Report" in html


def test_g6_no_operator_object_id_or_full_tenant(fixture_set, tmp_path):
    replay, finding_dir, mapping_dir = fixture_set
    out = tmp_path / "out.html"
    gen.main(["--replay-log", str(replay), "--finding-dir", str(finding_dir),
              "--mapping-dir", str(mapping_dir), "--output", str(out)])
    html = out.read_text(encoding="utf-8")
    # G-6: operator object id never rendered; tenant shown truncated (first segment only)
    assert "48df3ad2-9110-4c27-9630-f82b1b8eb177" not in html
    assert "76b87c33-6178-4ff9-94a7-164792c8e4c6" not in html
    assert "76b87c33" in html


def test_real_r012_sample(tmp_path):
    out = tmp_path / "r012.html"
    rc = gen.main([
        "--replay-log", str(REPO_ROOT / "samples" / "replay-log" / "R012.json"),
        "--finding-dir", str(REPO_ROOT / "samples" / "finding-triage"),
        "--mapping-dir", str(REPO_ROOT / "samples" / "finding-to-control"),
        "--output", str(out),
    ])
    assert rc == 0
    html = out.read_text(encoding="utf-8")
    assert "Run: R012" in html
    assert 'class="badge-medium"' in html and 'class="badge-high"' in html
    assert "CA-COV008-BlockByLocation" in html and "Directory Readers" in html
    # ROI section: both R012 findings (T1087.004, T1550.001) are in the bridge and get a
    # line. Since ROI model v0.2 no line carries a dollar figure, T1550.001 included.
    assert "ROI / business impact" in html
    assert "Credential / token theft" in html  # T1550.001 risk category
    roi = html[html.index("<h2>ROI / business impact</h2>"):]
    assert "$" not in roi[:roi.index("</section>")]
    assert gen.ROI_NOT_MODELED not in html


def test_never_modifies_historical_report(fixture_set, tmp_path):
    # AC5: the generator must never touch docs/replay-report-r011.html.
    historical = REPO_ROOT / "docs" / "replay-report-r011.html"
    before = historical.read_bytes()
    replay, finding_dir, mapping_dir = fixture_set
    gen.main(["--replay-log", str(replay), "--finding-dir", str(finding_dir),
              "--mapping-dir", str(mapping_dir), "--output", str(tmp_path / "out.html")])
    assert historical.read_bytes() == before


def test_missing_replay_log_errors(tmp_path):
    rc = gen.main(["--replay-log", str(tmp_path / "nope.json"),
                   "--output", str(tmp_path / "out.html")])
    assert rc == 2


def test_roi_bridge_parses_the_committed_model():
    """The §6 bridge parser yields all 11 techniques, and no reviewed cell carries a dollar
    figure (AC2; ROI model v0.2 retired the §3 $728K reference)."""
    bridge = gen.load_roi_bridge(REPO_ROOT / "docs" / "phs-security-roi-model-v0.1.md")
    # the original nine plus the two W18 additions
    expected = {
        "T1078.004", "T1087.004", "T1069.003", "T1550.001", "T1526", "T1518.001",
        "T1082", "T1580", "T1654", "T1213.002", "T1033",
    }
    assert set(bridge) == expected
    assert bridge["T1213.002"]["control"] == "CA-SPO-001-RequireCompliantApp"
    assert bridge["T1033"]["control"] == "PIM-EligibleRoleAssignments"
    assert bridge["T1526"]["control"] == "CA policy read roles (RBAC)"
    # AC2 as a data invariant: no bridge cell mentions a dollar figure.
    dollar_cells = {t for t, v in bridge.items() if "$" in v["direction"]}
    assert dollar_cells == set()


def test_roi_finding_not_in_bridge_renders_explicit_line(tmp_path):
    """A finding whose technique is absent from the §6 bridge gets the explicit not-modeled
    line (AC4) — never a fabricated ROI statement, never a blank (AC1)."""
    tenant = "76b87c33-6178-4ff9-94a7-164792c8e4c6"
    replay = tmp_path / "R901.json"
    _write(replay, [
        {
            "kind": "graph_call", "run_id": "R901", "tenant_id": tenant,
            "started_at_utc": "2026-09-08T00:00:00Z", "tool": "tool_x", "outcome": "success",
            "schema_version": "0.5",
            "request": {"method": "GET", "url": "https://graph.microsoft.com/v1.0/x"},
            "response": {"status_code": 200, "row_count": 1},
            "technique": {"id": "T1071", "name": "Application Layer Protocol"},
        },
    ])
    finding_dir = tmp_path / "finding-triage"
    _write(finding_dir / "t1071-r901.json", {
        "finding_id": "ft-t1071-r901", "technique_id": "T1071",
        "technique_name": "Application Layer Protocol", "run_id": "R901",
        "severity": "medium", "confidence": "high", "evidence": [], "triage_status": "open",
        "triage_metadata": {"created_utc": "2026-09-08T00:00:00Z", "author": "rejewski", "schema_version": "0.1"},
    })
    out = tmp_path / "out.html"
    rc = gen.main([
        "--replay-log", str(replay), "--finding-dir", str(finding_dir),
        "--mapping-dir", str(tmp_path / "finding-to-control"), "--output", str(out),
    ])
    assert rc == 0
    html = out.read_text(encoding="utf-8")
    assert "ROI / business impact" in html
    # T1071 gets a line, and it is the explicit not-modeled line — no fabricated $ figure.
    assert "T1071" in html
    assert gen.ROI_NOT_MODELED in html
    roi = html[html.index("<h2>ROI / business impact</h2>"):]
    assert "$" not in roi[roi.index("<tbody>"):roi.index("</tbody>")]


def test_roi_empty_bridge_degrades_to_not_modeled(tmp_path, fixture_set):
    """If the ROI model doc is missing/unparseable, every finding degrades to the not-modeled
    line rather than to a fabricated figure (graceful, no-fabrication fallback)."""
    replay, finding_dir, mapping_dir = fixture_set
    out = tmp_path / "out.html"
    rc = gen.main([
        "--replay-log", str(replay), "--finding-dir", str(finding_dir),
        "--mapping-dir", str(mapping_dir), "--roi-model", str(tmp_path / "nonexistent.md"),
        "--output", str(out),
    ])
    assert rc == 0
    html = out.read_text(encoding="utf-8")
    assert gen.ROI_NOT_MODELED in html
    assert "Account enumeration" not in html  # bridge content absent when the doc is gone


def test_v2_consent_record_is_rendered_as_consent(tmp_path):
    """A v2 durable consent record carries schema_version; it must still be treated as consent
    (dry-run finding 2026-10-19: R017's report showed 0 consent records)."""
    replay = tmp_path / "R901.json"
    replay.write_text(json.dumps([
        {"event": "consent.granted", "run_id": "R901", "schema_version": "2.0",
         "tenant_id": "76b87c33-6178-4ff9-94a7-164792c8e4c6",
         "engagement": {"name": "x", "type": "self_test", "mvp_pillar": "x", "status": "active"}},
    ]), encoding="utf-8")
    meta = gen.load_replay_log(replay)
    assert len(meta["consent"]) == 1
