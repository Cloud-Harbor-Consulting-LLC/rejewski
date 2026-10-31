# SPDX-License-Identifier: MIT
"""Tests for scripts/replay_log_viewer.py.

Covers the v0.2 --format html output mode (render_html) plus a regression
guard on the unchanged default text path.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import replay_log_viewer as viewer  # noqa: E402

TENANT = "c0ffee00-0000-4000-8000-000000000001"

CONSENT = {
    "event": "consent.granted",
    "run_id": "R011",
    "tenant_id": TENANT,
    "operator_object_id": "0b5e7a70-0000-4000-8000-000000000002",
    "techniques": ["T1087.004", "T1550.001"],
    "confirmed_at": "2026-07-18T16:30:35Z",
}

GRAPH_SUCCESS = {
    "kind": "graph_call",
    "tool": "tool_list_users",
    "technique": {"id": "T1087.004", "name": "Account Discovery: Cloud Account"},
    "tenant_id": TENANT,
    "actor_upn": "meganb@lab.example",
    "started_at_utc": "2026-07-18T16:31:35Z",
    "request": {
        "method": "GET",
        "url": "https://graph.microsoft.com/v1.0/users?$select=id&$top=999",
    },
    "response": {"status_code": 200, "row_count": 8, "page_count": 1},
    "outcome": "success",
    "run_id": "R011",
}

GRAPH_ERROR = {
    "kind": "graph_call",
    "tool": "tool_list_role_assignments",
    "technique": {"id": "T1087.004", "name": "Account Discovery: Cloud Account"},
    "tenant_id": TENANT,
    "actor_upn": "meganb@lab.example",
    "started_at_utc": "2026-07-18T16:32:48Z",
    "request": {
        "method": "GET",
        "url": "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$top=100",
    },
    "response": {"status_code": 0, "row_count": 0, "page_count": 0},
    "outcome": "error",
    "run_id": "R011",
}

TOKEN_EVENT = {
    "kind": "token_event",
    "tool": "scripts.identity",
    "technique": {"id": "T1550.001", "name": "Application Access Token"},
    "tenant_id": TENANT,
    "actor_upn": "meganb@lab.example",
    "started_at_utc": "2026-07-18T16:31:36Z",
    "response": {"status_code": 200},
    "outcome": "success",
    "run_id": "R011",
}


class TestRenderHtmlMetadata:
    def test_html_contains_run_metadata_and_outcomes(self):
        html = viewer.render_html([CONSENT, GRAPH_SUCCESS, GRAPH_ERROR])
        # Run metadata in the header.
        assert "Rejewski Run Report" in html
        assert "R011" in html
        assert "c0ffee00" in html  # short tenant
        assert "meganb@lab.example" in html  # operator UPN preferred
        assert "2026-07-18" in html  # date
        # Both graph endpoints appear (query string stripped).
        assert "/users" in html
        assert "/roleManagement/directory/roleAssignments" in html
        # Outcome badge text for each graph_call.
        assert ">success<" in html
        assert ">error<" in html
        # Self-contained: style inline, no external resource references.
        assert "<style>" in html
        assert "http-equiv" not in html
        assert "<script" not in html
        assert "src=" not in html and "href=" not in html


class TestOutcomeBadgeClass:
    # Note: the CSS <style> block defines .badge-success/.badge-error/.badge-other,
    # so the bare class name is always present. Assertions check span *usage*
    # (class="...") to distinguish an applied badge from its stylesheet definition.
    def test_success_and_error_badge_classes(self):
        html = viewer.render_html([GRAPH_SUCCESS, GRAPH_ERROR])
        assert 'class="badge-success"' in html
        assert 'class="badge-error"' in html

    def test_row_cap_hit_is_success_class(self):
        entry = dict(GRAPH_SUCCESS, outcome="row_cap_hit")
        html = viewer.render_html([entry])
        assert 'class="badge-success"' in html
        assert 'class="badge-error"' not in html


class TestNoConsent:
    def test_missing_consent_message(self):
        html = viewer.render_html([GRAPH_SUCCESS])
        assert "No consent record found in this log." in html

    def test_empty_sections_messages(self):
        # Only a consent entry -> both call tables show their empty message.
        html = viewer.render_html([CONSENT])
        assert "No graph calls in this log." in html
        assert "No token events in this log." in html


class TestSectionsAndFooter:
    def test_token_event_and_footer_summary(self):
        html = viewer.render_html([CONSENT, GRAPH_SUCCESS, TOKEN_EVENT])
        assert "T1550.001" in html  # token event technique rendered
        # Footer summary matches the text-mode summary counts.
        assert "3 entries — 1 graph_call · 1 token_event · 1 consent" in html


class TestTextPathUnchanged:
    def test_default_text_output_matches_render(
        self, tmp_path, capsys, monkeypatch
    ):
        log = tmp_path / "log.json"
        log.write_text(json.dumps([CONSENT, GRAPH_SUCCESS, TOKEN_EVENT]), "utf-8")
        rc = viewer.main([str(log)])
        assert rc == 0
        printed = capsys.readouterr().out.rstrip("\n").split("\n")
        expected = viewer.render([CONSENT, GRAPH_SUCCESS, TOKEN_EVENT])
        assert printed == expected  # AC4: text path byte-for-byte unchanged


class TestHtmlCliValidation:
    def test_html_without_output_errors(self, tmp_path, capsys):
        log = tmp_path / "log.json"
        log.write_text(json.dumps([GRAPH_SUCCESS]), "utf-8")
        rc = viewer.main([str(log), "--format", "html"])
        assert rc == 1
        assert "--output is required when --format is html" in capsys.readouterr().err

    def test_html_writes_file(self, tmp_path):
        log = tmp_path / "log.json"
        log.write_text(json.dumps([CONSENT, GRAPH_SUCCESS]), "utf-8")
        out = tmp_path / "report.html"
        rc = viewer.main([str(log), "--format", "html", "--output", str(out)])
        assert rc == 0
        content = out.read_text(encoding="utf-8")
        assert content.startswith("<!DOCTYPE html>")
        assert "Rejewski Run Report" in content
