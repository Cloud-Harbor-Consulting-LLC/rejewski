# SPDX-License-Identifier: MIT
"""Tests for scripts/identity.py (B021 token persistence helper, ADR-0005)."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import identity  # noqa: E402

TENANT_ID = "c0ffee00-0000-4000-8000-000000000001"
ACTOR_UPN = "meganb@lab.example"
CLIENT_ID = identity.DEFAULT_CLIENT_ID


RUN_ID = "R-TEST"


def _write_consent(d: Path, *, run_id: str = RUN_ID, tenant_id: str = TENANT_ID) -> None:
    """G-1 (ADR 0008): acquire_token needs the run's consent record in the log dir."""
    (d / f"consent-{run_id}.json").write_text(
        json.dumps({"event": "consent.granted", "run_id": run_id, "tenant_id": tenant_id}),
        encoding="utf-8",
    )


@pytest.fixture
def replay_dir(tmp_path: Path) -> Path:
    d = tmp_path / "replay-logs"
    d.mkdir()
    _write_consent(d)
    return d


@pytest.fixture
def cache_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    p = tmp_path / "cache" / "rejewski.bin"
    monkeypatch.setenv(identity.ENV_CACHE_PATH, str(p))
    return p


def _read_token_events(replay_dir: Path) -> list[dict]:
    entries = []
    for fp in sorted(replay_dir.glob("*.json")):
        with open(fp, encoding="utf-8") as fh:
            entries.append(json.load(fh))
    return [e for e in entries if e.get("kind") == "token_event"]


class TestCachePathResolution:
    def test_linux_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(identity.ENV_CACHE_PATH, raising=False)
        monkeypatch.setattr(sys, "platform", "linux")
        path = identity._default_cache_path(ACTOR_UPN)
        assert ".cache/rejewski" in path.as_posix()
        assert path.name.endswith(".bin")
        assert "meganb" in path.name.lower()

    def test_darwin_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(identity.ENV_CACHE_PATH, raising=False)
        monkeypatch.setattr(sys, "platform", "darwin")
        path = identity._default_cache_path(ACTOR_UPN)
        assert "Library/Caches/rejewski" in path.as_posix()

    def test_windows_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(identity.ENV_CACHE_PATH, raising=False)
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setenv("LOCALAPPDATA", "C:\\Users\\test\\AppData\\Local")
        path = identity._default_cache_path(ACTOR_UPN)
        assert "rejewski" in str(path)
        assert path.name.endswith(".bin")

    def test_override_env(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        override = tmp_path / "custom.bin"
        monkeypatch.setenv(identity.ENV_CACHE_PATH, str(override))
        assert identity._resolve_cache_path(ACTOR_UPN) == override

    def test_actor_slug_sanitises(self) -> None:
        slug = identity._safe_actor_slug("Megan.B+test@lab.example")
        assert "+" not in slug
        assert "@" not in slug
        assert slug == slug.lower()


class TestPlaintextRefusal:
    def test_refuses_plaintext_without_optin(
        self, cache_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(identity.ENV_ALLOW_PLAINTEXT, raising=False)

        with mock.patch(
            "msal_extensions.build_encrypted_persistence",
            side_effect=RuntimeError("libsecret unavailable"),
        ):
            with pytest.raises(RuntimeError, match="refusing plaintext fallback"):
                identity._build_cache(cache_path)

    def test_allows_plaintext_with_optin(
        self, cache_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(identity.ENV_ALLOW_PLAINTEXT, "1")

        with mock.patch(
            "msal_extensions.build_encrypted_persistence",
            side_effect=RuntimeError("libsecret unavailable"),
        ), mock.patch("msal_extensions.FilePersistence") as fp_mock, mock.patch(
            "msal_extensions.PersistedTokenCache"
        ) as cache_mock:
            _, kind = identity._build_cache(cache_path)
            assert kind == identity.PERSISTENCE_PLAINTEXT
            fp_mock.assert_called_once_with(str(cache_path))
            cache_mock.assert_called_once()


class TestAcquireToken:
    def _patch_cache(self) -> mock._patch:
        return mock.patch(
            "identity._build_cache",
            return_value=(mock.MagicMock(), identity.PERSISTENCE_ENCRYPTED),
        )

    def test_silent_reuse_hit(self, cache_path: Path, replay_dir: Path) -> None:
        fake_app = mock.MagicMock()
        fake_app.get_accounts.return_value = [{"username": ACTOR_UPN}]
        fake_app.acquire_token_silent_with_error.return_value = {
            "access_token": "AT_silent",
            "token_type": "Bearer",
            "expires_in": 3599,
            "correlation_id": "cor-silent-1",
        }

        with self._patch_cache(), mock.patch(
            "identity._build_app", return_value=fake_app
        ):
            result = identity.acquire_token(
                actor_upn=ACTOR_UPN,
                tenant_id=TENANT_ID,
                client_id=CLIENT_ID,
                replay_log_dir=replay_dir,
                run_id=RUN_ID,
            )

        assert result["access_token"] == "AT_silent"
        assert result["flow"] == identity.FLOW_SILENT
        assert result["persistence_kind"] == identity.PERSISTENCE_ENCRYPTED
        fake_app.acquire_token_by_username_password.assert_not_called()

        events = _read_token_events(replay_dir)
        assert len(events) == 1
        assert events[0]["kind"] == "token_event"
        assert events[0]["outcome"] == "success"
        # B029: silent reuse replays an already-issued token -> T1550.001.
        assert events[0]["technique"]["id"] == "T1550.001"
        assert events[0]["technique"]["name"].startswith("Application Access Token")
        assert events[0]["request"]["flow"] == identity.FLOW_SILENT
        assert "access_token" not in json.dumps(events[0])

    def test_ropc_fallback_on_cache_miss(
        self, cache_path: Path, replay_dir: Path
    ) -> None:
        fake_app = mock.MagicMock()
        fake_app.get_accounts.return_value = []
        fake_app.acquire_token_by_username_password.return_value = {
            "access_token": "AT_ropc",
            "token_type": "Bearer",
            "expires_in": 3599,
            "correlation_id": "cor-ropc-1",
        }

        with self._patch_cache(), mock.patch(
            "identity._build_app", return_value=fake_app
        ):
            result = identity.acquire_token(
                actor_upn=ACTOR_UPN,
                tenant_id=TENANT_ID,
                client_id=CLIENT_ID,
                password="P@ssword!",
                replay_log_dir=replay_dir,
                run_id=RUN_ID,
            )

        assert result["access_token"] == "AT_ropc"
        assert result["flow"] == identity.FLOW_ROPC
        fake_app.acquire_token_by_username_password.assert_called_once()

        events = _read_token_events(replay_dir)
        assert len(events) == 1
        assert events[0]["request"]["flow"] == identity.FLOW_ROPC
        assert events[0]["outcome"] == "success"
        # B029: a fresh ROPC acquisition is an interactive sign-in, so the
        # token_event must carry T1078.004 — not T1550.001, which describes
        # reuse of an already-issued token.
        assert events[0]["technique"]["id"] == "T1078.004"
        assert events[0]["technique"]["name"] == "Valid Accounts: Cloud Accounts"

    def test_cache_miss_without_password_errors(
        self, cache_path: Path, replay_dir: Path
    ) -> None:
        fake_app = mock.MagicMock()
        fake_app.get_accounts.return_value = []

        with self._patch_cache(), mock.patch(
            "identity._build_app", return_value=fake_app
        ):
            with pytest.raises(RuntimeError, match="no password supplied"):
                identity.acquire_token(
                    actor_upn=ACTOR_UPN,
                    tenant_id=TENANT_ID,
                    client_id=CLIENT_ID,
                    replay_log_dir=replay_dir,
                    run_id=RUN_ID,
                )

        events = _read_token_events(replay_dir)
        assert len(events) == 1
        assert events[0]["outcome"] == "error"
        assert events[0]["error"]["type"] == identity.ERROR_TYPE_URN
        # Boundary: with no password, ROPC is never attempted — so this stays a
        # failed silent reuse (T1550.001), not a sign-in attempt. Guards against
        # the B029 follow-up over-reaching into this path.
        assert events[0]["request"]["flow"] == identity.FLOW_SILENT
        assert events[0]["technique"]["id"] == "T1550.001"

    def test_ropc_aadsts_error_recorded(
        self, cache_path: Path, replay_dir: Path
    ) -> None:
        fake_app = mock.MagicMock()
        fake_app.get_accounts.return_value = []
        fake_app.acquire_token_by_username_password.return_value = {
            "error": "invalid_grant",
            "error_description": "AADSTS50076: MFA required",
        }

        with self._patch_cache(), mock.patch(
            "identity._build_app", return_value=fake_app
        ):
            with pytest.raises(RuntimeError, match="ROPC token acquisition failed"):
                identity.acquire_token(
                    actor_upn=ACTOR_UPN,
                    tenant_id=TENANT_ID,
                    client_id=CLIENT_ID,
                    password="wrong",
                    replay_log_dir=replay_dir,
                    run_id=RUN_ID,
                )

        events = _read_token_events(replay_dir)
        assert events[0]["outcome"] == "error"
        assert events[0]["response"]["aadsts_code"] == "invalid_grant"
        # B029 follow-up: a FAILED sign-in attempt is still a T1078.004 event.
        # AADSTS50076 is the ZT-S02 signal proving the defender's MFA-required
        # CA policy fired (ADR-0004 §4) — it must not be filed as token reuse.
        assert events[0]["request"]["flow"] == identity.FLOW_ROPC
        assert events[0]["technique"]["id"] == "T1078.004"
        assert events[0]["technique"]["name"] == "Valid Accounts: Cloud Accounts"


class TestTechniqueConstants:
    """B029: identity.py maps acquisition flow -> ATT&CK technique.

    Pins both pairs so a future edit cannot silently collapse them back to a
    single hardcoded technique, which is the defect B029 fixed.
    """

    def test_reuse_constants(self) -> None:
        assert identity.TECHNIQUE_ID == "T1550.001"
        assert identity.TECHNIQUE_NAME.startswith("Application Access Token")

    def test_interactive_constants(self) -> None:
        assert identity.TECHNIQUE_ID_INTERACTIVE == "T1078.004"
        assert identity.TECHNIQUE_NAME_INTERACTIVE == "Valid Accounts: Cloud Accounts"

    def test_the_two_techniques_are_distinct(self) -> None:
        assert identity.TECHNIQUE_ID != identity.TECHNIQUE_ID_INTERACTIVE
        assert identity.TECHNIQUE_NAME != identity.TECHNIQUE_NAME_INTERACTIVE


class TestPersistenceKindPropagatesToReplayLog:
    def test_plaintext_kind_visible_in_replay_log(
        self, cache_path: Path, replay_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(identity.ENV_ALLOW_PLAINTEXT, "1")

        fake_app = mock.MagicMock()
        fake_app.get_accounts.return_value = [{"username": ACTOR_UPN}]
        fake_app.acquire_token_silent_with_error.return_value = {
            "access_token": "AT_silent",
            "correlation_id": "cor-pt-1",
        }

        with mock.patch(
            "identity._build_cache",
            return_value=(mock.MagicMock(), identity.PERSISTENCE_PLAINTEXT),
        ), mock.patch("identity._build_app", return_value=fake_app):
            identity.acquire_token(
                actor_upn=ACTOR_UPN,
                tenant_id=TENANT_ID,
                client_id=CLIENT_ID,
                replay_log_dir=replay_dir,
                run_id=RUN_ID,
            )

        events = _read_token_events(replay_dir)
        assert events[0]["response"]["persistence_kind"] == identity.PERSISTENCE_PLAINTEXT


class TestEndSession:
    """G-8 teardown: end_session deletes the local cache and its lock file only."""

    def test_removes_cache_and_lockfile(self, cache_path: Path) -> None:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_bytes(b"x")
        lock = Path(f"{cache_path}.lockfile")
        lock.write_text("", encoding="utf-8")

        removed = identity.end_session(ACTOR_UPN)

        assert set(removed) == {cache_path, lock}
        assert not cache_path.exists() and not lock.exists()

    def test_no_cache_is_a_no_op(self, cache_path: Path) -> None:
        assert identity.end_session(ACTOR_UPN) == []

    def test_makes_no_network_call(self, cache_path: Path) -> None:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_bytes(b"x")
        with mock.patch.object(identity.msal, "PublicClientApplication") as pca:
            identity.end_session(ACTOR_UPN)
        pca.assert_not_called()
