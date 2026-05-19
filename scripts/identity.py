#!/usr/bin/env python3
"""
Rejewski — shared MSAL token acquisition helper (B021).

Persists borrowed refresh tokens through msal-extensions' encrypted
PersistedTokenCache so every tool after the first ROPC attempt acquires
access tokens silently. Refuses plaintext fallback on headless Linux
unless REJEWSKI_ALLOW_PLAINTEXT_CACHE=1 is set.

Wired per ADR-0005 §2 (decision), ADR-0004 §4 (identity-decision factors),
and b021-research-report.md (Tue May 19, 2026).

Emits a token_event replay-log entry on every acquisition — silent or
interactive. Access / refresh / id tokens are never logged.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import msal

from replay_log import (
    ReplayLogEntry,
    make_error,
    utc_now_iso,
    write_entry,
)

GRAPH_SCOPE_DEFAULT = ["https://graph.microsoft.com/.default"]
TOKEN_AUTHORITY_FMT = "https://login.microsoftonline.com/{tenant_id}"
TOKEN_ENDPOINT_URL_FMT = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
DEFAULT_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"  # Graph CLI Tools (ADR-0004 §4)
CLIENT_CAPABILITIES = ["CP1"]  # CAE-aware per ADR-0005 §2

TECHNIQUE_ID = "T1550.001"
TECHNIQUE_NAME = "Application Access Token (refresh-token reuse)"
TOOL_NAME = "scripts.identity"
ERROR_TYPE_URN = "urn:rejewski:error:token-acquisition-failed"

ENV_ALLOW_PLAINTEXT = "REJEWSKI_ALLOW_PLAINTEXT_CACHE"
ENV_CACHE_PATH = "REJEWSKI_CACHE_PATH"

PERSISTENCE_ENCRYPTED = "encrypted"
PERSISTENCE_PLAINTEXT = "plaintext"

FLOW_SILENT = "silent"
FLOW_ROPC = "ropc"


def _safe_actor_slug(actor_upn: str) -> str:
    return "".join(
        c if c.isalnum() or c in {"-", "_", "."} else "_"
        for c in actor_upn.lower()
    )


def _default_cache_path(actor_upn: str) -> Path:
    slug = _safe_actor_slug(actor_upn)
    if sys.platform == "win32":
        base = Path(
            os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))
        )
        return base / "rejewski" / f"{slug}.bin"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / "rejewski" / f"{slug}.bin"
    return Path.home() / ".cache" / "rejewski" / f"{slug}.bin"


def _resolve_cache_path(actor_upn: str) -> Path:
    override = os.environ.get(ENV_CACHE_PATH)
    if override:
        return Path(override).expanduser()
    return _default_cache_path(actor_upn)


def _build_cache(cache_path: Path) -> tuple[Any, str]:
    """Return (token_cache, persistence_kind).

    Refuses plaintext fallback unless REJEWSKI_ALLOW_PLAINTEXT_CACHE=1.
    """
    from msal_extensions import (
        FilePersistence,
        PersistedTokenCache,
        build_encrypted_persistence,
    )

    cache_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        persistence = build_encrypted_persistence(str(cache_path))
        return PersistedTokenCache(persistence), PERSISTENCE_ENCRYPTED
    except Exception as exc:
        if os.environ.get(ENV_ALLOW_PLAINTEXT) != "1":
            raise RuntimeError(
                f"encrypted token cache unavailable at {cache_path} ({exc!s}); "
                f"refusing plaintext fallback. Set {ENV_ALLOW_PLAINTEXT}=1 to opt in "
                f"(opt-in is recorded in every token_event replay-log entry)."
            ) from exc
        persistence = FilePersistence(str(cache_path))
        return PersistedTokenCache(persistence), PERSISTENCE_PLAINTEXT


def _build_app(
    tenant_id: str, client_id: str, token_cache: Any
) -> msal.PublicClientApplication:
    return msal.PublicClientApplication(
        client_id=client_id,
        authority=TOKEN_AUTHORITY_FMT.format(tenant_id=tenant_id),
        token_cache=token_cache,
        client_capabilities=CLIENT_CAPABILITIES,
    )


def acquire_token(
    *,
    actor_upn: str,
    tenant_id: str,
    client_id: str = DEFAULT_CLIENT_ID,
    scopes: list[str] | None = None,
    password: str | None = None,
    replay_log_dir: Path | None = None,
) -> dict[str, Any]:
    """Acquire a delegated Graph access token (silent reuse → ROPC fallback).

    The first call (cache empty) requires `password` and runs ROPC. Subsequent
    calls re-use the cached refresh token via acquire_token_silent_with_error.
    Every invocation emits a token_event replay-log entry; tokens themselves
    are never written to the log.
    """
    requested_scopes = list(scopes) if scopes else list(GRAPH_SCOPE_DEFAULT)
    cache_path = _resolve_cache_path(actor_upn)
    started_at = utc_now_iso()

    outcome = "error"
    error_block: dict[str, Any] | None = None
    aadsts_code: str | None = None
    flow: str = FLOW_SILENT
    correlation_id: str | None = None
    result: dict[str, Any] | None = None
    persistence_kind = PERSISTENCE_ENCRYPTED

    try:
        token_cache, persistence_kind = _build_cache(cache_path)
        app = _build_app(tenant_id, client_id, token_cache)

        accounts = [
            a
            for a in app.get_accounts()
            if a.get("username", "").lower() == actor_upn.lower()
        ]
        if accounts:
            silent = app.acquire_token_silent_with_error(
                scopes=requested_scopes, account=accounts[0]
            )
            if silent and "access_token" in silent:
                result = silent
                flow = FLOW_SILENT
                outcome = "success"
            elif silent and silent.get("error"):
                aadsts_code = silent.get("error")

        if result is None:
            if not password:
                raise RuntimeError(
                    f"silent reuse miss for {actor_upn} and no password supplied; "
                    f"ROPC fallback requires the seeded compromised-user password"
                )
            ropc = app.acquire_token_by_username_password(
                username=actor_upn,
                password=password,
                scopes=requested_scopes,
            )
            if "access_token" not in ropc:
                aadsts_code = ropc.get("error", "unknown_error")
                desc = ropc.get("error_description", "no description")
                raise RuntimeError(
                    f"ROPC token acquisition failed: {aadsts_code} - {desc}"
                )
            result = ropc
            flow = FLOW_ROPC
            outcome = "success"

        correlation_id = result.get("correlation_id")
    except Exception as exc:
        outcome = "error"
        error_block = make_error(
            type_=ERROR_TYPE_URN,
            message=str(exc),
            status_code=None,
        )
        completed_at = utc_now_iso()
        _emit_token_event(
            tenant_id=tenant_id,
            client_id=client_id,
            actor_upn=actor_upn,
            scopes=requested_scopes,
            started_at=started_at,
            completed_at=completed_at,
            outcome=outcome,
            flow=flow,
            aadsts_code=aadsts_code,
            correlation_id=correlation_id,
            persistence_kind=persistence_kind,
            cache_path=cache_path,
            error_block=error_block,
            replay_log_dir=replay_log_dir,
        )
        raise

    completed_at = utc_now_iso()
    _emit_token_event(
        tenant_id=tenant_id,
        client_id=client_id,
        actor_upn=actor_upn,
        scopes=requested_scopes,
        started_at=started_at,
        completed_at=completed_at,
        outcome=outcome,
        flow=flow,
        aadsts_code=aadsts_code,
        correlation_id=correlation_id,
        persistence_kind=persistence_kind,
        cache_path=cache_path,
        error_block=None,
        replay_log_dir=replay_log_dir,
    )

    return {
        "access_token": result["access_token"],
        "token_type": result.get("token_type", "Bearer"),
        "expires_in": result.get("expires_in"),
        "scope": result.get("scope"),
        "flow": flow,
        "persistence_kind": persistence_kind,
        "cache_path": str(cache_path),
        "correlation_id": correlation_id,
    }


def _emit_token_event(
    *,
    tenant_id: str,
    client_id: str,
    actor_upn: str,
    scopes: list[str],
    started_at: str,
    completed_at: str,
    outcome: str,
    flow: str,
    aadsts_code: str | None,
    correlation_id: str | None,
    persistence_kind: str,
    cache_path: Path,
    error_block: dict[str, Any] | None,
    replay_log_dir: Path | None,
) -> None:
    request_obj: dict[str, Any] = {
        "method": "POST",
        "url": TOKEN_ENDPOINT_URL_FMT.format(tenant_id=tenant_id),
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "flow": flow,
        "scopes": scopes,
    }
    response_obj: dict[str, Any] = {
        "status_code": 200 if outcome == "success" else 0,
        "aadsts_code": aadsts_code,
        "correlation_id": correlation_id,
        "persistence_kind": persistence_kind,
        "cache_path": str(cache_path),
    }
    entry = ReplayLogEntry(
        kind="token_event",
        tool=TOOL_NAME,
        technique_id=TECHNIQUE_ID,
        technique_name=TECHNIQUE_NAME,
        tenant_id=tenant_id,
        borrowed_client_id=client_id,
        actor_upn=actor_upn,
        started_at_utc=started_at,
        completed_at_utc=completed_at,
        request=request_obj,
        response=response_obj,
        outcome=outcome,
        error=error_block,
    )
    if replay_log_dir is not None:
        write_entry(entry, log_dir=replay_log_dir)
    else:
        write_entry(entry)