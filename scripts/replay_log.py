#!/usr/bin/env python3
"""
Rejewski — replay-log writer middleware.

v0.5 (Thu Jun 11, 2026): adds optional model_id field.
  - model_id records which Claude model handled the reasoning-loop step that
    produced this entry (Sonnet/Opus routing — see
    scripts/rejewski_runtime.RoutingConfig). Routine enumeration steps carry
    "claude-sonnet-4-6"; hard multi-hop analysis steps carry "claude-opus-4-6".
    Omitted from the serialized payload when None, so v0.4 producers stay valid.

v0.4 (Wed May 27, 2026): adds optional run_id binding field.
  - run_id propagates the consent.granted run ID (e.g. "R002") into every
    downstream graph_call and token_event entry in the run. Omitted when None.

v0.3 (Wed May 20, 2026): kind-discriminated response shapes.
  - graph_call : response requires (status_code, page_count, row_count);
                 optional (row_cap, row_cap_hit, retry_count)
  - token_event: response requires (status_code);
                 optional (aadsts_code, correlation_id, persistence_kind,
                           cache_path, flow)

Writes one JSON entry per run to samples/replay-log/<utc-stamp>-<uuid>.json,
validated against schemas/replay-log/v0.4.json. Two-layer secret scrubbing:
allow-list for request.headers (Authorization and any other non-listed header
is dropped key-and-value); deny-list for all other dict keys (value replaced
with [REDACTED] when key matches SECRET_KEY_PATTERN). Tenant GUID is redacted
from the error block before serialization.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "0.5"
SCHEMA_PATH = REPO_ROOT / "schemas" / "replay-log" / "v0.5.json"
DEFAULT_LOG_DIR = REPO_ROOT / "samples" / "replay-log"

SANDBOX_TENANT_ID = "76b87c33-6178-4ff9-94a7-164792c8e4c6"
REDACTED = "00000000-0000-0000-0000-000000000000"

ALLOWED_KINDS = ("graph_call", "token_event")
ALLOWED_OUTCOMES = ("success", "error", "throttled", "row_cap_hit")

GRAPH_CALL_RESPONSE_REQUIRED = ("status_code", "page_count", "row_count")
GRAPH_CALL_RESPONSE_OPTIONAL = ("row_cap", "row_cap_hit", "retry_count")

TOKEN_EVENT_RESPONSE_REQUIRED = ("status_code",)
TOKEN_EVENT_RESPONSE_OPTIONAL = (
    "aadsts_code",
    "correlation_id",
    "persistence_kind",
    "cache_path",
    "flow",
)

ALLOWED_REQUEST_HEADERS = (
    "User-Agent",
    "Content-Type",
    "Accept",
    "ConsistencyLevel",
    "Prefer",
    "Client-Request-Id",
)

SECRET_KEY_PATTERN = re.compile(
    r"(access_token|refresh_token|id_token|client_secret|password|authorization|bearer)",
    re.IGNORECASE,
)

_TENANT_GUID_RE = re.compile(re.escape(SANDBOX_TENANT_ID), re.IGNORECASE)


def _load_schema() -> dict[str, Any]:
    with SCHEMA_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


_VALIDATOR = Draft202012Validator(_load_schema(), format_checker=FormatChecker())


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_error(
    *, type_: str, message: str, status_code: int | None = None
) -> dict[str, Any]:
    block: dict[str, Any] = {"type": type_, "message": message}
    if status_code is not None:
        block["status_code"] = status_code
    return block


def redact_tenant_id(tenant_id: str) -> str:
    """Return the sandbox tenant GUID replaced with REDACTED for inclusion in a
    tool's evidence output (stdout / --output). The replay-log entry itself keeps
    the real tenant_id — G-1 requires write_entry to validate it — so this only
    affects the human-facing evidence blob. Any non-sandbox value passes through
    unchanged. Shared by every tool so the redaction is consistent across the
    toolset."""
    return REDACTED if tenant_id == SANDBOX_TENANT_ID else tenant_id


@dataclass
class ReplayLogEntry:
    kind: str
    tool: str
    technique_id: str
    technique_name: str
    tenant_id: str
    borrowed_client_id: str
    actor_upn: str
    started_at_utc: str
    completed_at_utc: str
    request: dict[str, Any]
    response: dict[str, Any]
    outcome: str
    error: dict[str, Any] | None = None
    run_id: str | None = None
    model_id: str | None = None
    schema_version: str = SCHEMA_VERSION
    entry_id: str = field(default_factory=lambda: str(uuid.uuid4()))


def _scrub(value: Any) -> Any:
    if isinstance(value, dict):
        scrubbed: dict[str, Any] = {}
        for k, v in value.items():
            if isinstance(k, str) and SECRET_KEY_PATTERN.search(k):
                scrubbed[k] = "[REDACTED]"
            else:
                scrubbed[k] = _scrub(v)
        return scrubbed
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    return value


def _redact_tenant_guid(value: Any) -> Any:
    if isinstance(value, str):
        return _TENANT_GUID_RE.sub(REDACTED, value)
    if isinstance(value, dict):
        return {k: _redact_tenant_guid(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_tenant_guid(v) for v in value]
    return value


def _shape_response(kind: str, response: dict[str, Any]) -> dict[str, Any]:
    if kind == "graph_call":
        required = GRAPH_CALL_RESPONSE_REQUIRED
        optional = GRAPH_CALL_RESPONSE_OPTIONAL
    elif kind == "token_event":
        required = TOKEN_EVENT_RESPONSE_REQUIRED
        optional = TOKEN_EVENT_RESPONSE_OPTIONAL
    else:
        raise ValueError(
            f"invalid kind: {kind!r}; expected one of {ALLOWED_KINDS}"
        )

    shaped: dict[str, Any] = {}
    for key in required:
        if key not in response:
            raise ValueError(
                f"response envelope missing required key: {key} (kind={kind})"
            )
        shaped[key] = response[key]
    for key in optional:
        if key in response:
            shaped[key] = response[key]
    return shaped


def _shape_technique(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": payload.pop("technique_id"),
        "name": payload.pop("technique_name"),
    }


def _allowlist_request_headers(request: dict[str, Any]) -> dict[str, Any]:
    headers = request.get("headers")
    if not isinstance(headers, dict):
        return request
    allowed = {h.lower() for h in ALLOWED_REQUEST_HEADERS}
    request["headers"] = {
        k: v
        for k, v in headers.items()
        if isinstance(k, str) and k.lower() in allowed
    }
    return request


def _filename(entry: ReplayLogEntry) -> str:
    stamp = entry.started_at_utc.replace("-", "").replace(":", "")
    return f"{stamp}-{entry.entry_id}.json"


def _atomic_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        prefix=".replay-", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=False)
            fh.write("\n")
        os.replace(tmp_path, path)
        if sys.platform != "win32":
            dir_fd = os.open(str(path.parent), os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def write_entry(entry: ReplayLogEntry, *, log_dir: Path | None = None) -> Path:
    if entry.kind not in ALLOWED_KINDS:
        raise ValueError(
            f"invalid kind: {entry.kind!r}; expected one of {ALLOWED_KINDS}"
        )
    if entry.outcome not in ALLOWED_OUTCOMES:
        raise ValueError(
            f"invalid outcome: {entry.outcome!r}; expected one of {ALLOWED_OUTCOMES}"
        )
    if not entry.borrowed_client_id or not entry.borrowed_client_id.strip():
        raise ValueError(
            "borrowed_client_id is required (no-tenant-app-reg posture, G-3)"
        )
    if entry.tenant_id != SANDBOX_TENANT_ID:
        raise ValueError(
            f"tenant lock (G-1): tenant_id must be {SANDBOX_TENANT_ID}, "
            f"got {entry.tenant_id!r}"
        )
    # G-1 read-only enforcement: a graph_call must be a GET. A token_event carries
    # the legitimate POST to the OAuth token endpoint and is exempt. This is the
    # active write-verb guard — a graph_call recorded with POST/PATCH/PUT/DELETE is
    # refused before the entry is written, so a future tool that issued a write
    # cannot silently produce a valid evidence record for it.
    if entry.kind == "graph_call":
        method = ""
        if isinstance(entry.request, dict):
            method = str(entry.request.get("method", "")).upper()
        if method != "GET":
            raise ValueError(
                "G-1 read-only enforcement: graph_call request.method must be "
                f"'GET', got {method!r}"
            )

    shaped_response = _shape_response(entry.kind, entry.response)
    payload = asdict(entry)
    if payload.get("run_id") is None:
        payload.pop("run_id", None)
    if payload.get("model_id") is None:
        payload.pop("model_id", None)
    payload["response"] = shaped_response
    payload["technique"] = _shape_technique(payload)
    if isinstance(payload.get("request"), dict):
        payload["request"] = _allowlist_request_headers(payload["request"])
    payload = _scrub(payload)
    if payload.get("error") is None:
        payload.pop("error", None)
    elif isinstance(payload.get("error"), dict):
        payload["error"] = _redact_tenant_guid(payload["error"])

    _VALIDATOR.validate(payload)

    out_dir = log_dir if log_dir is not None else DEFAULT_LOG_DIR
    target = out_dir / _filename(entry)
    if target.exists():
        raise FileExistsError(
            f"refusing to overwrite existing replay-log entry: {target}"
        )
    _atomic_write(target, payload)
    return target