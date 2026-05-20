#!/usr/bin/env python3
"""
Rejewski — replay-log writer middleware.

v0.3 (Wed May 20, 2026): kind-discriminated response shapes.
  - graph_call : response requires (status_code, page_count, row_count);
                 optional (row_cap, row_cap_hit, retry_count)
  - token_event: response requires (status_code);
                 optional (aadsts_code, correlation_id, persistence_kind,
                           cache_path, flow)

Writes one JSON entry per run to samples/replay-log/<utc-stamp>-<uuid>.json,
validated against schemas/replay-log/v0.3.json. Tokens, passwords, and
known secret fields are scrubbed before serialization. Tenant GUID is
redacted from the error block before serialization (second-layer scrub).
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
SCHEMA_VERSION = "0.3"
SCHEMA_PATH = REPO_ROOT / "schemas" / "replay-log" / "v0.3.json"
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

    shaped_response = _shape_response(entry.kind, entry.response)
    payload = asdict(entry)
    payload["response"] = shaped_response
    payload["technique"] = _shape_technique(payload)
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