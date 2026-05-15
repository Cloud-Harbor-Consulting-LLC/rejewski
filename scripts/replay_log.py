from __future__ import annotations


import json
import os
import re
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


from jsonschema import Draft202012Validator, FormatChecker


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "schemas" / "replay-log" / "v0.1.json"
DEFAULT_LOG_DIR = REPO_ROOT / "samples" / "replay-log"


SCHEMA_VERSION = "0.1"
SANDBOX_TENANT_ID = "76b87c33-6178-4ff9-94a7-164792c8e4c6"


ALLOWED_REQUEST_HEADERS = frozenset({
    "User-Agent",
    "Content-Type",
    "client-request-id",
    "Retry-After",
})


DENYLIST_KEYS = frozenset({
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "password",
    "secret",
    "credentials",
    "Authorization",
    "Cookie",
    "Set-Cookie",
    "Proxy-Authorization",
})


ALLOWED_OUTCOMES = frozenset({"success", "error", "throttled", "row_cap_hit"})


RESPONSE_REQUIRED_KEYS = ("status_code", "page_count", "row_count")
RESPONSE_OPTIONAL_KEYS = ("row_cap", "row_cap_hit", "retry_count")


REDACTED = "<redacted>"
TENANT_GUID_PATTERN = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)



def _load_validator() -> Draft202012Validator:
    with SCHEMA_PATH.open("r", encoding="utf-8") as handle:
        schema = json.load(handle)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())



_VALIDATOR = _load_validator()



def utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )



def new_entry_id() -> str:
    return str(uuid.uuid4())



def _redact_tenant_guids(value: str) -> str:
    return TENANT_GUID_PATTERN.sub(REDACTED, value)



def _scrub_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        scrubbed: dict[str, Any] = {}
        for key, inner in value.items():
            if key in DENYLIST_KEYS:
                scrubbed[key] = REDACTED
            else:
                scrubbed[key] = _scrub_value(inner)
        return scrubbed
    if isinstance(value, list):
        return [_scrub_value(item) for item in value]
    if isinstance(value, str):
        return _redact_tenant_guids(value)
    return value



def _filter_request_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    if not headers:
        return {}
    return {
        name: value
        for name, value in headers.items()
        if name in ALLOWED_REQUEST_HEADERS
    }



def _scrub_request(request: Mapping[str, Any]) -> dict[str, Any]:
    scrubbed: dict[str, Any] = {
        "method": str(request["method"]),
        "url": _redact_tenant_guids(str(request["url"])),
    }
    if request.get("query") is not None:
        scrubbed["query"] = _scrub_value(request["query"])
    if "headers" in request:
        scrubbed["headers"] = _filter_request_headers(request["headers"])
    if request.get("body") is not None:
        scrubbed["body"] = _scrub_value(request["body"])
    return scrubbed



def _shape_response(response: Mapping[str, Any]) -> dict[str, Any]:
    shaped: dict[str, Any] = {}
    for key in RESPONSE_REQUIRED_KEYS:
        if key not in response:
            raise ValueError(f"response envelope missing required key: {key}")
        shaped[key] = int(response[key])
    for key in RESPONSE_OPTIONAL_KEYS:
        if key in response and response[key] is not None:
            value = response[key]
            shaped[key] = bool(value) if key == "row_cap_hit" else int(value)
    return shaped



def _scrub_error(error: Mapping[str, Any]) -> dict[str, Any]:
    scrubbed: dict[str, Any] = {
        "type": _redact_tenant_guids(str(error["type"])),
        "message": _redact_tenant_guids(str(error["message"])),
    }
    if "status_code" in error and error["status_code"] is not None:
        scrubbed["status_code"] = int(error["status_code"])
    return scrubbed



def _filename_for(entry: Mapping[str, Any]) -> str:
    parsed = datetime.fromisoformat(entry["started_at_utc"].replace("Z", "+00:00"))
    stamp = parsed.strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{entry['entry_id']}.json"



def _atomic_write_json(target: Path, payload: Mapping[str, Any]) -> None:
    if target.exists():
        raise FileExistsError(f"replay-log entry already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        prefix=".tmp-", suffix=".json", dir=str(target.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, target)
        tmp_path = None
        if sys.platform != "win32":
            dir_fd = os.open(str(target.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    finally:
        if tmp_path is not None and os.path.exists(tmp_path):
            os.remove(tmp_path)



@dataclass
class ReplayLogEntry:
    tool: str
    technique_id: str
    technique_name: str
    tenant_id: str
    borrowed_client_id: str
    actor_upn: str
    started_at_utc: str
    completed_at_utc: str
    request: Mapping[str, Any]
    response: Mapping[str, Any]
    outcome: str
    error: Mapping[str, Any] | None = None
    schema_version: str = SCHEMA_VERSION
    entry_id: str = field(default_factory=new_entry_id)


    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "schema_version": self.schema_version,
            "entry_id": self.entry_id,
            "tool": self.tool,
            "technique": {
                "id": self.technique_id,
                "name": self.technique_name,
            },
            "tenant_id": self.tenant_id,
            "borrowed_client_id": self.borrowed_client_id,
            "actor_upn": self.actor_upn,
            "started_at_utc": self.started_at_utc,
            "completed_at_utc": self.completed_at_utc,
            "request": dict(self.request),
            "response": dict(self.response),
            "outcome": self.outcome,
        }
        if self.error is not None:
            data["error"] = dict(self.error)
        return data



def make_error(
    *,
    type_: str,
    message: str,
    status_code: int | None = None,
) -> dict[str, Any]:
    """Build a typed error block for the replay-log schema's error field.


    Shape: {type, message, status_code?}. Tenant GUIDs in the string fields
    are redacted at scrub time.
    """
    error: dict[str, Any] = {"type": type_, "message": message}
    if status_code is not None:
        error["status_code"] = int(status_code)
    return error



def write_entry(entry: ReplayLogEntry, log_dir: Path | None = None) -> Path:
    if entry.tenant_id != SANDBOX_TENANT_ID:
        raise ValueError(
            f"G-1 tenant scope lock: tenant_id must equal {SANDBOX_TENANT_ID}"
        )
    if not entry.borrowed_client_id:
        raise ValueError(
            "no-tenant-app-reg posture: borrowed_client_id is required"
        )
    if entry.outcome not in ALLOWED_OUTCOMES:
        raise ValueError(
            f"outcome must be one of {sorted(ALLOWED_OUTCOMES)}; got {entry.outcome!r}"
        )


    payload = entry.to_dict()
    payload["request"] = _scrub_request(payload["request"])
    payload["response"] = _shape_response(payload["response"])
    if payload.get("error") is not None:
        payload["error"] = _scrub_error(payload["error"])


    _VALIDATOR.validate(payload)


    target_dir = log_dir if log_dir is not None else DEFAULT_LOG_DIR
    target = target_dir / _filename_for(payload)
    _atomic_write_json(target, payload)
    return target