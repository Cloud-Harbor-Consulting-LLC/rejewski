# Dependency License Audit (Rejewski)

Version: v0.2
Owner: Cloud Harbor Consulting LLC
Last updated: 2026-10-20

## 1. Purpose

This document records the license posture of every Python package Rejewski depends on, direct and transitive. It establishes the SPDX identifier for each dependency, confirms inbound compatibility with Rejewski's MIT downstream license, and binds the audit script that re-emits this evidence on each release.

The audit is reproducible, offline, and re-runs on demand via scripts/audit_licenses.py.

## 2. Scope

In scope for v0.2:

- Direct runtime dependencies: msal, msal-extensions, requests, python-dotenv, jsonschema, claude-agent-sdk (Section 3).
- Direct development dependency: pytest.
- All transitive dependencies a clean install pulls in (37 packages, Section 4).
- Downstream license: MIT (Cloud Harbor Consulting LLC, 2026).

Out of scope, deferred:

- Vulnerability scanning (pip-audit). Belongs to a future security-scanning item.
- SBOM emission (SPDX 2.3 or CycloneDX 1.6+). Evidence field names in Section 7 preserve forward compatibility.
- Vendored or bundled distribution. Rejewski v1.0 ships source only; users install dependencies from PyPI.

## 3. Direct Dependencies

Versions are those resolved by a clean install on 2026-10-20 (Windows, Python 3.14.5).

| Package | Kind | Pin | Resolved | SPDX | Used for | MIT-inbound compatible |
|---|---|---|---|---|---|---|
| msal | runtime | `>=1.28,<2` | 1.39.0 | MIT | Token acquisition (scripts/identity.py) | yes |
| msal-extensions | runtime | `>=1.1,<2` | 1.3.1 | MIT | Encrypted token cache (ADR 0005) | yes |
| requests | runtime | `>=2.31,<3` | 2.34.2 | Apache-2.0 | Microsoft Graph HTTP calls | yes |
| python-dotenv | runtime | `>=1.0,<2` | 1.2.4 | BSD-3-Clause | Loads .env | yes |
| jsonschema | runtime | `>=4.21,<5` | 4.26.0 | MIT | Replay-log, consent, finding schema validation | yes |
| claude-agent-sdk | runtime | `>=0.1.81,<0.2` | 0.1.81 | MIT | Agent SDK options (scripts/rejewski_runtime.py) | yes |
| pytest | development | `>=8,<9` | 8.4.2 | MIT | Test suite | yes |

`claude-agent-sdk` was missing from `requirements.txt` until 2026-10-19 (PR #132); the v1.0 dry run found it. Before that, a clean install failed two test modules.

## 4. Transitive Dependencies

37 packages, pulled in by the direct dependencies above. `pywin32` and `colorama` install on Windows only.

| Package | Version | Pulled by | SPDX | MIT-inbound compatible | Notes |
|---|---|---|---|---|---|
| annotated-types | 0.8.0 | pydantic | MIT | yes |  |
| anyio | 4.15.1 | claude-agent-sdk, mcp, httpx2, starlette, sse-starlette | MIT | yes |  |
| attrs | 26.1.0 | jsonschema, referencing | MIT | yes |  |
| certifi | 2026.10.18 | requests | MPL-2.0 | yes | File-level copyleft; reviewed as compatible (Section 5) |
| cffi | 2.1.1 | cryptography | MIT-0 | yes | MIT No Attribution |
| charset-normalizer | 3.5.2 | requests | MIT | yes |  |
| click | 8.5.0 | uvicorn | BSD-3-Clause | yes |  |
| colorama | 0.4.6 | pytest (Windows only) | BSD-3-Clause-or-similar (manual review) | yes | BSD-3-Clause per its LICENSE.txt; classifier reads only 'BSD License' |
| cryptography | 50.0.2 | msal | Apache-2.0 OR BSD-3-Clause | yes |  |
| h11 | 0.16.0 | httpcore2, uvicorn | MIT | yes |  |
| httpcore2 | 2.14.0 | httpx2 | BSD-3-Clause | yes |  |
| httpx2 | 2.14.0 | mcp | BSD-3-Clause | yes |  |
| idna | 3.20 | requests, anyio, httpx2 | BSD-3-Clause | yes |  |
| iniconfig | 2.3.1 | pytest | MIT | yes |  |
| jsonschema-specifications | 2025.9.1 | jsonschema | MIT | yes |  |
| mcp | 2.3.0 | claude-agent-sdk | MIT | yes |  |
| mcp-types | 2.3.0 | mcp | MIT | yes |  |
| opentelemetry-api | 1.45.1 | mcp | Apache-2.0 | yes |  |
| packaging | 26.3 | pytest | Apache-2.0 OR BSD-2-Clause | yes |  |
| pluggy | 1.7.0 | pytest | MIT | yes |  |
| pycparser | 3.11 | cffi | BSD-3-Clause | yes |  |
| pydantic | 2.14.1 | mcp, mcp-types | MIT | yes |  |
| pydantic_core | 2.50.1 | pydantic | MIT | yes |  |
| Pygments | 2.21.0 | pytest | BSD-2-Clause | yes |  |
| PyJWT | 2.15.1 | msal, mcp | MIT | yes |  |
| python-multipart | 0.0.32 | mcp | Apache-2.0 | yes |  |
| pywin32 | 312 | mcp (Windows only) | PSF-2.0 | yes | Windows only |
| referencing | 0.37.0 | jsonschema | MIT | yes |  |
| rpds-py | 2026.9.1 | jsonschema, referencing | MIT | yes |  |
| sniffio | 1.3.1 | claude-agent-sdk | MIT | yes | Dual MIT OR Apache-2.0; resolved from metadata |
| sse-starlette | 3.5.0 | mcp | BSD-3-Clause | yes |  |
| starlette | 1.9.0 | mcp, sse-starlette | BSD-3-Clause | yes |  |
| truststore | 0.10.5 | httpx2, httpcore2 | MIT | yes |  |
| typing_extensions | 4.16.0 | pydantic, anyio, mcp, and 11 others | PSF-2.0 | yes | PSF-2.0, permissive |
| typing-inspection | 0.4.4 | pydantic, mcp | MIT | yes |  |
| urllib3 | 2.8.0 | requests | MIT | yes |  |
| uvicorn | 0.54.0 | mcp | BSD-3-Clause | yes |  |

This Section 4 table is the committed record of the 2026-10-20 run. The audit script also writes a machine-readable matrix to `evidence/<YYYY-MM-DD>/dependency-licenses.json`; `evidence/` is gitignored, so that file stays local and is regenerated on every run.

## 5. MIT-Inbound Compatibility Verdict

All 44 packages are compatible with distributing Rejewski under the MIT license.

- **Permissive:** MIT, MIT-0, Apache-2.0, BSD-2-Clause, BSD-3-Clause, PSF-2.0, and the dual `Apache-2.0 OR BSD-2-Clause` and `Apache-2.0 OR BSD-3-Clause` expressions.
- **One file-level copyleft package: `certifi` (MPL-2.0).** MPL-2.0 obligations attach to modified MPL-covered files. Rejewski installs certifi unmodified from PyPI as a dependency of `requests` and does not bundle, vendor, or modify it, so no obligation reaches Rejewski's own code. The audit script lists MPL-2.0 in `REVIEWED_FILE_LEVEL_COPYLEFT` so this review is explicit, and any other copyleft license still fails the gate.
- **No GPL, LGPL, or AGPL** package is present.

### 5.1 Attribution Guardrail (forward-looking)

MIT requires that "the above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software." For Rejewski v1.0, we do not redistribute jsonschema, pytest, or any transitive package binary. Users run pip install -r requirements.txt and fetch directly from PyPI, so attribution is satisfied at the package-manager layer.

If a later release ever ships a wheel, vendored copy, Docker image, PyInstaller bundle, or any other artifact that bundles these packages, the LICENSE files of every bundled package MUST travel with the artifact. This guardrail is binding on any future redistribution scenario.

## 6. Tool Selection

### 6.1 Primary collector: pip-licenses 5.5.5

pip-licenses is the chosen collector for the offline reproducible audit. Rationale:

- Offline: reads installed package metadata only, no network calls.
- JSON output: machine-readable, replay-log friendly.
- License-source flexibility: supports classifier, meta, and mixed modes (default mixed falls back classifier to meta).

Known limitation: the License field is the raw classifier or METADATA string ("MIT License", "BSD", "UNKNOWN"), not an SPDX short-form identifier. Mapping to SPDX is handled in-script via the lookup table in scripts/audit_licenses.py (see Section 7).

### 6.2 Secondary cross-check: licensecheck 2025.1.0 (deferred to CI)

licensecheck performs SPDX-aware project-license compatibility checks. Higher false-positive rate on packages with non-standard metadata. Reasonable CI cross-check for v0.2+; not required for v0.1.

### 6.3 Out of scope: pip-audit 2.10.0

pip-audit is a vulnerability scanner against the PyPI Advisory Database and OSV, not a license tool. Requires network. Belongs to a future security-scanning B-ID, not this audit.

## 7. Evidence Shape

The audit script emits two artifacts per run:

- Primary: JSON matrix at evidence/<YYYY-MM-DD>/dependency-licenses.json (one record per package).
- Secondary: the Section 4 Markdown table, regenerated from the JSON.

Per-package JSON record shape:

```json
{
  "name": "jsonschema",
  "version": "4.26.0",
  "license_spdx": "MIT",
  "license_source": "classifier",
  "license_raw": "MIT License",
  "license_url": "https://github.com/python-jsonschema/jsonschema/blob/main/COPYING",
  "mit_inbound_compat": true,
  "requires_manual_review": false
}
```

Field naming convention: lowercase-snake_case. Forward-compatibility note: these field names map cleanly to CycloneDX 1.6+ components[].licenses[].license.id and SPDX 2.3 packages[].licenseDeclared at SBOM emit time (future B-ID). Do not rename or switch to camelCase prematurely.

### 7.1 Classifier-Ambiguity Fallback (6 tiers)

When PyPI metadata reads only "License :: OSI Approved" with no specific OSI sub-license, or "UNKNOWN", the audit script walks the following ordering:

1. PEP 639 License-Expression core metadata field. Future canonical surface. If present, use verbatim. It IS the SPDX expression.
2. Wheel METADATA License free-text field. Heuristic-match against the in-script SPDX lookup table.
3. Trove classifier. Map "License :: OSI Approved :: MIT License" to "MIT", etc. Note: setuptools now emits a deprecation warning for license classifiers (warehouse #18917); classifiers will gradually disappear.
4. dist-info/licenses/LICENSE or COPYING text in the installed wheel. Hash-match the first 500 bytes against canonical SPDX license templates.
5. project-URL to GitHub LICENSE file. Requires network; deferred to CI, not the offline audit script.
6. license_spdx = "UNKNOWN" plus requires_manual_review = true. Fail loud in the Markdown report. Block release.

## 8. Version-Pin Policy

Posture: each direct dependency has a loose lower bound and an upper cap at its next major version (next minor for `claude-agent-sdk`, which is still 0.x). This accepts patch and minor security updates from PyPI without breaking on a major API change.

Lockfile decision for v1.0: no lockfile. v0.1 said to reconsider once the transitive set passed about 15 packages; it is now 37, mostly from `claude-agent-sdk` and `mcp`. The surface is still permissive apart from the reviewed certifi case, and the `tests` CI workflow (B040) now installs from scratch on every pull request, so a breaking upstream release shows up as a failed check. A constraints file for reproducible installs is a v1.1 candidate.

Reconsider when any of the following occurs:

- A copyleft license other than the reviewed MPL-2.0 case appears (any GPL, LGPL, or AGPL).
- A new direct dependency introduces extras that pull in copyleft transitives.
- An upstream release breaks a clean install in CI.

## 9. How to Run

The audit is reproducible from a clean checkout:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
python -m pip install pip-licenses==5.5.5
python scripts/audit_licenses.py
```

Outputs:

- evidence/<YYYY-MM-DD>/dependency-licenses.json (machine-readable matrix).
- Section 4 Markdown table (regenerated for human review).
- Non-zero exit code if any package resolves to license_spdx = "UNKNOWN", any license outside the permissive set and the reviewed MPL-2.0 exception appears, or the installed set drifts from `EXPECTED_PACKAGES` in the script (direct plus transitive; Windows-only packages and the audit tool itself are ignored).

## 10. Gaps

1. **Linux and macOS sets not audited separately.** The v0.2 run used Windows. The expected set excludes only the two Windows-only packages, so a run on Linux or macOS should pass; running the audit in CI on each platform would confirm it.
2. **Raw-classifier BSD entries.** `colorama` reports only "BSD License" in its classifier; its LICENSE file is BSD-3-Clause. The script records it as `BSD-3-Clause-or-similar (manual review)`.
3. **PEP 639 adoption is partial.** Some packages emit a `License-Expression` field and others only classifiers; the script handles both (Section 7.1).
4. **LICENSE-text hash matching (Tier 4) not implemented.** It depends on a vendored set of SPDX templates.

Resolved since v0.1: the transitive set is now verified by a live clean install (v0.1 Gap 4); `packaging` (Apache-2.0 OR BSD-2-Clause) and `rpds-py` (MIT) now resolve from their own package metadata (v0.1 Gaps 1 and 2).

## 11. References

- SPDX License List v3.28.0: <https://spdx.org/licenses/>
- SPDX License Expressions spec (3.0.1): <https://spdx.github.io/spdx-spec/v3.0.1/annexes/spdx-license-expressions/>
- PyPA Licensing Examples (PEP 639): <https://packaging.python.org/en/latest/guides/licensing-examples-and-user-scenarios/>
- jsonschema repo: <https://github.com/python-jsonschema/jsonschema>
- jsonschema maintainer license confirmation (Discussion #961): <https://github.com/orgs/python-jsonschema/discussions/961>
- pytest LICENSE: <https://github.com/pytest-dev/pytest/blob/main/LICENSE>
- pytest license docs: <https://docs.pytest.org/en/stable/license.html>
- pip-licenses on PyPI: <https://pypi.org/project/pip-licenses/>
- licensecheck on PyPI: <https://pypi.org/project/licensecheck/>
- CycloneDX BOM standard: <https://cyclonedx.org/>
- Grounding note: .memories/notes/sources-b008-license-audit.md (21 sources, 8 questions answered).
