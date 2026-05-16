# Dependency License Audit (Rejewski)

Version: v0.1
Owner: Cloud Harbor Consulting LLC
Last updated: 2026-05-16

## 1. Purpose

This document records the license posture of every Python package Rejewski depends on, direct and transitive. It establishes the SPDX identifier for each dependency, confirms inbound compatibility with Rejewski's MIT downstream license, and binds the audit script that re-emits this evidence on each release.

The audit is reproducible, offline, and re-runs on demand via scripts/audit_licenses.py.

## 2. Scope

In scope for v0.1:

- Direct runtime dependency: jsonschema>=4.26,<5
- Direct development dependency: pytest>=8,<9
- All transitive dependencies pulled by the above (7 packages, see Section 4)
- Downstream license: MIT (Cloud Harbor Consulting LLC, 2026)

Out of scope for v0.1, deferred to future B-IDs:

- Vulnerability scanning (pip-audit). Belongs to a future security-scanning B-ID.
- SBOM emission (SPDX 2.3 or CycloneDX 1.6+). Evidence field names in Section 7 preserve forward compatibility.
- Vendored or bundled distribution scenarios. Rejewski v0.1 ships source only; users pip install from PyPI.

## 3. Direct Dependencies

### 3.1 jsonschema (runtime)

| Field | Value |
|---|---|
| SPDX identifier | MIT |
| Version pin | >=4.26,<5 |
| Upstream | <https://github.com/python-jsonschema/jsonschema> |
| License file | dist-info/licenses/COPYING (MIT text) |
| MIT-inbound compatible | yes |

Source corroboration (4 independent signals):

1. PyPI Trove classifier: License :: OSI Approved :: MIT License
2. LICENSE file in wheel: dist-info/licenses/COPYING containing canonical MIT text
3. Maintainer statement (Julian Berman, python-jsonschema Discussion #961, June 2022): MIT
4. Distro reconciliation (MSYS2, piwheels): both label License(s): MIT

Extras note (non-binding for v0.1):

jsonschema exposes two optional extras, format and format-nongpl. The split exists because one optional format-validator dependency (rfc3987) is GPL-2.0+. format-nongpl is the curated permissive subset. Rejewski installs neither extra (we use Draft 2020-12 structural validation only), so this is non-binding for v0.1. If a future version pulls in either extra, this audit must re-evaluate.

### 3.2 pytest (development)

| Field | Value |
|---|---|
| SPDX identifier | MIT |
| Version pin | >=8,<9 |
| Upstream | <https://github.com/pytest-dev/pytest> |
| License file | LICENSE (MIT text, Copyright 2004 Holger Krekel and others) |
| MIT-inbound compatible | yes |

Source corroboration (3 independent signals):

1. LICENSE file: verbatim MIT text
2. Project docs: "Distributed under the terms of the MIT license"
3. PyPI project description: MIT attribution

Single license root-to-leaf. No sub-module split.

## 4. Transitive Dependencies

Transitive surface for v0.1 is small (7 packages) and audited in full from day one. Direct-only scope would miss the packaging dual-license, which is the only non-MIT element in the tree and exactly the kind of finding this audit exists to surface.

| Package | Pulled by | SPDX identifier | MIT-inbound compatible | Notes |
|---|---|---|---|---|
| attrs | jsonschema | MIT | yes | |
| referencing | jsonschema | MIT | yes | |
| rpds-py | jsonschema (via referencing) | MIT | yes | Direct PyPI verification pending (Gap 2) |
| jsonschema-specifications | jsonschema | MIT | yes | |
| iniconfig | pytest | MIT | yes | |
| packaging | pytest | Apache-2.0 OR BSD-2-Clause | yes | Non-MIT canary. Both options permissive and MIT-compatible. Direct LICENSE-file verification pending (Gap 1) |
| pluggy | pytest | MIT | yes | |

Total surface: 2 direct + 7 transitive = 9 packages.

This Section 4 table is the human-readable mirror of evidence/<YYYY-MM-DD>/dependency-licenses.json. The audit script regenerates this table on every run.

## 5. MIT-Inbound Compatibility Verdict

All 9 packages are MIT-inbound compatible with Rejewski's MIT downstream license. MIT is permissive, OSI-approved, FSF-libre, and combinable with any other MIT-licensed work without re-licensing constraints. The single non-MIT element (packaging, Apache-2.0 OR BSD-2-Clause) is permissive on either branch and combines cleanly with MIT downstream.

### 5.1 Attribution Guardrail (forward-looking)

MIT requires that "the above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software." For Rejewski v0.1, we do not redistribute jsonschema, pytest, or any transitive package binary. Users run pip install -r requirements.txt and fetch directly from PyPI, so attribution is satisfied at the package-manager layer.

If v0.2 or later ever ships a wheel, vendored copy, Docker image, PyInstaller bundle, or any other artifact that bundles these packages, the LICENSE files of every bundled package MUST travel with the artifact. This guardrail is binding on any future redistribution scenario.

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

Current posture: jsonschema>=4.26,<5 and pytest>=8,<9 (loose lower bound, major-version upper cap).

This is conventional for security-framework tooling that wants to accept patch and minor security updates from PyPI without breaking on a hypothetical major-version API change.

Lockfile decision for v0.1: no uv.lock, no pip-compile-generated requirements.lock. Justification: 9 total packages, MIT-uniform surface (with the permissive packaging exception). Marginal value of a lockfile for v0.1 is low; tooling surface (uv install in CI) is not earned yet.

Reconsider at v0.2 when any of the following occurs:

- Transitive surface grows beyond approximately 15 packages.
- A non-permissive transitive license appears (current canary: packaging Apache-2.0 / BSD-2-Clause stays permissive; watch for any LGPL, GPL, or AGPL appearance).
- A new direct dependency introduces extras that pull in copyleft transitives.

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
- Non-zero exit code if any package resolves to license_spdx = "UNKNOWN", any non-permissive license appears, or the observed transitive set drifts from the 7-package baseline in Section 4.

## 10. Gaps

1. packaging direct LICENSE-file verification. Listed as Apache-2.0 OR BSD-2-Clause per PyPA documentation; not yet fetched directly from packaging's own LICENSE file. The audit script's first run on a clean install must surface the resolved value and fail loud if it does not match Apache-2.0 OR BSD-2-Clause.
2. rpds-py direct PyPI verification. Inferred MIT from the piwheels listing under jsonschema's transitive dependencies. Direct PyPI metadata fetch will strengthen.
3. PEP 639 adoption status for jsonschema 4.26 and pytest 8.x. Neither was confirmed to emit License-Expression core metadata as of 2026-05-16. The audit script handles both PEP 639 and legacy classifier paths (Tier 1 then Tier 3 in Section 7.1) until adoption is universal.
4. Pip-resolved transitive set not verified live in this audit document. Task rules at v0.1 grounding time forbade running pip in the research environment. The audit_licenses.py first run on a clean install will emit the actual resolved set. If the observed set differs from the 7-package baseline in Section 4, the script flags requires_first_run_verification = true and fails the release gate. Update this document on first run.
5. LICENSE-text hash-matching feasibility (Tier 4). Hash-matching the first 500 bytes of dist-info/licenses/LICENSE or COPYING against canonical SPDX license templates depends on a vendored template set. If implementation difficulty is high, vendor licensecheck's template set or skip Tier 4 and surface a manual-review flag instead.

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
