# SPDX-License-Identifier: MIT
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lab_values import LAB_TENANT_ID  # noqa: E402


@pytest.fixture(autouse=True)
def _lab_tenant(monkeypatch):
    """Every test runs with the placeholder lab tenant configured (G-1, ADR 0008)."""
    monkeypatch.setenv("REJEWSKI_LAB_TENANT_ID", LAB_TENANT_ID)
