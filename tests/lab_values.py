# SPDX-License-Identifier: MIT
"""Placeholder lab-tenant values shared by the test suite.

None of these identify a real tenant or account. conftest.py sets
REJEWSKI_LAB_TENANT_ID to LAB_TENANT_ID for every test, so the G-1 gate treats it
as the operator's lab tenant (the v1 consent record is enough).
"""

LAB_TENANT_ID = "c0ffee00-0000-4000-8000-000000000001"
LAB_TENANT_SHORT = "c0ffee00"
LAB_DOMAIN = "lab.example"
LAB_ACTOR_UPN = f"meganb@{LAB_DOMAIN}"
LAB_OPERATOR_OBJECT_ID = "0b5e7a70-0000-4000-8000-000000000002"
LAB_OPERATOR_EMAIL = f"operator@{LAB_DOMAIN}"
