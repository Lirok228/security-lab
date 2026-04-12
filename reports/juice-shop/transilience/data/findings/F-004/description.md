# F-004: Broken Access Control / IDOR — OWASP Juice Shop

## Severity

**CRITICAL** — CVSS 3.1 Score: **9.1**

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
```

- Attack Vector: Network
- Attack Complexity: Low
- Privileges Required: Low (для F-004-A, F-004-C) / None (для F-004-B)
- User Interaction: None
- Confidentiality Impact: High
- Integrity Impact: High
- Availability Impact: None

## CWE

- CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)
- CWE-284: Improper Access Control
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

## OWASP Top 10 (2021)

- A01:2021 — Broken Access Control

---

## Описание

В приложении OWASP Juice Shop обнаружены четыре взаимосвязанные уязвимости класса Broken Access Control / IDOR. Они позволяют аутентифицированному пользователю или анонимному атакующему получить несанкционированный доступ к данным других пользователей, включая credentials, роли, токены и чувствительные персональные данные.

---

## Sub-findings

### F-004-A: IDOR — GET /api/Users/{id} (Horizontal Privilege Escalation)

**Severity**: HIGH (CVSS 7.5)

**Уязвимый endpoint**: `GET /api/Users/{id}`

**Описание**: API `/api/Users/` не реализует проверку владельца ресурса. Любой аутентифицированный пользователь может запросить данные произвольного пользователя по числовому ID. При перечислении ID 1–21 атакующий получает email, роль, profileImage всех зарегистрированных пользователей, включая admin.

**Воспроизведение**:
```bash
# bender@juice-sh.op (id=3) читает данные admin (id=1)
curl -s http://localhost:3000/api/Users/1 \
  -H "Authorization: Bearer <USER_TOKEN>"
# HTTP 200 — возвращает email=admin@juice-sh.op, role=admin
```

**Результат**: HTTP 200, данные admin@juice-sh.op (role=admin) доступны пользователю с role=customer. Подтверждено 3 раза.

---

### F-004-B: Unauthenticated Exposure of Password Hashes via /rest/memories (CRITICAL)

**Severity**: CRITICAL (CVSS 9.1)

**Уязвимый endpoint**: `GET /rest/memories`

**Описание**: Endpoint `/rest/memories` возвращает список воспоминаний пользователей без какой-либо аутентификации. В ответе каждый объект памяти включает вложенный объект `User`, содержащий MD5-хэш пароля (`password`), `deluxeToken`, `email`, `role` и другие атрибуты. Хэши подвержены атаке по словарю (MD5 без соли).

**Воспроизведение**:
```bash
# Без токена — полный список memories с хэшами паролей
curl -s http://localhost:3000/rest/memories
# Возвращает: {"User": {"email":"bjoern@owasp.org","password":"9283f1b2e9669749081963be0462e466","role":"deluxe","deluxeToken":"efe2f..."}}
```

**Exposed credentials (sample)**:
| Email | MD5 Hash | Role |
|-------|----------|------|
| bjoern@owasp.org | 9283f1b2e9669749081963be0462e466 | deluxe |
| bjoern.kimminich@gmail.com | 6edd9d726cbdc873c539e41ae8757b8c | admin |

Подтверждено 3 раза. Не требует аутентификации.

---

### F-004-C: Broken Access Control — /rest/user/authentication-details/ (Vertical Privilege Escalation)

**Severity**: HIGH (CVSS 8.1)

**Уязвимый endpoint**: `GET /rest/user/authentication-details/`

**Описание**: Endpoint должен быть доступен только администраторам, однако принимает токен любого аутентифицированного пользователя и возвращает полный список всех 21 зарегистрированных пользователей с email, ролью, lastLoginIp, profileImage, totpSecret. Пароли маскируются (`****`), однако утечка структуры данных всех пользователей представляет значимый риск.

**Воспроизведение**:
```bash
# Regular user bender (role=customer) получает список всех пользователей
curl -s http://localhost:3000/rest/user/authentication-details/ \
  -H "Authorization: Bearer <USER_TOKEN>"
# HTTP 200 — возвращает 21 пользователя: admin, customer, deluxe аккаунты
```

**Результат**: HTTP 200, список всех 21 пользователей. Подтверждено 3 раза.

---

### F-004-D: Information Disclosure — /api/Challenges/ (MEDIUM)

**Severity**: MEDIUM (CVSS 5.3)

**Уязвимый endpoint**: `GET /api/Challenges/`

**Описание**: Endpoint возвращает полный список из 111 challenges приложения без аутентификации, включая описания, категории, difficulty level и ссылки на mitigation. Это помогает атакующему составить полную карту attack surface и известных уязвимостей приложения, значительно ускоряя разведку.

**Воспроизведение**:
```bash
curl -s http://localhost:3000/api/Challenges/ | python3 -c "
import sys,json
d=json.loads(sys.stdin.read())
print(f'Challenges: {len(d[\"data\"])}')
"
# Challenges: 111 — без токена
```

---

## Impact

1. **F-004-B (CRITICAL)**: Атакующий без аутентификации получает MD5-хэши паролей нескольких пользователей (включая admin-ролей). MD5 без соли тривиально взламывается через rainbow tables / crackstation.net. Полная компрометация аккаунтов.

2. **F-004-C (HIGH)**: Любой зарегистрированный пользователь получает полный список пользователей системы, включая admin-аккаунты. Используется для таргетированных атак.

3. **F-004-A (HIGH)**: Горизонтальная эскалация — пользователь может получить данные любого другого пользователя по ID. В комбинации с F-004-B — полная компрометация всей базы пользователей.

4. **F-004-D (MEDIUM)**: Атакующий знает все существующие векторы атак в приложении, что сокращает время пентеста/атаки.

---

## Remediation

### Немедленные меры (Priority 1)

1. **F-004-B** — Удалить объект `User` из ответа `/rest/memories`, либо включить только non-sensitive поля (username, profileImage). **Никогда** не передавать password hash через API.

2. **F-004-C** — Добавить проверку роли (`isAdmin`) на endpoint `/rest/user/authentication-details/`. Возвращать 403 для non-admin токенов.

3. **F-004-A** — Реализовать ownership check: `if (req.user.id !== requestedUserId && !req.user.isAdmin) return 403`.

### Среднесрочные меры (Priority 2)

4. **Passwords** — Заменить MD5 на bcrypt/Argon2 с солью для хранения паролей.

5. **F-004-D** — Закрыть `/api/Challenges/` для production, либо требовать admin-токен.

6. **Общее** — Внедрить централизованную проверку авторизации (middleware) с принципом deny-by-default.

7. **Аудит** — Провести полный аудит всех REST API endpoints на наличие missing authorization checks.

### Код (пример fix для F-004-A в Express):
```javascript
router.get('/Users/:id', security.isAuthorized(), (req, res) => {
  const requestedId = parseInt(req.params.id);
  const currentUser = security.authenticatedUsers.get(req.headers.authorization);
  
  if (currentUser.data.id !== requestedId && currentUser.data.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  // ... proceed with data retrieval
});
```

---

## References

- [OWASP A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [OWASP ASVS v5.0 — V4: Access Control](https://owasp.org/www-project-application-security-verification-standard/)
