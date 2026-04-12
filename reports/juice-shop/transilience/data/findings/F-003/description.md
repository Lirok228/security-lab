# F-003: JWT Algorithm Confusion (alg:none) — Broken Authentication

## Summary

OWASP Juice Shop принимает JWT-токены с алгоритмом `none` (без цифровой подписи) для аутентификации запросов к защищённым API-endpoint-ам. Злоумышленник может создать произвольный JWT-токен с любыми claims (включая `role: admin`) без знания приватного ключа, после чего получить доступ к административным ресурсам.

## Vulnerability Details

| Field | Value |
|-------|-------|
| **CWE** | CWE-347: Improper Verification of Cryptographic Signature |
| **OWASP Top 10** | A02:2021 — Cryptographic Failures / A07:2021 — Identification and Authentication Failures |
| **CVSS 3.1 Score** | 9.8 (CRITICAL) |
| **CVSS Vector** | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| **Severity** | CRITICAL |

## Technical Description

Juice Shop выпускает JWT-токены с алгоритмом `RS256` (RSA + SHA-256), при котором токен подписывается приватным ключом, а сервер верифицирует подпись публичным ключом.

Уязвимость заключается в том, что сервер **не запрещает алгоритм `none`** при верификации входящих токенов. RFC 7518 описывает `none` как допустимый алгоритм ("unsecured JWTs"), однако любая production-система должна явно отклонять его. Если сервер принимает `alg: none`, он пропускает проверку подписи целиком, что позволяет атакующему:

1. Создать заголовок: `{"typ":"JWT","alg":"none"}`
2. Создать произвольный payload с нужными claims, например `{"role":"admin"}`
3. Собрать токен с пустой подписью: `header.payload.`
4. Использовать этот токен для доступа к защищённым endpoints

## Confirmed Vulnerable Endpoints

| Endpoint | Method | HTTP Status with alg:none |
|----------|--------|--------------------------|
| `/api/Users/` | GET | 200 — полная БД пользователей |
| `/api/Feedbacks/` | GET | 200 |
| `/api/Complaints/` | GET | 200 |
| `/rest/admin/application-version` | GET | 200 |

Endpoint `/rest/user/whoami` возвращает пустой объект `{"user":{}}` при alg:none — это значит токен технически принят, но claims из него не загружаются в сессию (частичная защита). Однако критические admin REST endpoints всё равно возвращают данные.

## Impact

- **Confidentiality**: полная утечка базы пользователей (22 аккаунта), включая email, хэши паролей, роли, deluxeToken
- **Integrity**: потенциальная возможность записи/модификации данных через другие admin endpoints
- **Authentication bypass**: любой неаутентифицированный пользователь может сформировать admin-токен без учётных данных
- **Privilege escalation**: клиент с ролью customer может переписать себе роль admin в payload

## Root Cause

Библиотека верификации JWT на сервере не настроена с явным whitelist допустимых алгоритмов. При обработке входящего токена с `alg: none` библиотека пропускает шаг криптографической проверки.

## Remediation

### Немедленные меры

1. **Запретить `alg: none` явно**: при инициализации JWT middleware передать allowedAlgorithms: `['RS256']` и отклонять все остальные значения.

   ```javascript
   // Node.js / jsonwebtoken
   jwt.verify(token, publicKey, { algorithms: ['RS256'] });
   ```

2. **Проверять поле `alg` перед верификацией**: если `header.alg !== 'RS256'` — немедленно отклонять с 401.

### Долгосрочные меры

3. Использовать проверенные JWT-библиотеки последних версий (например, `jose` вместо `jsonwebtoken`), которые по умолчанию требуют явного указания алгоритма.
4. Добавить интеграционные тесты: попытка использовать `alg: none` должна возвращать 401.
5. Включить мониторинг: алерт при появлении в логах JWT с `alg: none`.

## References

- [RFC 7518 §3.6 — "none" Algorithm](https://datatracker.ietf.org/doc/html/rfc7518#section-3.6)
- [PortSwigger: JWT alg:none attack](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification)
- [CWE-347](https://cwe.mitre.org/data/definitions/347.html)
