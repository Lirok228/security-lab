# Security Review: medclinic (FastAPI)

**Дата:** 2026-04-12  
**Метод:** Static analysis (getsentry/security-review skill)  
**Путь:** `./static/medclinic/`  
**Стек:** Python, FastAPI, SQLAlchemy, SQLite, JWT (python-jose), bcrypt

---

### Summary

- **Findings:** 11 (6 Critical, 5 High)
- **Risk Level:** Critical
- **Confidence:** High — все уязвимости подтверждены трассировкой данных

Медицинское приложение содержит критические уязвимости на уровне аутентификации, авторизации и контроля доступа. Несколько эндпоинтов полностью лишены защиты, что позволяет неаутентифицированному злоумышленнику читать и удалять медицинские записи, а также получать API-ключи всех пользователей.

---

## Findings

---

### [VULN-001] Hardcoded JWT Secret Key (Critical)

- **Location:** `app/auth.py:14`
- **Confidence:** High
- **Issue:** JWT secret захардкожен в исходном коде. Любой, кто получит доступ к репозиторию, может форжировать произвольные JWT-токены с любым `user_id` и `role`.
- **Impact:** Полный обход аутентификации — злышленник создаёт токен с `role: admin` без каких-либо учётных данных.
- **Evidence:**
  ```python
  SECRET_KEY = "super-secret-key-not-for-production-medclinic-2024"
  ALGORITHM = "HS256"
  # ...
  return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)  # auth.py:35
  ```
- **Fix:** Загружать из переменной окружения: `SECRET_KEY = os.environ["JWT_SECRET_KEY"]`. Ротировать ключ при любом подозрении на компрометацию.

---

### [VULN-002] Unauthenticated `GET /api/admin/users` — Full User Enumeration (Critical)

- **Location:** `app/routers/admin.py:47-64`
- **Confidence:** High
- **Issue:** Эндпоинт `GET /api/admin/users` не имеет **никакого** dependency на аутентификацию. Возвращает список всех пользователей системы включая `email`, `role`, `api_key`, `created_at`.
- **Impact:** Неаутентифицированный злоумышленник получает API-ключи всех пользователей (включая врачей и администраторов), что открывает доступ к любым эндпоинтам.
- **Evidence:**
  ```python
  @router.get("/users", response_model=List[UserAdminResponse])
  def list_users(
      db: Session = Depends(get_db),   # ← нет get_current_user / require_role
  ):
      users = db.query(User).all()
      return [UserAdminResponse(..., api_key=u.api_key, ...) for u in users]
  ```
- **Fix:** Добавить `current_user: User = Depends(require_role(["admin"]))`.

---

### [VULN-003] Unauthenticated `POST /api/records/` — Create Medical Records Without Auth (Critical)

- **Location:** `app/routers/medical_records.py:96-116`
- **Confidence:** High
- **Issue:** `create_record` использует `get_current_user_optional` — аутентификация опциональна. При отсутствии токена создаётся запись с `doctor_id=0`.
- **Impact:** Любой интернет-пользователь может создавать медицинские записи для любого пациента (по `patient_id`).
- **Evidence:**
  ```python
  @router.post("/", ...)
  def create_record(
      request: MedicalRecordCreateRequest,
      current_user: User = Depends(get_current_user_optional),  # ← optional!
      db: Session = Depends(get_db),
  ):
      doctor_id = current_user.id if current_user else 0   # ← анонимный создатель
      record = MedicalRecord(patient_id=request.patient_id, ...)
  ```
- **Fix:** Заменить на `Depends(require_role(["doctor", "admin"]))`.

---

### [VULN-004] Unauthenticated `DELETE /api/records/{id}` — Delete Any Medical Record (Critical)

- **Location:** `app/routers/medical_records.py:119-131`
- **Confidence:** High
- **Issue:** Эндпоинт удаления медицинских записей полностью лишён аутентификации.
- **Impact:** Неаутентифицированный злоумышленник может уничтожить любую медицинскую запись, перебирая `record_id`.
- **Evidence:**
  ```python
  @router.delete("/{record_id}")
  def delete_record(
      record_id: int,
      db: Session = Depends(get_db),   # ← нет аутентификации вообще
  ):
      record = db.query(MedicalRecord).filter(MedicalRecord.id == record_id).first()
      db.delete(record)
      db.commit()
  ```
- **Fix:** Добавить `current_user: User = Depends(require_role(["doctor", "admin"]))` и проверку принадлежности записи.

---

### [VULN-005] Privilege Escalation via `PUT /api/patients/{id}` (Critical)

- **Location:** `app/routers/patients.py:97-139`
- **Confidence:** High
- **Issue:** Эндпоинт принимает поле `role` в теле запроса и записывает его напрямую в `User.role` **без проверки прав**. Любой аутентифицированный пользователь может повысить роль любого пользователя до `admin`.
- **Impact:** Полное горизонтальное и вертикальное повышение привилегий. Пациент → admin за один HTTP-запрос.
- **Evidence:**
  ```python
  class PatientUpdateRequest(BaseModel):
      ...
      role: Optional[str] = None      # ← принимается от пользователя

  def update_patient(patient_id: int, update: PatientUpdateRequest, ...):
      # нет проверки: может ли current_user менять роль?
      if "role" in update_data and update_data["role"]:
          user = db.query(User).filter(User.id == profile.user_id).first()
          user.role = update_data["role"]   # ← запись роли без проверок
  ```
  ```bash
  # PoC: пациент повышает себя до admin
  PUT /api/patients/1 {"role": "admin"}
  ```
- **Fix:** Удалить поле `role` из `PatientUpdateRequest`. Смена роли должна быть отдельным admin-эндпоинтом с `require_role(["admin"])`.

---

### [VULN-006] Role Injection at Registration (Critical)

- **Location:** `app/routers/auth_router.py:24-28, 71-95`
- **Confidence:** High
- **Issue:** Эндпоинт регистрации принимает `role` как произвольную строку с дефолтом `"patient"`. Нет валидации допустимых значений.
- **Impact:** Злоумышленник регистрирует аккаунт с `role: "admin"` или `role: "doctor"` и получает соответствующий доступ немедленно.
- **Evidence:**
  ```python
  class RegisterRequest(BaseModel):
      email: str
      name: str
      password: str
      role: str = "patient"   # ← нет ограничений на значение

  # api_key содержит role в открытом виде:
  api_key = f"pk_{request.role}_{request.name.split()[0].lower()}_{secrets.token_hex(4)}"
  # → pk_admin_john_a1b2c3d4 — предсказуемый формат, 4 байта entropy
  ```
  ```bash
  # PoC:
  POST /api/auth/register {"email":"hacker@evil.com","name":"Hacker","password":"x","role":"admin"}
  ```
- **Fix:** Добавить `role: Literal["patient"] = "patient"` (только пациенты могут самостоятельно регистрироваться). Использовать `secrets.token_hex(16)` для API key.

---

### [VULN-007] Path Traversal in `GET /api/files/download/{filename}` (High)

- **Location:** `app/routers/files.py:82-93`
- **Confidence:** High
- **Issue:** `filename` из URL напрямую конкатенируется с `UPLOAD_DIR` без проверки. `Path("uploads") / "../app/auth.py"` резолвится в `app/auth.py`.
- **Impact:** Чтение произвольных файлов на сервере: исходный код, конфиги, БД (`medclinic.db`), секреты.
- **Evidence:**
  ```python
  UPLOAD_DIR = Path("uploads")

  @router.get("/download/{filename}")
  def download_file(filename: str, current_user: User = Depends(get_current_user)):
      file_path = UPLOAD_DIR / filename          # ← нет sanitization
      if not file_path.exists():
          raise HTTPException(status_code=404, ...)
      return FileResponse(path=str(file_path), filename=filename)
  ```
  ```bash
  # PoC: читаем базу данных
  GET /api/files/download/..%2Fmedclinic.db
  GET /api/files/download/..%2Fapp%2Fauth.py
  ```
- **Fix:**
  ```python
  resolved = (UPLOAD_DIR / filename).resolve()
  if not str(resolved).startswith(str(UPLOAD_DIR.resolve())):
      raise HTTPException(status_code=400, detail="Invalid filename")
  ```

---

### [VULN-008] IDOR — Patient Reads Any Medical Record (High)

- **Location:** `app/routers/medical_records.py:68-79` и `82-93`
- **Confidence:** High
- **Issue (A):** `GET /api/records/{record_id}` аутентифицирует пользователя, но не проверяет принадлежность записи. Пациент читает записи других пациентов по ID.
- **Issue (B):** `GET /api/records/patient/{patient_id}` — проверка роли сломана: `if current_user.role == "patient": pass` — оператор `pass` ничего не делает. Любой пациент получает записи любого другого пациента.
- **Impact:** Полная утечка медицинских данных (диагнозы, результаты анализов, заметки врача).
- **Evidence:**
  ```python
  # Issue A: нет ownership check
  def get_record(record_id: int, current_user: User = Depends(get_current_user), ...):
      record = db.query(MedicalRecord).filter(MedicalRecord.id == record_id).first()
      return _enrich_record(record, db)   # ← не проверяем record.patient_id == current_user.id

  # Issue B: сломанная проверка
  def get_patient_records(patient_id: int, current_user: User = Depends(get_current_user), ...):
      if current_user.role == "patient":
          pass   # ← ничего не делает! пациент должен видеть только свои записи
      records = db.query(MedicalRecord).filter(MedicalRecord.patient_id == patient_id).all()
  ```
- **Fix (A):** Добавить проверку `if current_user.role == "patient" and record.patient_id != current_user.id: raise HTTPException(403)`.  
  **Fix (B):** Заменить `pass` на `if patient_id != current_user.id: raise HTTPException(403)`.

---

### [VULN-009] IDOR — Patient Reads Any Other Patient's Prescriptions (High)

- **Location:** `app/routers/prescriptions.py:96-107`
- **Confidence:** High
- **Issue:** Та же сломанная проверка `if current_user.role == "patient": pass` — пациент видит рецепты любого другого пациента.
- **Evidence:**
  ```python
  def get_patient_prescriptions(patient_id: int, current_user: User = Depends(get_current_user), ...):
      if current_user.role == "patient":
          pass   # ← не защищает
      prescriptions = db.query(Prescription).filter(Prescription.patient_id == patient_id).all()
  ```
- **Fix:** `if current_user.role == "patient" and patient_id != current_user.id: raise HTTPException(403)`.

---

### [VULN-010] IDOR — Any Authenticated User Reads/Deletes Any File (High)

- **Location:** `app/routers/files.py:61-79` (get_file_info), `135-152` (delete_file)
- **Confidence:** High
- **Issue:** `GET /api/files/{file_id}` и `DELETE /api/files/{file_id}` проверяют аутентификацию, но не проверяют, что файл принадлежит `current_user`.
- **Impact:** Пациент читает метаданные и удаляет медицинские файлы других пациентов.
- **Evidence:**
  ```python
  def get_file_info(file_id: int, current_user: User = Depends(get_current_user), ...):
      file = db.query(File).filter(File.id == file_id).first()
      return FileResponse_(...)   # ← нет проверки file.owner_id == current_user.id

  def delete_file(file_id: int, current_user: User = Depends(get_current_user), ...):
      file = db.query(File).filter(File.id == file_id).first()
      file_path.unlink()          # ← нет проверки принадлежности
      db.delete(file)
  ```
- **Fix:** Добавить `if current_user.role == "patient" and file.owner_id != current_user.id: raise HTTPException(403)`.

---

### [VULN-011] Any Authenticated User Reads All Patient PII (High)

- **Location:** `app/routers/patients.py:43-67`
- **Confidence:** High
- **Issue:** `GET /api/patients/` доступен любому аутентифицированному пользователю (включая пациентов). Возвращает полный список пациентов с PII: ФИО, email, дата рождения, группа крови, аллергии, номер страховки, адрес, контакт экстренной помощи.
- **Impact:** Пациент видит медицинские данные всех других пациентов.
- **Evidence:**
  ```python
  @router.get("/", response_model=List[PatientProfileResponse])
  def list_patients(
      current_user: User = Depends(get_current_user),   # ← только auth, нет role check
      db: Session = Depends(get_db),
  ):
      profiles = db.query(PatientProfile).all()   # ← все пациенты
      # возвращает: allergies, insurance_number, address, emergency_contact...
  ```
- **Fix:** Добавить `Depends(require_role(["doctor", "nurse", "receptionist", "admin"]))`. Пациент должен видеть только свой профиль.

---

## Needs Verification

### [VERIFY-001] `require_role_weak` используется в admin-эндпоинтах

- **Location:** `app/auth.py:118-131`, `app/routers/admin.py:92`
- **Question:** `require_role_weak` допускает case-insensitive сравнение (`"Admin"` == `"admin"`). Если роль хранится в БД в виде, который можно манипулировать (например, через VULN-005 или VULN-006), это может открыть доступ. Проверить, возможно ли хранение роли в нестандартном регистре.

---

## Итоговая таблица

| ID | Severity | CVSS (est.) | Эндпоинт | Уязвимость |
|----|----------|-------------|----------|------------|
| VULN-001 | Critical | 9.1 | Весь сервис | Hardcoded JWT secret |
| VULN-002 | Critical | 9.8 | `GET /api/admin/users` | Нет аутентификации, утечка API keys |
| VULN-003 | Critical | 8.6 | `POST /api/records/` | Нет аутентификации |
| VULN-004 | Critical | 9.1 | `DELETE /api/records/{id}` | Нет аутентификации |
| VULN-005 | Critical | 8.8 | `PUT /api/patients/{id}` | Privilege escalation через role field |
| VULN-006 | Critical | 9.8 | `POST /api/auth/register` | Role injection при регистрации |
| VULN-007 | High | 7.5 | `GET /api/files/download/{filename}` | Path traversal |
| VULN-008 | High | 7.5 | `GET /api/records/{id}`, `/patient/{id}` | IDOR + broken role check |
| VULN-009 | High | 7.5 | `GET /api/prescriptions/patient/{id}` | IDOR (broken role check) |
| VULN-010 | High | 6.5 | `GET/DELETE /api/files/{id}` | IDOR на файлы |
| VULN-011 | High | 6.5 | `GET /api/patients/` | Нет role check, полная утечка PII |
