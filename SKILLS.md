# Security Skills — Справочник
**37 skills | Обновлено: 2026-04-12**

---

## Быстрый выбор по кейсу

| Кейс | Skills в порядке запуска |
|------|--------------------------|
| Black-box пентест | `recon-dominator` → `webapp-exploit-hunter` → `api-breaker` → `attack-path-architect` → `vuln-chain-composer` |
| Static code review | `security-review` → `source-code-scanning` → `injection` / `authentication` |
| Bug bounty | `bb-methodology-shuvonsec` → `idor-testing` → `web-app-logic` → `server-side` → `triage-validation-shuvonsec` → `report-writing-shuvonsec` |
| API пентест | `api-breaker` → `api-security` → `idor-testing` → `injection` |
| Финансовая логика | `web-app-logic` → `idor-testing` → `authentication` |
| AI/LLM приложение | `ai-threat-testing` → `server-side` → `injection` |
| Cloud инфраструктура | `cloud-pivot-finder` → `cloud-containers` → `infrastructure` |
| Отчёт для H1/Bugcrowd | `triage-validation-shuvonsec` → `report-writing-shuvonsec` |
| Reverse engineering | `ghidra-headless-tob` |
| CTF / HackTheBox | `hackthebox` → `system` → `infrastructure` |

---

## Группа 1: Orizon Pipeline (6 skills)
> Запускать последовательно. Каждый берёт output предыдущего.

### `recon-dominator`
**Что делает:** Полная разведка attack surface — endpoints, порты, tech stack, subdomains, wayback URLs.  
**Когда:** Первый шаг любого black-box теста.  
**Вызов:** `/recon-dominator http://localhost:5050`  
**Output:** `output/<target>/assets.json`, `subdomains.json`, `technologies.json`  
**Скриптов:** 8 Python

---

### `webapp-exploit-hunter`
**Что делает:** Автоматический поиск уязвимостей — SQLi, XSS, SSRF, IDOR, mass assignment, auth bypass, file upload, race conditions.  
**Когда:** После recon-dominator, или самостоятельно если знаешь target.  
**Вызов:** `/webapp-exploit-hunter http://localhost:5050`  
**Output:** `findings.json` с PoC для каждой уязвимости  
**Скриптов:** 11 Python

---

### `api-breaker`
**Что делает:** API-специфичное тестирование — реконструкция схем REST/GraphQL/SOAP, auth bypass, BOLA, mass assignment, rate limiting.  
**Когда:** Есть API endpoints (особенно GraphQL или REST без документации).  
**Вызов:** `/api-breaker http://localhost:5050`  
**Скриптов:** 8 Python

---

### `cloud-pivot-finder`
**Что делает:** Маппинг cloud инфраструктуры — S3 buckets, metadata endpoints, IAM misconfigs, exposed cloud services.  
**Когда:** Цель на AWS/GCP/Azure, или есть SSRF вектор.  
**Вызов:** `/cloud-pivot-finder http://target.com`  
**Скриптов:** 7 Python

---

### `attack-path-architect`
**Что делает:** Строит attack tree с MITRE ATT&CK mapping, скорит каждый путь (feasibility × impact × stealth).  
**Когда:** После сбора findings, нужен MITRE mapping или приоритизация.  
**Вызов:** `/attack-path-architect http://localhost:5050 findings: F-01 SQLi, F-04 SSRF ...`  
**⚠️ Важно:** `classify_assets.py` не парсит произвольный JSON — создавать `classified.json` вручную (формат: `{"assets": [{...}]}`).  
**Скриптов:** 3 Python

---

### `vuln-chain-composer`
**Что делает:** Собирает multi-step exploit chains, пересчитывает CVSS для цепочек, генерирует отчёт.  
**Когда:** Финальный шаг pipeline. Или когда есть 3+ findings и нужно показать worst-case.  
**Вызов:** `/vuln-chain-composer http://localhost:5050 findings: findings.json attack_tree: attack_tree.json`  
**⚠️ Важно:** correlate.py находит только generic chains — VulnBank-специфичные цепочки (SSRF→JWT, PIN ATO) дописывать вручную.  
**Скриптов:** 6 Python

---

## Группа 2: Специализированные (offensive, с reference материалами)

### `injection`
**Что делает:** SQL (UNION, error-based, time-based, blind), NoSQL, OS command, SSTI, XXE, LDAP injection.  
**Когда:** Есть подозрение на любой injection вектор, нужны конкретные payload'ы.  
**Вызов:** "Тестируй SQLi на POST /login"  
**Reference:** 15 файлов (cheatsheet'ы под MySQL/PostgreSQL/MSSQL, NoSQL, SSTI техники)

---

### `web-app-logic`
**Что делает:** Business logic flaws, race conditions, price manipulation, workflow bypass, cache poisoning.  
**Когда:** Финансовые приложения, coupon/discount системы, любые multi-step workflows.  
**Вызов:** "Ищи business logic уязвимости на http://localhost:5050"  
**Reference:** 19 файлов

---

### `server-side`
**Что делает:** SSRF (cloud metadata, internal services, protocol smuggling), HTTP Request Smuggling, XXE, deserialization.  
**Когда:** Есть URL-параметры, file upload, XML input, или подозрение на SSRF.  
**Reference:** 19 файлов

---

### `client-side`
**Что делает:** XSS (reflected/stored/DOM), CORS misconfig, Prototype Pollution, clickjacking, CSP bypass.  
**Когда:** Фронтенд с user input, SPA приложения, нужны XSS payload'ы.  
**Reference:** 13 файлов

---

### `authentication`
**Что делает:** JWT attacks (algorithm confusion, brute secret), OAuth flaws, 2FA bypass, credential stuffing, CAPTCHA bypass.  
**Когда:** Любая auth система, JWT токены, OAuth/SSO.  
**Reference:** 19 файлов

---

### `idor-testing`
**Что делает:** Systematic IDOR — horizontal/vertical escalation, Burp Intruder enumeration, static file IDOR, write-IDOR.  
**Когда:** Есть numeric IDs в URL/body, API endpoints с object references.  
**Вызов:** "Тестируй IDOR на http://localhost:5050"  
**Reference:** методология + примеры с PoC

---

### `api-security`
**Что делает:** GraphQL attacks (introspection, batching DoS, field suggestion), REST BOLA/mass assignment, WebSocket hijacking, Web-LLM attacks.  
**Когда:** GraphQL endpoint, REST API с документацией, WebSocket.  
**Reference:** 13 файлов

---

### `ai-threat-testing`
**Что делает:** OWASP LLM Top 10 — prompt injection (direct/indirect), rate limit bypass, DB exfiltration через LLM, system prompt extraction, excessive agency.  
**Когда:** Приложение имеет AI/LLM чат, API агент, RAG систему.  
**Reference:** 10 файлов

---

### `infrastructure`
**Что делает:** Network pentest — port scanning, DNS enum, Active Directory attacks, pivoting, VPN/firewall bypass.  
**Когда:** Internal network pentest, AD среда, нужен network-level тест.  
**Reference:** 18 файлов

---

### `cloud-containers`
**Что делает:** AWS/Azure/GCP misconfigs, Kubernetes RBAC, Docker escapes, container security, IAM privilege escalation.  
**Когда:** Цель в cloud, есть K8s/Docker, нужен cloud security review.  

---

### `system`
**Что делает:** Linux/Windows privilege escalation, post-exploitation, Active Directory attacks, lateral movement.  
**Когда:** Есть initial access, нужен privesc или lateral movement.  

---

### `osint`
**Что делает:** Внешний OSINT по компании — GitHub leaks, Shodan, leaked credentials, email enumeration, social media.  
**Когда:** Начало engagement, нужна разведка по организации (не по web app).  

---

## Группа 3: Static Analysis

### `security-review`
**Что делает:** Code review с HIGH/MED/LOW confidence. Трассирует data flow, проверяет attacker-controlled input, не флагает false positives.  
**Когда:** Есть исходники. Первый шаг любого white-box теста.  
**Вызов:** "Проведи security review ./static/vuln-bank"  
**Reference:** 20+ файлов (language guides: Python/JS/Go/Rust/Java + infrastructure)

---

### `source-code-scanning`
**Что делает:** CodeQL-уровень анализ — variant analysis (если найден паттерн, ищет похожие), SARIF output, differential review.  
**Когда:** После security-review, нужно найти все инстансы одного паттерна.  
**Reference:** 6 файлов

---

## Группа 4: Bug Bounty Pipeline

### `bb-methodology-shuvonsec`
**Что делает:** Mindset + 5-phase workflow для bug bounty — developer psychology, what-if experiments, как думать атакующим.  
**Когда:** Начало новой BB сессии, или потерял фокус что тестировать.  
**Вызов:** "Как подходить к тестированию http://target.com"

---

### `bug-bounty-main-shuvonsec`
**Что делает:** Полный BB pipeline — recon → subdomain enum → JS analysis → тестирование → валидация → отчёт.  
**Когда:** Bug bounty engagement от начала до конца.  

---

### `triage-validation-shuvonsec`
**Что делает:** 7-Question Gate — убивает false positives до написания отчёта. Проверяет: есть ли реальный impact, воспроизводимость, уникальность.  
**Когда:** Перед написанием любого отчёта. Обязательно при BB.  
**Вызов:** "Валидируй этот finding: [описание]"

---

### `report-writing-shuvonsec`
**Что делает:** Генерирует H1/Bugcrowd/Intigriti/Immunefi отчёты. Impact-first стиль, без "could potentially", с CVSS 3.1.  
**Когда:** После валидации finding'а, нужен platform-ready отчёт.  
**Вызов:** "Напиши H1 отчёт для этого finding'а: [описание]"

---

### `transilience-report-style`
**Что делает:** PDF отчёты в стиле Transilience — Threat Intelligence формат для команды/менеджмента.  
**Когда:** Нужен формальный отчёт для внутреннего использования.  

---

### `hackerone`
**Что делает:** Автоматизация H1 — парсинг scope, управление submissions, работа с программами.  
**Когда:** Активная работа с H1 платформой.  

---

## Группа 5: Инструменты / Утилиты

### `techstack-identification`
**Что делает:** OSINT-based fingerprint tech stack — CMS, frameworks, серверы, cloud provider, без активного сканирования.  
**Когда:** Нужно определить стек до активного тестирования.  
**Вызов:** "Определи стек http://localhost:5050"

---

### `security-arsenal-shuvonsec`
**Что делает:** Готовые payload'ы, bypass таблицы, wordlists, gf patterns для различных классов уязвимостей.  
**Когда:** Нужны конкретные payload'ы под WAF bypass, encoding, специфичные техники.  
**Вызов:** "Дай payload'ы для XSS bypass WAF"

---

### `web2-vuln-classes-shuvonsec`
**Что делает:** Справочник 20 классов web2 уязвимостей с примерами из реальных H1 отчётов.  
**Когда:** Нужно понять конкретный класс уязвимости или найти примеры.  

---

### `cve-poc-generator`
**Что делает:** Исследует CVE, генерирует standalone PoC скрипт, пишет отчёт.  
**Когда:** Нашёл outdated компонент с CVE, нужен работающий PoC.  
**Вызов:** "Сгенерируй PoC для CVE-2024-XXXXX"

---

### `ffuf-web-fuzzing-tob`
**Что делает:** Expert guidance по ffuf — wordlist выбор, фильтрация результатов, рекурсивный fuzzing, rate limiting.  
**Когда:** Нужен directory/parameter fuzzing с ffuf (требует ffuf установленный).  

---

### `ghidra-headless-tob`
**Что делает:** Reverse engineering бинарей через Ghidra headless — деcompиляция, поиск функций, анализ без GUI.  
**Когда:** CTF с бинарём, malware analysis, нужен RE без открытия GUI.  
**Скриптов:** 8 Python

---

### `shannon`
**Что делает:** Автономный пентестер — анализирует исходники, запускает реальные эксплойты, 96% exploit success rate.  
**Когда:** Есть исходники + нужен fully autonomous pentest.  
**⚠️ Требует:** `ANTHROPIC_API_KEY` в env + Docker  
**Вызов:** `/shannon http://host.docker.internal:5050 vuln-bank`

---

### `hackthebox`
**Что делает:** Автоматизация HTB — login, выбор машины, VPN, делегирует решение pentest агентам.  
**Когда:** Работа с HackTheBox платформой.  

---

### `auth-bypass-testing`
**Что делает:** Методология тестирования broken authentication — password policy, session handling, MFA, credential management.  
**Когда:** Нужен checklist по auth (менее детальный чем `authentication`).  
**Лучший аналог:** `authentication` (19 ref файлов vs только SKILL.md)

---

### `coordination`
**Что делает:** Multi-agent pentest orchestration через slash команды.  
**Когда:** Нужен полный пентест с координацией нескольких агентов.  
**Вызов:** `/coordination http://localhost:5050`

---

### `skiller`
**Что делает:** Создание и управление skills — генерирует структуру, валидирует best practices.  
**Когда:** Нужно создать новый skill.  

---

## Связка всех инструментов

Да, можно сделать единую обвязку. Три варианта:

### Вариант A: Slash команда `/pentest`
Один вызов — полный цикл. Создать skill `pentest` который:
1. Определяет кейс (black-box / white-box / bug-bounty)
2. Запускает нужную последовательность скиллов
3. Собирает output в единый отчёт

### Вариант B: CLAUDE.md workflow rules
Добавить в CLAUDE.md правила автоматического выбора скиллов:
- "При тестировании API — всегда api-breaker + injection"
- "Перед любым отчётом — triage-validation-shuvonsec"
- "После findings — attack-path-architect если 3+ Critical"

### Вариант C: Мета-скилл с роутингом
Один skill-оркестратор который читает тип цели и автоматически
вызывает правильную цепочку (аналог `coordination` но с Orizon pipeline).

**Самый практичный сейчас:** Вариант B (изменение CLAUDE.md) — работает сразу без кода.
Вариант A/C — потребует создать новый skill через `skiller`.

Хочешь сделать одну из этих обвязок?
