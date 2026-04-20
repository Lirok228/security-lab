# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Контекст
AI-driven security testing. Цель задаётся пользователем в каждой сессии.
Оператор: AppSec специалист / Security Business Partner.

## Dashboard

```bash
# Запустить dashboard с результатами (http://localhost:7777)
docker compose -f docker-compose.dashboard.yml up -d --build
```

## Правила
1. Тестировать ТОЛЬКО цель, указанную пользователем в текущей сессии
2. НЕ отправлять запросы на хосты, не указанные явно
3. Все файлы → `./projects/{таргет}/{агент}/`
4. Каждый finding: severity (CVSS 3.1), CWE ID, описание, PoC команда, remediation
5. Язык отчётов: русский, технические термины на английском

## Структура проектов

```
projects/<target>/
├── <agent>/              # orizon, manual, transilience, shannon…
│   ├── recon/
│   ├── findings/finding-NNN/
│   │   ├── description.md
│   │   ├── poc.py
│   │   └── evidence/
│   ├── logs/
│   ├── artifacts/{certs,tickets,captures,loot}/
│   └── report.md         # отчёт агента
├── FINAL-REPORT.md       # сводный отчёт для разработчиков/ИТ
└── AGENTS-COMPARISON.md  # внутренний анализ: какой агент что нашёл
```

**`FINAL-REPORT.md`** — объединяет findings всех агентов, дедуплицирует, ранжирует по severity. Формат: понятный разработчику (что сломано, как воспроизвести, как исправить). Создаётся после завершения всех агентов.

**`AGENTS-COMPARISON.md`** — внутренний документ для анализа эффективности агентов. Содержит:
- Матрицу: уязвимость × агент (кто что нашёл)
- Уникальные findings каждого агента
- Время работы, количество findings, процент покрытия
- Выводы: какой агент сильнее в каком классе уязвимостей

Перед запуском любого инструмента (nmap, sqlmap, dirsearch, certipy…) направить вывод в нужную поддиректорию через `-o`/`-oN` флаг или `cd` туда заранее.

## Переменные окружения / credentials

**ОБЯЗАТЕЛЬНО** читать из `.env` перед тем, как спрашивать пользователя:

```bash
python3 .claude/tools/env-reader.py VAR1 VAR2 VAR3
```

Спрашивать пользователя только если `env-reader.py` вернул `NOT_SET`.  
**НИКОГДА** не читать `.env` через `source .env`, `cat .env` или `echo $VAR` — это не работает (каждый Bash вызов — чистый shell).

## Директории
- `./projects/` — все данные по таргетам (артефакты + отчёты агентов + FINAL-REPORT)
- `./reports/SUMMARY.md` — сводная таблица всех тестов (все таргеты, все агенты)
- `./configs/` — scan profiles, wordlists, кастомные правила
- `./static/` — клонированные исходники для sentry-review (gitignore)
- `./.claude/agents/` — определения агентов (см. `AGENTS.md`)
- `./.claude/skills/` — установленные skills (см. `SKILLS.md`)

## Агенты для сравнения

Цель: сравнить что каждый агент находит по одному таргету. Структура: `./projects/{таргет}/{агент}/`

| Агент | Тип | Описание |
|-------|-----|---------|
| shannon | hybrid (white+black box) | Autonomous pentest, Docker-based |
| transilience | multi-agent, dynamic | `/coordination` slash command |
| manual | black box, свободный | Claude Code без спец-skills |
| sentry-review | static, code review | security-review skill, нужны исходники в `./static/` |
| orizon | full pipeline | recon → exploit → chain composition |

Сводная таблица: `./reports/SUMMARY.md`

## Installed Skills
Полный справочник с описанием каждого: `SKILLS.md`

**Быстрый выбор:**

| Кейс | Skills в порядке запуска |
|------|--------------------------|
| Black-box пентест | `recon-dominator` → `webapp-exploit-hunter` → `api-breaker` → `attack-path-architect` → `vuln-chain-composer` |
| Static code review | `security-review` → `source-code-scanning` |
| Bug bounty | `bb-methodology-shuvonsec` → `idor-testing` → `triage-validation-shuvonsec` → `report-writing-shuvonsec` |
| API пентест | `api-breaker` → `api-security` → `injection` |
| AI/LLM приложение | `ai-threat-testing` → `server-side` → `injection` |

## Agents (.claude/agents/)
Полная документация: `AGENTS.md`

| Агент | Роль |
|-------|------|
| pentester-orchestrator | Координация, планирование, делегирует ВСЁ sub-агентам |
| pentester-executor | Выполнение конкретных тестов уязвимостей |
| pentester-validator | Верификация findings по raw evidence (5 checks) |
| script-generator | Генерация валидированных exploit scripts |
| hackerone | Bug bounty автоматизация, парсинг scope, submissions |
| hackthebox | Автоматизация HTB (Playwright + VPN + pentest агенты) |

**Docker mode**: executor/validator запускаются в изолированных Kali контейнерах. Требует `ANTHROPIC_API_KEY` в env (login-auth не работает в контейнерах).

## Slash Commands (из transilienceai)
- `/coordination <url>` — полный multi-agent пентест
- `/reconnaissance <url>` — маппинг attack surface
- `/techstack-identification` — определение стека
- `/source-code-scanning <path>` — static analysis

## Workflow
1. Определить стек → `/techstack-identification`
2. Маппинг → `/reconnaissance`
3. Source code review → `security-review` skill (если есть исходники в `./static/`)
4. Dynamic testing → curl / Playwright / sqlmap
5. Validate → каждый finding confirmed exploitable
6. Report → `./projects/{таргет}/{агент}/report.md`
7. После всех агентов → собрать `./projects/{таргет}/FINAL-REPORT.md` и `AGENTS-COMPARISON.md`
8. Обновить `./reports/SUMMARY.md`
