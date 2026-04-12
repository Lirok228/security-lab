# Security Testing Lab

## Контекст
Локальный полигон для AI-driven security testing.
Все приложения — intentionally vulnerable, развёрнуты в Docker.
Оператор: AppSec специалист / Security Business Partner.

## Целевые приложения (Docker, все на localhost)

| App | URL | Стек | Логин |
|-----|-----|------|-------|
| Juice Shop | http://localhost:3000 | Node.js, Angular | — |
| VAmPI | http://localhost:5001 | Python Flask REST API | — |
| medclinic | http://localhost:8000 | Python FastAPI, SQLite | — |

## Правила
1. Тестировать ТОЛЬКО приложения из таблицы выше (localhost)
2. НЕ отправлять запросы на внешние хосты без явного разрешения
3. Результаты → ./reports/{таргет}/{агент}/
4. Формат отчёта — стандартный из установленных skills
5. Каждый finding: severity (CVSS 3.1), CWE ID, описание, PoC команда, remediation
6. Язык отчётов: русский, технические термины на английском

## Директории
- ./reports/ — финальные отчёты
- ./scans/ — raw output инструментов
- ./configs/ — scan profiles, wordlists, кастомные правила
- ./static/ — клонированные исходники (для sentry-review)

## Отчёты — агенты для сравнения

Цель: сравнить что каждый агент находит по одному таргету.

| Агент | Тип | Описание |
|-------|-----|---------|
| shannon | hybrid (white+black box) | Autonomous pentest, Docker-based |
| transilience | multi-agent, dynamic | /coordination slash command |
| manual | black box, свободный | Claude Code без спец-skills |
| sentry-review | static, code review | getsentry security-review skill, нужны исходники |

### Структура директорий
```
./reports/{таргет}/{агент}/
  juice-shop/shannon/
  juice-shop/transilience/
  juice-shop/manual/
  juice-shop/sentry-review/
  vampi/shannon/
  vampi/transilience/
  vampi/manual/
  vampi/sentry-review/
```

### Сводная таблица ./reports/SUMMARY.md
| Дата | Таргет | Агент | Тип | Findings | Confirmed | Уникальные | Время |

## Installed Skills (типы)
### Skills (SKILL.md → .claude/skills/)
- getsentry/skills@security-review — code review, confidence levels HIGH/MED/LOW
- agamm/claude-code-owasp — OWASP Top 10 2025, ASVS 5.0, language quirks
- trailofbits/skills-curated — CodeQL, SARIF, variant analysis, differential review
- transilienceai/communitytools — 23 pentest skills + slash commands
- shuvonsec/claude-bug-bounty — 18 bug classes: IDOR, XSS, SSRF, OAuth, LLM injection
- unicodeveloper/shannon — autonomous pentester (Docker-only!)

### Agents (.claude/agents/)
- pentester-orchestrator — координация multi-agent тестирования
- pentester-executor — выполнение exploit'ов
- pentester-validator — верификация findings
- hackthebox — автоматизация HTB challenges
- script-generator — генерация exploit scripts

### Slash Commands (из transilienceai)
- /coordination <url> — полный пентест
- /reconnaissance <url> — маппинг attack surface
- /techstack-identification — определение стека
- /source-code-scanning <path> — static analysis

## Workflow
1. Определить стек → /techstack-identification
2. Маппинг → /reconnaissance
3. Source code review → security-review skill (если есть код)
4. Dynamic testing → curl / Playwright / sqlmap
5. Validate → каждый finding должен быть confirmed exploitable
6. Report → ./reports/
