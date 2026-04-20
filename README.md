# Security Lab

Локальный полигон для AI-driven security testing. Intentionally vulnerable приложения развернуты в Docker, тестируются несколькими AI-агентами для сравнения их возможностей.

## Целевые приложения

| App | URL | Стек |
|-----|-----|------|
| [Juice Shop](https://github.com/juice-shop/juice-shop) | `http://localhost:3000` | Node.js, Angular |
| [VAmPI](https://github.com/erev0s/VAmPI) | `http://localhost:5001` | Python Flask REST API |
| medclinic | `http://localhost:8000` | Python FastAPI, SQLite |

## Быстрый старт

```bash
# 1. Поднять уязвимые приложения
docker compose up -d

# 2. (опционально) Поднять dashboard с результатами
docker compose -f docker-compose.dashboard.yml up -d --build
# Открыть http://localhost:7777
```

## Структура проекта

```
security-lab/
├── CLAUDE.md                  # Инструкции для Claude Code
├── AGENTS.md                  # Конфигурация агентов (orchestrator, executor, validator)
├── SKILLS.md                  # Справочник 37 security skills
├── docker-compose.yml         # Juice Shop + VAmPI
├── docker-compose.dashboard.yml
├── dashboard/                 # Web-dashboard результатов тестирования
│   ├── app.py                 #   HTTP-сервер на Python (порт 7777)
│   ├── Dockerfile
│   └── static/                #   Статические HTML-снапшоты
├── reports/                   # Финальные отчеты по каждому таргету и агенту
│   ├── SUMMARY.md             #   Сводная таблица всех тестов
│   ├── juice-shop/
│   ├── medclinic/
│   └── vuln-bank/
├── configs/                   # Scan profiles, wordlists
├── scans/                     # Raw output инструментов (в .gitignore)
├── scripts/                   # Вспомогательные скрипты
├── static/                    # Клонированные исходники для code review (в .gitignore)
├── files/                     # Дополнительные файлы
└── .claude/
    ├── skills/                # Установленные Claude Code skills
    └── agents/                # Определения агентов
```

## Агенты для сравнения

Ключевая идея — один таргет тестируется несколькими агентами, результаты сравниваются.

| Агент | Тип | Описание |
|-------|-----|---------|
| shannon | hybrid (white+black box) | Autonomous pentester, Docker-based |
| transilience | multi-agent, dynamic | `/coordination` slash command |
| manual | black box | Claude Code без специализированных skills |
| sentry-review | static code review | getsentry security-review skill |
| orizon | pipeline | 6-step: recon → exploit → chain composition |

## Результаты тестирования

> Подробности: [`reports/SUMMARY.md`](reports/SUMMARY.md)

Протестировано 3 таргета, 12 сессий, **133 findings** суммарно:

| Таргет | Агенты | Findings | Ключевые находки |
|--------|--------|----------|------------------|
| Juice Shop | manual, transilience | 5 | SQLi login bypass → admin ATO, BAC, XSS |
| medclinic | sentry-review, manual, transilience, idor-testing | 46 | Hardcoded JWT, unauth admin, 13 IDOR, 5 attack chains |
| vuln-bank | manual, sentry-review, ai-threat, web-app-logic, injection, orizon | 87 | SQLi full DB dump, SSRF→JWT forge, negative transfer theft, 46 static findings |

## Установленные Skills (37 шт.)

Полный справочник: [`SKILLS.md`](SKILLS.md)

**Быстрый выбор:**

| Кейс | Skills |
|------|--------|
| Black-box пентест | `recon-dominator` → `webapp-exploit-hunter` → `api-breaker` → `vuln-chain-composer` |
| Static code review | `security-review` → `source-code-scanning` |
| Bug bounty | `bb-methodology` → `idor-testing` → `triage-validation` → `report-writing` |
| API пентест | `api-breaker` → `api-security` → `injection` |
| AI/LLM app | `ai-threat-testing` → `injection` |

## Dashboard

Web-интерфейс для просмотра результатов тестирования — отчеты, findings, skills, сравнение агентов.

```bash
docker compose -f docker-compose.dashboard.yml up -d --build
open http://localhost:7777
```

Страницы: главная, отчеты по таргетам, drill-down по findings, каталог skills, сравнение агентов.

## Требования

- Docker / Docker Compose
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) с установленными skills (см. `skills-lock.json`)
- Для Shannon: `ANTHROPIC_API_KEY` в `.env`
