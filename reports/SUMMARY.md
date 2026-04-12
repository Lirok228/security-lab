# Security Testing — Сводная таблица результатов

Цель: сравнить что каждый агент находит по одному таргету.

## Агенты

| Агент | Тип | Описание |
|-------|-----|---------|
| shannon | hybrid (white+black box) | Autonomous pentest, Docker-based |
| transilience | multi-agent, dynamic | /coordination slash command |
| manual | black box, свободный | Claude Code без спец-skills |
| sentry-review | static, code review | getsentry security-review skill, нужны исходники в ./static/ |

## Результаты

| Дата | Таргет | Агент | Тип | Findings | Confirmed | Уникальные | Время |
|------|--------|-------|-----|----------|-----------|------------|-------|
| 2026-04-12 | juice-shop | manual | black box | 1 (+2 доп.) | 1 | SQLi login bypass → admin ATO | ~15 мин |
| 2026-04-12 | juice-shop | transilience | multi-agent | 4 (1 rejected) | 3 | F-001 SQLi 9.8, F-004 BAC 9.1, F-002 XSS 7.4 | ~45 мин |
| 2026-04-12 | medclinic | sentry-review | static code review | 11 (6C+5H) | 11 | VULN-001..011: hardcoded JWT, unauth admin, IDOR records/prescriptions/files | ~20 мин |
| 2026-04-12 | medclinic | manual | white+black box recon | 10 (6C+4H) | 10 | F-001..010: все из sentry-review динамически подтверждены, 5 цепочек атак | ~30 мин |
| 2026-04-12 | medclinic | transilience | multi-agent | 10 (6C+4H) | 10 | F-001..010: полный отчёт + findings.json, 5 attack chains, план P0/P1/P2 | ~40 мин |
| 2026-04-12 | medclinic | idor-testing | black-box IDOR (zebbern skill) | 15 (11H+3M) | 15 | 13 IDOR + 2 BAC; Write-IDOR в patients/appointments — новые векторы | ~25 мин |
| 2026-04-12 | vuln-bank | manual (idor-testing skill) | black-box | 9 (4C+4H+1M) | 9 | SSRF→JWT Leak→Forge chain, BOPLA mass-assignment admin, 4x IDOR (balance/tx/cards) | ~25 мин |
| 2026-04-12 | vuln-bank | sentry-review | static code review | 46 (24C+12H+10M) | 46 | SQLi 20+ instances, JWT none-alg, plaintext passwords, /debug/users, race condition, 9 новых vs dynamic | ~20 мин |
| 2026-04-12 | vuln-bank | ai-threat-testing | OWASP LLM Top 10 | 5 (2C+2H+1M) | 5 | DB exfil to external API, rate limit bypass X-Forwarded-For, indirect injection via bio, system prompt extraction | ~20 мин |
| 2026-04-12 | vuln-bank | web-app-logic | Business logic | 8 (4C+2H+2M) | 8 | negative transfer theft, self-approve loan ($700k), PIN ATO, unlimited loans, 3 новых vs static | ~20 мин |
| 2026-04-12 | vuln-bank | injection | SQL/SSTI/Cmd injection | 5 (4C+1H) | 5 | UNION 10-col full dump, error-based 1-query cred dump, GraphQL SQLi, time-based blind | ~25 мин |
| 2026-04-12 | vuln-bank | orizon | Full pipeline (recon→exploit→chain) | 14 (8C+3H+2M+1L) | 14 | 5 attack chains: SQLi 2-req DB dump, SSRF→JWT forge, mass-assign→admin, PIN ATO, IDOR mass enum | ~60 мин |

## Структура директорий

```
reports/
├── SUMMARY.md              ← этот файл
├── juice-shop/
│   ├── shannon/
│   ├── transilience/
│   ├── manual/
│   └── sentry-review/
└── vampi/
    ├── shannon/
    ├── transilience/
    ├── manual/
    └── sentry-review/

static/                     ← исходники для sentry-review
├── juice-shop/             ← git clone https://github.com/juice-shop/juice-shop
└── vampi/                  ← git clone https://github.com/erev0s/VAmPI
```
