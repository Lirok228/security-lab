# Security Testing — Сводная таблица результатов

Цель: сравнить что каждый агент находит по одному таргету.

## Агенты

| Агент | Тип | Описание |
|-------|-----|---------|
| orizon | full pipeline | recon → exploit → chain composition |
| transilience | multi-agent, dynamic | `/coordination` slash command |
| manual | black box | Claude Code без спец-skills |
| sentry-review | static, code review | security-review skill, нужны исходники в `./static/` |
| shannon | hybrid (white+black box) | Autonomous pentest, Docker-based |

## Результаты

| Дата | Таргет | Агент | Тип | Findings | Confirmed | Уникальные | Время |
|------|--------|-------|-----|----------|-----------|------------|-------|
| 2026-04-20 | eyeflow.ru | orizon (pentester-orchestrator) | multi-agent, black-box | 10 | 10 | 4 | ~30 мин |
| 2026-04-21 | eyeflow.ru | manual (webapp-exploit-hunter + api-breaker + cloud-pivot-finder) | black-box, skill-based | 14 | 14 | 9 | ~2 ч |

## Структура

```
projects/<target>/
├── <agent>/
│   └── report.md
├── FINAL-REPORT.md
└── AGENTS-COMPARISON.md
```
