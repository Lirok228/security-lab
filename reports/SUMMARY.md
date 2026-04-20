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

## Структура

```
projects/<target>/
├── <agent>/
│   └── report.md
├── FINAL-REPORT.md
└── AGENTS-COMPARISON.md
```
