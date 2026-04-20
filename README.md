# Security Lab

> AI-driven security testing toolkit for web applications and APIs.  
> Сравнение нескольких AI-агентов на одном таргете — чтобы понять, кто что находит.

---

## Что это

Рабочее окружение для пентестинга с набором из **43 security skills** и **6 агентов** для Claude Code. Каждый таргет тестируется несколькими агентами независимо, результаты сравниваются.

**Ключевые возможности:**
- 43 security skills: recon, exploitation, IDOR, injection, auth bypass, API, cloud, AI/LLM, AD/ADCS
- Multi-agent оркестрация через `pentester-orchestrator` с параллельными Kali-контейнерами
- Три типа отчётов на каждый таргет: агентский, финальный (для разработчиков) и сравнительный (внутренний)
- Dashboard для просмотра результатов (`http://localhost:7777`)

---

## Быстрый старт

```bash
# 1. Клонировать репозиторий (skills включены)
git clone https://github.com/Lirok228/security-lab.git && cd security-lab

# 2. (опционально) Запустить dashboard
docker compose -f docker-compose.dashboard.yml up -d --build
open http://localhost:7777

# 3. Открыть Claude Code и начать тестирование
claude
```

---

## Структура проекта

```
security-lab/
├── CLAUDE.md                    # Инструкции для Claude Code (загружается автоматически)
├── AGENTS.md                    # Архитектура агентов: дисциплина артефактов, Docker mode
├── SKILLS.md                    # Справочник 43 skills с описанием и примерами вызова
├── docker-compose.dashboard.yml # Dashboard с результатами (порт 7777)
├── dashboard/                   # Исходники dashboard (Python, порт 7777)
├── reports/
│   └── SUMMARY.md               # Сводная таблица всех тестов (все таргеты, все агенты)
├── projects/                    # Создаётся автоматически при тестировании
│   └── <target>/
│       ├── <agent>/             # Данные каждого агента: recon, findings, артефакты
│       │   └── report.md
│       ├── FINAL-REPORT.md      # Сводный отчёт для разработчиков/ИТ
│       └── AGENTS-COMPARISON.md # Внутренний анализ эффективности агентов
├── configs/                     # Scan profiles, wordlists
├── files/
│   ├── install.sh               # Скрипт переустановки skills из источников
│   └── security-skills-toolkit.md  # Каталог skills с бенчмарками
└── .claude/
    ├── skills/                  # 43 установленных skills
    └── agents/                  # Определения агентов
```

> `projects/` в `.gitignore` — содержит чувствительные данные пентестов.

---

## Агенты

| Агент | Тип | Описание |
|-------|-----|---------|
| **orizon** | Full pipeline | recon → exploit → chain composition (6 шагов) |
| **transilience** | Multi-agent | `/coordination <url>` — параллельные executor'ы |
| **shannon** | Autonomous | White+black box, Docker, 96% exploit success rate |
| **manual** | Black box | Claude Code без специализированных skills |
| **sentry-review** | Static | Code review с confidence HIGH/MED/LOW |
| **idor-testing** | Специализированный | Систематический IDOR по всем endpoints |

---

## Skills — быстрый выбор

| Кейс | Skills в порядке запуска |
|------|--------------------------|
| Black-box web пентест | `recon-dominator` → `webapp-exploit-hunter` → `api-breaker` → `attack-path-architect` → `vuln-chain-composer` |
| Static code review | `security-review` → `source-code-scanning` |
| API пентест | `api-breaker` → `api-security` → `injection` |
| AI/LLM приложение | `ai-threat-testing` → `server-side` → `injection` |
| AD пентест | `performing-active-directory-penetration-test` → `conducting-internal-reconnaissance-with-bloodhound-ce` → `exploiting-kerberoasting-with-impacket` → `exploiting-active-directory-with-bloodhound` |
| ADCS атаки | `exploiting-active-directory-certificate-services-esc1` |

Полный справочник: [`SKILLS.md`](SKILLS.md)

---

## Источники skills

| Пакет | Skills |
|-------|--------|
| [getsentry/skills](https://github.com/getsentry/skills) | security-review |
| [trailofbits/skills-curated](https://github.com/trailofbits/skills-curated) | source-code-scanning, ffuf, ghidra |
| [transilienceai/communitytools](https://github.com/transilienceai/communitytools) | coordination + 20 pentest skills + agents |
| [shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty) | idor, triage, report-writing и др. |
| [Orizon-eu/claude-code-pentest](https://github.com/Orizon-eu/claude-code-pentest) | recon-dominator, webapp-exploit-hunter, api-breaker, vuln-chain-composer |
| [unicodeveloper/shannon](https://github.com/KeygraphHQ/shannon) | shannon |
| [Eyadkelleh/awesome-claude-skills-security](https://github.com/Eyadkelleh/awesome-claude-skills-security) | security-arsenal, pentest agents |
| [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) | AD/ADCS, BloodHound, Kerberoasting, lateral movement (11 skills) |

---

## Требования

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code)
- Docker / Docker Compose (для dashboard и Shannon)
- `ANTHROPIC_API_KEY` в `.env` (для Shannon и Docker mode)

---

## Безопасность

Все skills выполняются с полным доступом к shell. Перед установкой нового skill проверяй `SKILL.md` на наличие внешних запросов и чтения env-переменных. Используй [repello.ai/tools/skills](https://repello.ai/tools/skills) для автоматической проверки.
