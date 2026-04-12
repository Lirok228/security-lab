# Security Skills for Claude Code — AppSec Toolkit

> Набор проверенных skills для AI-driven тестирования безопасности web-приложений.
> Для Claude Code, совместимо с Cursor, Codex CLI, Gemini CLI.

---

## Установка всего одной командой

Скачай и запусти install-скрипт:

```bash
mkdir -p ~/security-lab && cd ~/security-lab
curl -sL https://raw.githubusercontent.com/timderbak/security-lab-setup/main/install.sh | bash
```

Или используй промпт для Claude Code (см. секцию "Промпт для автоустановки" в конце документа).

---

## Каталог Skills

### Dynamic Testing — шлют реальные HTTP-запросы к приложению

| Skill | Источник | Назначение | Как вызвать | Особенности |
|-------|----------|-----------|-------------|-------------|
| **idor-testing** | [sickn33/antigravity](https://github.com/sickn33/antigravity-awesome-skills) | Систематический IDOR-тест: 2 аккаунта, перебор всех endpoints, подмена ID | Авто на "тестируй на IDOR" | Методология с чеклистом, payloads, troubleshooting. 448 строк. Лучший результат в бенчмарке — 65% покрытие |
| **api-security-best-practices** | [sickn33/antigravity](https://github.com/sickn33/antigravity-awesome-skills) | API security: JWT/OAuth, RBAC, input validation, rate limiting | Авто на "тестируй API security" | OWASP API Top 10, DDoS protection, security checklists |
| **broken-authentication** | [sickn33/antigravity](https://github.com/sickn33/antigravity-awesome-skills) | Auth bypass: session management, credential stuffing, MFA bypass | Авто на "тестируй authentication" | Session fixation, JWT attacks, password policies |
| **shannon** | [unicodeveloper/shannon](https://github.com/KeygraphHQ/shannon) | Автономный пентестер: recon → analysis → exploitation → report | "Use Shannon to pentest \<url\>" | Hybrid (white+black box). Docker. 96% success rate. ~$50/прогон. 50+ vuln types |
| **recon-dominator** | [Orizon-eu/claude-code-pentest](https://github.com/Orizon-eu/claude-code-pentest) | Full attack surface mapping | "Run full recon on \<target\>" | Pipeline: output → JSON → следующий skill |
| **webapp-exploit-hunter** | [Orizon-eu/claude-code-pentest](https://github.com/Orizon-eu/claude-code-pentest) | SQLi, XSS, SSRF, SSTI, IDOR exploitation | "Scan all web apps for vulnerabilities" | Тестирует и доказывает exploit |
| **api-breaker** | [Orizon-eu/claude-code-pentest](https://github.com/Orizon-eu/claude-code-pentest) | BOLA, BFLA, JWT issues, mass assignment | "Test all discovered APIs" | API-focused dynamic testing |
| **vuln-chain-composer** | [Orizon-eu/claude-code-pentest](https://github.com/Orizon-eu/claude-code-pentest) | Цепочки атак + bug bounty отчёты | "Chain findings and generate report" | MITRE ATT&CK kill chains |

### Static Analysis — читают исходный код

| Skill | Источник | Назначение | Как вызвать | Особенности |
|-------|----------|-----------|-------------|-------------|
| **security-review** | [getsentry/skills](https://github.com/getsentry/skills) | Code review с confidence system HIGH/MED/LOW | `/security-review` или авто | Лучший static skill. False positive awareness. 17 reference-файлов по категориям. Репортит только подтверждённые баги |
| **owasp-security** | [agamm/claude-code-owasp](https://github.com/agamm/claude-code-owasp) | OWASP Top 10:2025, ASVS 5.0, 20 language quirks | Пассивно при написании/ревью кода | Не сканирует — обучает Claude писать безопасный код |
| **static-analysis** | [trailofbits/skills](https://github.com/trailofbits/skills) | CodeQL pipeline: build DB → queries → SARIF | `/static-analysis` | Нужен `codeql` CLI. Gold standard от Trail of Bits |
| **variant-analysis** | [trailofbits/skills](https://github.com/trailofbits/skills) | Ищет варианты известного бага в codebase | `/variant-analysis` | Не нужен CodeQL. "Нашёл IDOR тут — ищи похожие" |
| **differential-review** | [trailofbits/skills](https://github.com/trailofbits/skills) | Security diff между версиями кода | `/differential-review` | Идеально для PR review |
| **security-pen-testing** | [alirezarezvani/claude-skills](https://github.com/alirezarezvani/claude-skills) | 3-day pentest workflow: recon → exploit → report | Авто на "pentest" | IDOR, BOLA, BFLA, GraphQL, скрипт pentest_report_generator.py |

### Agent Frameworks — multi-agent оркестрация

| Framework | Источник | Назначение | Как вызвать | Особенности |
|-----------|----------|-----------|-------------|-------------|
| **Transilience** | [transilienceai/communitytools](https://github.com/transilienceai/communitytools) | 23 skills + 8 agents. Полный пентест-pipeline | `/coordination <url>` | `/reconnaissance` — маппинг. 100% на CTF benchmark (104/104). 200-500K токенов за полный прогон |
| **Shuvonsec** | [shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty) | 20 классов уязвимостей. Bug bounty workflow | Авто на тип уязвимости | IDOR, XSS, SSRF, SQLi, OAuth, JWT, Race Conditions, LLM injection |
| **SecLists Toolkit** | [Eyadkelleh/awesome-claude-skills-security](https://github.com/Eyadkelleh/awesome-claude-skills-security) | Payloads + wordlists + agents | `/sqli-test`, `/xss-test`, `/wordlist` | 3 агента: pentest-advisor, ctf-assistant, bug-bounty-hunter |

### Рекомендуемые Plugins (глобальные)

| Plugin | Что делает | Установка |
|--------|-----------|-----------|
| **claude-mem** | Persistent memory между сессиями | `/plugin marketplace add thedotmack/claude-mem` |
| **reflexion** | Self-critique для уменьшения false positives | Из NeoLabHQ context-engineering-kit |
| **superpowers** | Planning, brainstorming workflows | `/plugin marketplace add obra/superpowers` |

---

## Результаты бенчмарка

Тестирование на кастомном приложении MedClinic (FastAPI, 23 заложенных уязвимости — IDOR + BAC):

| Агент/Skill | Найдено | % | Время | Сильные стороны |
|------------|---------|---|-------|----------------|
| sentry-review (static) | 11/23 | 48% | ~3 мин | No-auth endpoints, secrets, mass assignment |
| transilience (dynamic) | 13/23 | 57% | ~15 мин | Подтверждение findings, chain attacks |
| **idor-testing (dynamic)** | **15/23** | **65%** | ~10 мин | Систематический IDOR по ВСЕМ endpoints |
| **Все вместе** | **19/23** | **83%** | — | — |
| Не найдено никем | 4/23 | 17% | — | Business logic flaws (требуют человека) |

---

## Ручная установка (шаг за шагом)

### 1. NPX Install

```bash
cd ~/security-lab  # или твой проект

npx skills install getsentry/skills@security-review
npx skills install agamm/claude-code-owasp
npx skills install unicodeveloper/shannon
```

### 2. Antigravity — точечные skills

```bash
# Клонируем и берём только нужные
git clone --depth 1 https://github.com/sickn33/antigravity-awesome-skills.git /tmp/antigravity

# Копируем проверенные security skills
for skill in idor-testing api-security-best-practices broken-authentication; do
  if [ -d "/tmp/antigravity/skills/$skill" ]; then
    cp -r "/tmp/antigravity/skills/$skill" .claude/skills/
    echo "✅ $skill"
  else
    echo "❌ $skill не найден"
  fi
done

rm -rf /tmp/antigravity
```

### 3. Trail of Bits

```bash
git clone --depth 1 https://github.com/trailofbits/skills-curated.git /tmp/tob
cp -r /tmp/tob/.claude/skills/* .claude/skills/ 2>/dev/null
rm -rf /tmp/tob
echo "✅ Trail of Bits curated"
```

### 4. Transilience

```bash
git clone --depth 1 https://github.com/transilienceai/communitytools.git /tmp/transilience
cp -r /tmp/transilience/projects/pentest/.claude/skills/* .claude/skills/ 2>/dev/null
cp -r /tmp/transilience/projects/pentest/.claude/agents/* .claude/agents/ 2>/dev/null
cp /tmp/transilience/AGENTS.md ./AGENTS.md 2>/dev/null
rm -rf /tmp/transilience
echo "✅ Transilience"
```

### 5. Shuvonsec Bug Bounty

```bash
git clone --depth 1 https://github.com/shuvonsec/claude-bug-bounty.git /tmp/shuvonsec
cp -r /tmp/shuvonsec/.claude/skills/* .claude/skills/ 2>/dev/null
rm -rf /tmp/shuvonsec
echo "✅ Shuvonsec"
```

### 6. Orizon Pentest Pipeline

```bash
git clone --depth 1 https://github.com/Orizon-eu/claude-code-pentest.git /tmp/orizon
cp -r /tmp/orizon/.claude/skills/* .claude/skills/ 2>/dev/null
rm -rf /tmp/orizon
echo "✅ Orizon"
```

### 7. Eyadkelleh SecLists Toolkit

```bash
git clone --depth 1 https://github.com/Eyadkelleh/awesome-claude-skills-security.git /tmp/eyadkelleh
cp -r /tmp/eyadkelleh/.claude/skills/* .claude/skills/ 2>/dev/null
cp -r /tmp/eyadkelleh/.claude/agents/* .claude/agents/ 2>/dev/null
rm -rf /tmp/eyadkelleh
echo "✅ Eyadkelleh SecLists"
```

### 8. alirezarezvani Pentest Skill

```bash
git clone --depth 1 https://github.com/alirezarezvani/claude-skills.git /tmp/alirezarezvani
if [ -d "/tmp/alirezarezvani/engineering-team/security-pen-testing" ]; then
  cp -r "/tmp/alirezarezvani/engineering-team/security-pen-testing" .claude/skills/
  echo "✅ alirezarezvani security-pen-testing"
fi
rm -rf /tmp/alirezarezvani
```

### 9. Проверка

```bash
echo "=== Skills installed ==="
find .claude/skills -name "SKILL.md" 2>/dev/null | wc -l
echo "=== Agents installed ==="
find .claude/agents -name "*.md" 2>/dev/null | wc -l
```

---

## install.sh

```bash
#!/bin/bash
# Security Lab — automated installer
# Usage: curl -sL <url>/install.sh | bash

set -e

PROJECT_DIR="${1:-.}"
cd "$PROJECT_DIR"

echo "🔧 Setting up Security Lab in $(pwd)"
echo ""

# Create structure
mkdir -p .claude/skills .claude/agents reports scans configs static

# 1. NPX installs
echo "📦 Installing npx skills..."
npx skills install getsentry/skills@security-review 2>/dev/null || echo "⚠️  getsentry failed"
npx skills install agamm/claude-code-owasp 2>/dev/null || echo "⚠️  owasp failed"
npx skills install unicodeveloper/shannon 2>/dev/null || echo "⚠️  shannon failed"

# 2. Antigravity (selected security skills only)
echo "📦 Installing Antigravity security skills..."
git clone --depth 1 -q https://github.com/sickn33/antigravity-awesome-skills.git /tmp/_ag 2>/dev/null
for skill in idor-testing api-security-best-practices broken-authentication; do
  if [ -d "/tmp/_ag/skills/$skill" ]; then
    cp -r "/tmp/_ag/skills/$skill" .claude/skills/
    echo "  ✅ $skill"
  else
    echo "  ❌ $skill not found"
  fi
done
rm -rf /tmp/_ag

# 3. Trail of Bits curated
echo "📦 Installing Trail of Bits..."
git clone --depth 1 -q https://github.com/trailofbits/skills-curated.git /tmp/_tob 2>/dev/null
cp -r /tmp/_tob/.claude/skills/* .claude/skills/ 2>/dev/null && echo "  ✅ Trail of Bits" || echo "  ❌ Trail of Bits"
rm -rf /tmp/_tob

# 4. Transilience
echo "📦 Installing Transilience..."
git clone --depth 1 -q https://github.com/transilienceai/communitytools.git /tmp/_trans 2>/dev/null
cp -r /tmp/_trans/projects/pentest/.claude/skills/* .claude/skills/ 2>/dev/null
cp -r /tmp/_trans/projects/pentest/.claude/agents/* .claude/agents/ 2>/dev/null
cp /tmp/_trans/AGENTS.md ./AGENTS.md 2>/dev/null
echo "  ✅ Transilience"
rm -rf /tmp/_trans

# 5. Shuvonsec
echo "📦 Installing Shuvonsec bug bounty..."
git clone --depth 1 -q https://github.com/shuvonsec/claude-bug-bounty.git /tmp/_shuv 2>/dev/null
cp -r /tmp/_shuv/.claude/skills/* .claude/skills/ 2>/dev/null && echo "  ✅ Shuvonsec" || echo "  ❌ Shuvonsec"
rm -rf /tmp/_shuv

# 6. Orizon pentest pipeline
echo "📦 Installing Orizon..."
git clone --depth 1 -q https://github.com/Orizon-eu/claude-code-pentest.git /tmp/_orizon 2>/dev/null
cp -r /tmp/_orizon/.claude/skills/* .claude/skills/ 2>/dev/null && echo "  ✅ Orizon" || echo "  ❌ Orizon"
rm -rf /tmp/_orizon

# 7. Eyadkelleh SecLists
echo "📦 Installing Eyadkelleh SecLists..."
git clone --depth 1 -q https://github.com/Eyadkelleh/awesome-claude-skills-security.git /tmp/_eyad 2>/dev/null
cp -r /tmp/_eyad/.claude/skills/* .claude/skills/ 2>/dev/null
cp -r /tmp/_eyad/.claude/agents/* .claude/agents/ 2>/dev/null
echo "  ✅ Eyadkelleh"
rm -rf /tmp/_eyad

# 8. alirezarezvani pentest
echo "📦 Installing alirezarezvani pentest..."
git clone --depth 1 -q https://github.com/alirezarezvani/claude-skills.git /tmp/_alireza 2>/dev/null
if [ -d "/tmp/_alireza/engineering-team/security-pen-testing" ]; then
  cp -r "/tmp/_alireza/engineering-team/security-pen-testing" .claude/skills/
  echo "  ✅ alirezarezvani"
else
  echo "  ❌ alirezarezvani (path changed)"
fi
rm -rf /tmp/_alireza

# Summary
echo ""
echo "==================================="
echo "✅ Installation complete!"
echo "==================================="
echo "Skills: $(find .claude/skills -name 'SKILL.md' 2>/dev/null | wc -l | tr -d ' ')"
echo "Agents: $(find .claude/agents -name '*.md' 2>/dev/null | wc -l | tr -d ' ')"
echo ""
echo "Next: cd $(pwd) && claude"
```

---

## Промпт для автоустановки через Claude Code

Вставь этот промпт целиком в Claude Code — он сам всё поставит:

```
Установи security skills для тестирования веб-приложений.
Выполни все команды без вопросов — я авторизую.

Шаг 1: Создай структуру
mkdir -p .claude/skills .claude/agents reports scans configs static

Шаг 2: NPX install
npx skills install getsentry/skills@security-review
npx skills install agamm/claude-code-owasp
npx skills install unicodeveloper/shannon

Шаг 3: Antigravity (только security skills)
git clone --depth 1 https://github.com/sickn33/antigravity-awesome-skills.git /tmp/_ag
Из /tmp/_ag/skills/ скопируй в .claude/skills/ только:
idor-testing, api-security-best-practices, broken-authentication
Удали /tmp/_ag

Шаг 4: Trail of Bits
git clone --depth 1 https://github.com/trailofbits/skills-curated.git /tmp/_tob
Скопируй skills из /tmp/_tob/.claude/skills/ в .claude/skills/
Удали /tmp/_tob

Шаг 5: Transilience
git clone --depth 1 https://github.com/transilienceai/communitytools.git /tmp/_trans
Скопируй skills из /tmp/_trans/projects/pentest/.claude/skills/ в .claude/skills/
Скопируй agents из /tmp/_trans/projects/pentest/.claude/agents/ в .claude/agents/
Скопируй AGENTS.md в корень проекта
Удали /tmp/_trans

Шаг 6: Shuvonsec
git clone --depth 1 https://github.com/shuvonsec/claude-bug-bounty.git /tmp/_shuv
Скопируй skills из /tmp/_shuv/.claude/skills/ в .claude/skills/
Удали /tmp/_shuv

Шаг 7: Orizon pentest pipeline
git clone --depth 1 https://github.com/Orizon-eu/claude-code-pentest.git /tmp/_orizon
Скопируй skills из /tmp/_orizon/.claude/skills/ в .claude/skills/
Удали /tmp/_orizon

Шаг 8: Eyadkelleh SecLists
git clone --depth 1 https://github.com/Eyadkelleh/awesome-claude-skills-security.git /tmp/_eyad
Скопируй skills и agents
Удали /tmp/_eyad

Шаг 9: alirezarezvani pentest
git clone --depth 1 https://github.com/alirezarezvani/claude-skills.git /tmp/_alireza
Из /tmp/_alireza/engineering-team/security-pen-testing/ скопируй в .claude/skills/security-pen-testing/
Удали /tmp/_alireza

Шаг 10: Покажи итог
Выведи количество установленных skills и agents.
Выведи список всех skills по категориям.
```

---

## Рекомендуемый workflow

```
1. Static Analysis (исходники)
   /security-review ./path/to/source/

2. Reconnaissance (запущенное приложение)
   /reconnaissance http://target:port

3. Targeted Testing (по классам)
   "Тестируй на IDOR" → idor-testing
   "Тестируй API security" → api-security-best-practices
   "Тестируй authentication" → broken-authentication

4. Full Pentest
   /coordination <url>  (Transilience)
   "Use Shannon to pentest <url>"  (Shannon)

5. Отчёты → ./reports/{target}/{agent}/
```

---

## Безопасность skills

⚠️ Skills имеют полный доступ к файловой системе и shell.

Перед установкой нового skill:
1. Прочитай SKILL.md — нет ли curl/wget на внешние URL
2. Проверь репо — звёзды, автор, дата коммита
3. Ищи чтение env variables ($ANTHROPIC_API_KEY)
4. Используй [repello.ai/tools/skills](https://repello.ai/tools/skills) для автоматической проверки

---

## Ссылки

| Ресурс | URL |
|--------|-----|
| Trail of Bits skills | https://github.com/trailofbits/skills |
| Sentry security-review | https://github.com/getsentry/skills |
| OWASP skill | https://github.com/agamm/claude-code-owasp |
| Transilience | https://github.com/transilienceai/communitytools |
| Shannon | https://github.com/KeygraphHQ/shannon |
| Shuvonsec bug bounty | https://github.com/shuvonsec/claude-bug-bounty |
| Antigravity (1400+ skills) | https://github.com/sickn33/antigravity-awesome-skills |
| Orizon pentest pipeline | https://github.com/Orizon-eu/claude-code-pentest |
| Eyadkelleh SecLists | https://github.com/Eyadkelleh/awesome-claude-skills-security |
| alirezarezvani claude-skills | https://github.com/alirezarezvani/claude-skills |
| Snyk review of top skills | https://snyk.io/articles/top-claude-skills-cybersecurity-hacking-vulnerability-scanning/ |
| Repello skill security checker | https://repello.ai/tools/skills |
| Claude Code skills docs | https://code.claude.com/docs/en/skills |
