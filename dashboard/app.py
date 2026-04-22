#!/usr/bin/env python3
"""
Security Lab Dashboard
Запуск: python3 dashboard/app.py
Открыть: http://localhost:7777
"""

import json
import os
import re
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

try:
    import markdown as _md_lib
    _MD_AVAILABLE = True
except ImportError:
    _MD_AVAILABLE = False

LAB_DIR = Path(__file__).parent.parent
REPORTS_DIR = Path(os.environ.get("LAB_REPORTS", str(LAB_DIR / "reports")))
SKILLS_DIR  = Path(os.environ.get("LAB_SKILLS",  str(LAB_DIR / ".claude" / "skills")))
PORT = int(os.environ.get("PORT", 7777))

SKILLS_META = {
    # source: точный GitHub репозиторий
    "pentest-orchestrator": {"icon": "⊕", "group": "orchestrator", "source": "transilience",  "desc": "Авто-роутинг по типу цели — выбирает pipeline на основе сигналов URL"},
    # Orizon-eu/claude-code-pentest
    "recon-dominator":      {"icon": "◎", "group": "orizon",       "source": "orizon",        "desc": "Attack surface mapping: субдомены, порты, endpoints, tech fingerprint"},
    "webapp-exploit-hunter":{"icon": "◈", "group": "orizon",       "source": "orizon",        "desc": "Automated web exploitation: SQLi, XSS, SSRF, IDOR, mass assignment"},
    "api-breaker":          {"icon": "⊗", "group": "orizon",       "source": "orizon",        "desc": "REST/GraphQL security: auth bypass, rate limits, schema exposure"},
    "attack-path-architect":{"icon": "◇", "group": "orizon",       "source": "orizon",        "desc": "MITRE ATT&CK kill chain mapping + attack tree generation"},
    "vuln-chain-composer":  {"icon": "⊞", "group": "orizon",       "source": "orizon",        "desc": "Multi-step exploit chain composition с CVSS пересчётом"},
    "cloud-pivot-finder":   {"icon": "○", "group": "orizon",       "source": "orizon",        "desc": "Cloud misconfiguration discovery: AWS, GCP, Azure pivot points"},
    # getsentry/skills
    "security-review":      {"icon": "▣", "group": "static",       "source": "getsentry",     "desc": "Source code security review с уровнями HIGH/MED/LOW confidence"},
    # trailofbits/skills
    "source-code-scanning": {"icon": "▤", "group": "static",       "source": "trailofbits",   "desc": "CodeQL, SARIF, variant analysis, differential security review"},
    # agamm/claude-code-owasp
    "owasp-security":       {"icon": "▦", "group": "static",       "source": "agamm",         "desc": "OWASP Top 10 2025, ASVS 5.0, language-specific security quirks"},
    # transilienceai/communitytools
    "injection":            {"icon": "▸", "group": "offensive",    "source": "transilience",  "desc": "SQL/NoSQL/SSTI/Cmd injection — union-based, error-based, blind, time-based"},
    "web-app-logic":        {"icon": "▸", "group": "offensive",    "source": "transilience",  "desc": "Business logic: negative transfers, self-approval, race conditions, TOCTOU"},
    "server-side":          {"icon": "▸", "group": "offensive",    "source": "transilience",  "desc": "SSRF, HTTP smuggling, request splitting, internal network pivot"},
    "client-side":          {"icon": "▸", "group": "offensive",    "source": "transilience",  "desc": "XSS reflected/stored/DOM, CORS misconfiguration, Prototype Pollution"},
    "authentication":       {"icon": "▸", "group": "offensive",    "source": "transilience",  "desc": "JWT alg:none/confusion, OAuth misconfig, 2FA bypass, session fixation"},
    "api-security":         {"icon": "▸", "group": "offensive",    "source": "transilience",  "desc": "GraphQL introspection, REST verb tampering, WebSocket injection"},
    "ai-threat-testing":    {"icon": "▸", "group": "offensive",    "source": "transilience",  "desc": "OWASP LLM Top 10: prompt injection, data exfil, indirect injection"},
    "infrastructure":       {"icon": "▸", "group": "offensive",    "source": "transilience",  "desc": "Network scanning, Active Directory attacks, lateral movement, pivoting"},
    "cloud-containers":     {"icon": "▸", "group": "offensive",    "source": "transilience",  "desc": "AWS/GCP/Azure misconfigs, K8s RBAC, Docker escape, ECS metadata"},
    "system":               {"icon": "▸", "group": "offensive",    "source": "transilience",  "desc": "Linux/Windows privilege escalation, SUID abuse, credential extraction"},
    # sickn33/antigravity-awesome-skills
    "idor-testing":         {"icon": "▸", "group": "offensive",    "source": "antigravity",   "desc": "IDOR/BOLA — systematic object reference testing, read/write/delete"},
    # shuvonsec/claude-bug-bounty
    "triage-validation-shuvonsec": {"icon": "◉", "group": "bounty", "source": "shuvonsec",  "desc": "7-Question Gate validation перед написанием отчёта, kill false positives"},
    "report-writing-shuvonsec":    {"icon": "◉", "group": "bounty", "source": "shuvonsec",  "desc": "H1/Bugcrowd/Intigriti report format с impact-first структурой"},
    "bug-bounty-main-shuvonsec":   {"icon": "◉", "group": "bounty", "source": "shuvonsec",  "desc": "Full bug bounty workflow: recon → hunt → validate → report"},
    "bb-methodology-shuvonsec":    {"icon": "◉", "group": "bounty", "source": "shuvonsec",  "desc": "Hunter mindset, scope analysis, priority ranking, time management"},
    "web2-vuln-classes-shuvonsec": {"icon": "◉", "group": "bounty", "source": "shuvonsec",  "desc": "Reference: 20 web2 bug classes с PoC примерами и bypass techniques"},
    "security-arsenal-shuvonsec":  {"icon": "◉", "group": "bounty", "source": "shuvonsec",  "desc": "Payloads, bypass tables, wordlists, gf patterns для автоматизации"},
    # KeygraphHQ/shannon
    "shannon":              {"icon": "◆", "group": "autonomous",   "source": "keygraph",      "desc": "Autonomous pentester — запускается в Docker, 96% exploit success rate"},
    # transilienceai/communitytools
    "coordination":         {"icon": "◆", "group": "autonomous",   "source": "transilience",  "desc": "Multi-agent orchestration: executor → validator → report pipeline"},
    "techstack-identification": {"icon": "·", "group": "utils",   "source": "transilience",  "desc": "OSINT tech fingerprinting через headers, JS, meta, CDN signatures"},
    "osint":                {"icon": "·", "group": "utils",       "source": "transilience",  "desc": "Company OSINT: сотрудники, инфраструктура, утечки, DNS history"},
    "cve-poc-generator":    {"icon": "·", "group": "utils",       "source": "transilience",  "desc": "CVE research + standalone PoC script + отчёт с CVSS"},
    "hackthebox":           {"icon": "·", "group": "utils",       "source": "transilience",  "desc": "HTB platform automation: login, challenge select, VPN, skill delegation"},
    "hackerone":            {"icon": "·", "group": "utils",       "source": "transilience",  "desc": "HackerOne automation: scope parsing, report submission, dedup check"},
    "transilience-report-style": {"icon": "·", "group": "utils",  "source": "transilience", "desc": "Transilience PDF report style: threat intel format с executive summary"},
    # trailofbits/skills
    "ghidra-headless-tob":  {"icon": "·", "group": "utils",       "source": "trailofbits",   "desc": "Binary reverse engineering через Ghidra headless analyzer"},
    "ffuf-web-fuzzing-tob": {"icon": "·", "group": "utils",       "source": "trailofbits",   "desc": "Expert ffuf guidance: wordlists, filters, rate limits, recursive fuzzing"},
    # sickn33/antigravity-awesome-skills
    "auth-bypass-testing":  {"icon": "▸", "group": "offensive",   "source": "antigravity",   "desc": "Auth bypass checklist: MFA, SSO, password reset, account lockout"},
    # markdav-is/Skiller
    "skiller":              {"icon": "·", "group": "utils",       "source": "skiller",       "desc": "Skill creator — генерация структуры и валидация новых скиллов"},
}

GROUP_META = {
    "orchestrator": {"label": "Orchestrator",     "color": "#2563eb"},
    "orizon":       {"label": "Orizon Pipeline",  "color": "#7c3aed"},
    "static":       {"label": "Static Analysis",  "color": "#0891b2"},
    "offensive":    {"label": "Offensive",        "color": "#dc2626"},
    "bounty":       {"label": "Bug Bounty",       "color": "#d97706"},
    "autonomous":   {"label": "Autonomous",       "color": "#059669"},
    "utils":        {"label": "Utilities",        "color": "#64748b"},
}

SOURCE_META = {
    "orizon":       {"label": "Orizon-eu",          "color": "#7c3aed", "bg": "#f3f0ff"},
    "shuvonsec":    {"label": "Shuvonsec",          "color": "#d97706", "bg": "#fffbeb"},
    "trailofbits":  {"label": "Trail of Bits",      "color": "#0891b2", "bg": "#ecfeff"},
    "transilience": {"label": "Transilience",       "color": "#2563eb", "bg": "#eff6ff"},
    "keygraph":     {"label": "Keygraph/Shannon",   "color": "#059669", "bg": "#f0fdf4"},
    "getsentry":    {"label": "Sentry",             "color": "#6366f1", "bg": "#eef2ff"},
    "agamm":        {"label": "agamm/owasp",        "color": "#be185d", "bg": "#fdf2f8"},
    "skiller":      {"label": "markdav-is/Skiller", "color": "#92400e", "bg": "#fffbeb"},
    "antigravity":  {"label": "antigravity-skills", "color": "#0f766e", "bg": "#f0fdfa"},
    "community":    {"label": "Community",          "color": "#64748b", "bg": "#f8fafc"},
    "internal":     {"label": "Internal",           "color": "#94a3b8", "bg": "#f8fafc"},
}

PIPELINE_CHAINS = {
    "black-box":   ["recon-dominator","webapp-exploit-hunter","api-breaker","attack-path-architect","vuln-chain-composer"],
    "white-box":   ["security-review","source-code-scanning","injection","authentication","triage-validation-shuvonsec"],
    "api":         ["api-breaker","api-security","idor-testing","injection"],
    "bug-bounty":  ["bb-methodology-shuvonsec","recon-dominator","webapp-exploit-hunter","idor-testing","web-app-logic","triage-validation-shuvonsec","report-writing-shuvonsec"],
    "ai-app":      ["ai-threat-testing","server-side","injection"],
    "finance":     ["web-app-logic","idor-testing","authentication","server-side"],
}

SEV_COLORS = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#d97706",
    "low":      "#16a34a",
    "info":     "#6366f1",
}

AGENT_COLORS = {
    "manual":          "#2563eb",
    "manual2":         "#2563eb",
    "transilience":    "#7c3aed",
    "sentry-review":   "#0891b2",
    "orizon":          "#7c3aed",
    "injection":       "#dc2626",
    "idor-testing":    "#ea580c",
    "web-app-logic":   "#d97706",
    "ai-threat":       "#059669",
    "ai-threat-testing": "#059669",
    "shannon":         "#059669",
    "web-app-logic":   "#d97706",
}

# Agents that belong to pipelines (get purple border)
PIPELINE_AGENTS = {"orizon", "transilience", "shannon", "coordination"}


def parse_report_meta(rel_path):
    agent_dir = LAB_DIR / rel_path
    findings_file = agent_dir / "findings.json"

    raw = []
    s   = {}

    if findings_file.exists():
        try:
            data = json.loads(findings_file.read_text())
            s    = data.get("summary", {})
            raw  = data.get("findings") or data.get("validated_findings", [])
        except Exception:
            pass
    else:
        # Fallback: parse markdown files
        for md_file in sorted(agent_dir.glob("*.md")):
            try:
                parsed = parse_md_findings(md_file.read_text(errors='replace'))
                if parsed:
                    raw.extend(parsed)
            except Exception:
                pass
        if raw:
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in raw:
                sev = str(f.get("severity", f.get("_sev", ""))).lower()
                if sev in counts:
                    counts[sev] += 1
            s = {**counts, "total": len(raw), "confirmed": sum(1 for f in raw if f.get("_confirmed", True))}

    if not raw:
        return None

    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    top = sorted(raw, key=lambda f: SEV_ORDER.get(str(f.get("severity", "")).lower(), 9))[:3]

    return {
        "critical":  int(s.get("critical", 0)),
        "high":      int(s.get("high", 0)),
        "medium":    int(s.get("medium", 0)),
        "low":       int(s.get("low", 0)),
        "total":     int(s.get("total", 0)),
        "confirmed": int(s.get("confirmed", 0)),
        "skills":    data.get("engagement", {}).get("skills", []) if findings_file.exists() else [],
        "top":       top,
    }


def get_reports():
    reports = []
    if not REPORTS_DIR.exists():
        return reports
    for target_dir in sorted(REPORTS_DIR.iterdir()):
        if not target_dir.is_dir() or target_dir.name.startswith("SUMMARY"):
            continue
        for agent_dir in sorted(target_dir.iterdir()):
            if not agent_dir.is_dir():
                continue
            md_files  = list(agent_dir.glob("*.md"))
            json_files = list(agent_dir.glob("*.json"))
            if md_files or json_files:
                rel = str(agent_dir.relative_to(LAB_DIR))
                sev = parse_report_meta(rel)
                reports.append({
                    "target":  target_dir.name,
                    "agent":   agent_dir.name,
                    "path":    rel,
                    "files":   [f.name for f in sorted(md_files + json_files)],
                    "mtime":   max((f.stat().st_mtime for f in md_files + json_files), default=0),
                    "sev":     sev,
                })
    reports.sort(key=lambda r: r["mtime"], reverse=True)
    return reports


def get_report_content(rel_path, filename):
    full = LAB_DIR / rel_path / filename
    if not full.exists():
        return None
    return full.read_text(errors="replace")


def get_skills():
    installed = set()
    if SKILLS_DIR.exists():
        for d in SKILLS_DIR.iterdir():
            try:
                if d.is_dir() and ((d / "SKILL.md").exists() or d.name in SKILLS_META):
                    installed.add(d.name)
            except OSError:
                pass
    result = {}
    for name, meta in SKILLS_META.items():
        result[name] = {**meta, "installed": name in installed}
    for name in installed:
        if name not in result:
            result[name] = {"icon": "·", "group": "utils", "desc": "", "installed": True}
    return result


# ── New data layer ──────────────────────────────────────────────────────────

def _parse_findings_from_file(findings_path):
    """Parse findings list from findings.json or aggregated-findings.json."""
    try:
        data = json.loads(Path(findings_path).read_text())
        # Standard format: findings[]
        raw = data.get("findings") or data.get("validated_findings", [])
        summary = data.get("summary", {})
        engagement = data.get("engagement", {})
        if isinstance(engagement, str):
            engagement = {"name": engagement}
        return raw, summary, engagement, data
    except Exception:
        return [], {}, {}, {}


def parse_md_findings(text):
    """Extract findings from markdown reports.
    Supports two patterns:
    1. Summary tables with ID/Severity/CWE columns
    2. ### FINDING-ID — Title sections with **Severity:** lines
    """
    findings = []
    SEV_MAP = {
        'critical': 'critical', 'крит': 'critical',
        'high': 'high', 'высокий': 'high',
        'medium': 'medium', 'средний': 'medium',
        'low': 'low', 'низкий': 'low',
        'info': 'info', 'informational': 'info',
        'n/a': 'info',
    }

    lines = text.split('\n')

    # ── Pattern 1: summary table ─────────────────────────────────────────────
    header_cols = []
    in_table = False

    for line in lines:
        stripped = line.strip()
        if not stripped.startswith('|'):
            in_table = False
            header_cols = []
            continue

        cells = [c.strip() for c in stripped.strip('|').split('|')]
        lower_cells = [c.lower() for c in cells]

        if not in_table:
            # Detect header: needs severity column + id/title column
            has_sev = any('severity' in c or 'северити' in c for c in lower_cells)
            has_id  = any(c in ('#', 'id', '№') or 'уязвим' in c or 'vulnerability' in c or 'finding' in c for c in lower_cells)
            if has_sev and has_id:
                header_cols = lower_cells
                in_table = True
            continue

        # Skip separator rows (--- :--- etc)
        if all(re.match(r'^[-: ]+$', c) for c in cells if c):
            continue

        if len(cells) < 2:
            continue

        f = {'_from_md': True}
        for i, col in enumerate(header_cols):
            if i >= len(cells):
                break
            val = cells[i].strip()
            if not val:
                continue
            # ID column
            if col in ('#', 'id', '№', 'num'):
                f['id'] = val
            # Title/vuln column
            elif any(k in col for k in ('уязвим', 'vulnerability', 'finding', 'title', 'name', 'description', 'desc')):
                # strip markdown bold/links
                f['title'] = re.sub(r'[\*\[\]`]', '', val).strip()
            # Severity
            elif 'severity' in col or 'сев' in col:
                sev_raw = re.sub(r'[\*`]', '', val).lower().strip()
                f['severity'] = SEV_MAP.get(sev_raw, sev_raw if sev_raw else 'medium')
            # CWE
            elif 'cwe' in col:
                cwe_match = re.search(r'CWE-\d+', val, re.IGNORECASE)
                f['cwe'] = cwe_match.group(0).upper() if cwe_match else val
            # Endpoint/URL
            elif any(k in col for k in ('endpoint', 'url', 'path', 'эндпоинт')):
                f['endpoint'] = re.sub(r'`', '', val).strip()
            # Status/confirmed
            elif any(k in col for k in ('status', 'статус', 'confirmed', 'result', 'результат', 'verify')):
                v = val.lower()
                f['_confirmed'] = '✅' in val or 'confirmed' in v or 'подтвержд' in v or 'уязвим' in v

        if f.get('title') and f.get('severity'):
            if '_confirmed' not in f:
                f['_confirmed'] = True  # if in summary table, assume confirmed unless stated otherwise
            f['_sev'] = f.get('severity', 'medium')
            findings.append(f)

    if findings:
        return findings

    # ── Pattern 2: ### FINDING-ID — Title sections ───────────────────────────
    # Split on finding headers: ### IDOR-001, ### [F-001], ### INJ-001, ### BL-01, ### VULN-001
    section_pattern = re.compile(
        r'^#{2,4}\s+(?:\[)?([A-Z][\w-]*-\d+)(?:\])?\s*[:\s—–-]+\s*(.+)',
        re.MULTILINE
    )

    # Split document into sections by finding headers
    splits = list(section_pattern.finditer(text))
    for i, m in enumerate(splits):
        fid    = m.group(1)
        title  = m.group(2).strip()
        # section body: from end of this match to start of next
        start = m.end()
        end   = splits[i + 1].start() if i + 1 < len(splits) else len(text)
        body  = text[start:end]

        sev_m  = re.search(r'\*\*Severity[:\*\s]+\**\s*([A-Za-z/]+)', body, re.IGNORECASE)
        cwe_m  = re.search(r'CWE-(\d+)', body, re.IGNORECASE)
        ep_m   = re.search(r'\*\*Endpoint[:\*\s]+`?([^\n`\*]+)', body, re.IGNORECASE)
        cvss_m = re.search(r'CVSS\s*(?:3\.1)?[:\s]+(\d+(?:\.\d+)?)', body, re.IGNORECASE)

        # Severity may be embedded in the section title: "F-001 — CRITICAL: Some Title"
        title_sev_m = re.match(r'^(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s*[:\-–—]\s*', title, re.IGNORECASE)
        if title_sev_m:
            sev_raw = title_sev_m.group(1).lower()
            title   = title[title_sev_m.end():].strip()
        elif sev_m:
            sev_raw = sev_m.group(1).lower().strip()
        else:
            sev_raw = 'medium'
        confirmed = ('✅' in body or 'confirmed' in body.lower()
                     or 'подтвержд' in body.lower() or '❌' not in body)

        f = {
            'id':         fid,
            'title':      title,
            'severity':   SEV_MAP.get(sev_raw, sev_raw),
            'cwe':        f'CWE-{cwe_m.group(1)}' if cwe_m else '',
            'endpoint':   ep_m.group(1).strip() if ep_m else '',
            'cvss_score': float(cvss_m.group(1)) if cvss_m else None,
            '_confirmed': confirmed,
            '_sev':       SEV_MAP.get(sev_raw, sev_raw),
            '_from_md':   True,
        }
        findings.append(f)

    return findings


def get_target_data(target_name):
    """Aggregate all agents for a target.
    Returns dict: {agent_name: {findings:[], summary:{}, files:[], engagement:{}}}
    """
    target_dir = REPORTS_DIR / target_name
    if not target_dir.exists():
        return {}

    result = {}
    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    for agent_dir in sorted(target_dir.iterdir()):
        if not agent_dir.is_dir():
            continue

        agent = agent_dir.name
        findings = []
        summary = {}
        engagement = {}

        # Try findings.json first
        fj = agent_dir / "findings.json"
        agg_fj = agent_dir / "data" / "aggregated-findings.json"

        if fj.exists():
            findings, summary, engagement, raw_data = _parse_findings_from_file(fj)
            # Build summary from findings if not present
            if not summary and findings:
                counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                confirmed = 0
                for f in findings:
                    sev = str(f.get("severity", "")).lower()
                    if sev in counts:
                        counts[sev] += 1
                    if str(f.get("confirmed", f.get("status", ""))).upper() in ("TRUE", "CONFIRMED"):
                        confirmed += 1
                summary = {**counts, "total": len(findings), "confirmed": confirmed}
        elif agg_fj.exists():
            findings, summary, engagement, raw_data = _parse_findings_from_file(agg_fj)
            if not summary and findings:
                counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                confirmed = 0
                for f in findings:
                    sev = str(f.get("severity", "")).lower()
                    if sev in counts:
                        counts[sev] += 1
                    confirmed_val = f.get("confirmed", True)
                    if confirmed_val is True or str(confirmed_val).upper() == "CONFIRMED":
                        confirmed += 1
                summary = {**counts, "total": len(findings), "confirmed": confirmed}

        # If no JSON findings, try to parse from markdown files
        if not findings:
            # Only parse report.md to avoid attack-chains.md / attack-paths.md
            # being picked up as fake findings
            md_files = sorted(
                [f for f in agent_dir.glob("*.md") if f.name == "report.md"]
                or agent_dir.glob("*.md")
            )
            for md_file in md_files:
                try:
                    md_text = md_file.read_text(errors='replace')
                    parsed = parse_md_findings(md_text)
                    if parsed:
                        findings.extend(parsed)
                except Exception:
                    pass
            # Build summary from parsed md findings
            if findings:
                counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                confirmed = 0
                for f in findings:
                    sev = str(f.get("severity", f.get("_sev", ""))).lower()
                    if sev in counts:
                        counts[sev] += 1
                    if f.get("_confirmed", False):
                        confirmed += 1
                summary = {**counts, "total": len(findings), "confirmed": confirmed}

        # Normalize confirmed field on each finding.
        # Only override _confirmed when an explicit confirmed/status key exists
        # (JSON-parsed findings). Markdown-parsed findings already have _confirmed
        # set correctly by parse_md_findings — don't overwrite them.
        for f in findings:
            raw_conf = f.get("confirmed", f.get("status"))  # None if key absent
            if raw_conf is not None:
                if raw_conf is True or str(raw_conf).upper() in ("TRUE", "CONFIRMED"):
                    f["_confirmed"] = True
                else:
                    f["_confirmed"] = False
            elif "_confirmed" not in f:
                f["_confirmed"] = True
            # Normalize severity to lowercase
            f["_sev"] = str(f.get("severity", "")).lower()

        # Collect all files (md + json at top level)
        all_files = (
            list(agent_dir.glob("*.md")) +
            list(agent_dir.glob("*.json")) +
            list(agent_dir.glob("*.txt")) +
            list(agent_dir.glob("*.py"))
        )
        # Deduplicate and sort
        file_names = sorted(set(f.name for f in all_files if f.is_file()))

        # Last run date
        mtimes = [f.stat().st_mtime for f in all_files if f.is_file()]
        last_run = datetime.fromtimestamp(max(mtimes)).strftime("%Y-%m-%d") if mtimes else ""

        result[agent] = {
            "findings":   findings,
            "summary":    summary,
            "files":      file_names,
            "engagement": engagement,
            "last_run":   last_run,
            "path":       str(agent_dir.relative_to(LAB_DIR)),
        }

    return result


def detect_overlap(agents_data):
    """Find findings present in 2+ agents.
    Keys by CWE first, then normalized endpoint, then first 50 chars of title.
    Returns list of {key, matches: [{agent, finding}]}
    """
    # bucket: key -> list of (agent, finding)
    buckets = {}

    for agent, data in agents_data.items():
        for f in data.get("findings", []):
            keys_tried = []

            cwe = str(f.get("cwe", "")).strip().upper()
            if cwe and cwe != "NONE" and cwe != "":
                keys_tried.append(("cwe", cwe))

            endpoint = str(f.get("endpoint", "")).strip()
            if endpoint:
                # normalize: strip query params, lowercase
                norm_ep = re.sub(r'\?.*', '', endpoint).lower().strip()
                if norm_ep:
                    keys_tried.append(("endpoint", norm_ep))

            title = str(f.get("title", ""))[:50].strip().lower()
            if title:
                keys_tried.append(("title", title))

            for key_type, key_val in keys_tried:
                bucket_key = f"{key_type}:{key_val}"
                buckets.setdefault(bucket_key, []).append((agent, f))
                break  # use first available key only

    overlaps = []
    seen_keys = set()
    for bucket_key, matches in buckets.items():
        agents_in = set(m[0] for m in matches)
        if len(agents_in) >= 2 and bucket_key not in seen_keys:
            seen_keys.add(bucket_key)
            # Deduplicate by agent (keep first finding per agent)
            seen_agents = {}
            deduped = []
            for agent, finding in matches:
                if agent not in seen_agents:
                    seen_agents[agent] = True
                    deduped.append({"agent": agent, "finding": finding})
            overlaps.append({"key": bucket_key, "matches": deduped})

    return overlaps


def render_md(text):
    """Simple Markdown -> HTML renderer (no external libs)."""
    # Escape HTML first
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    lines = text.split("\n")
    html_parts = []
    i = 0
    in_list = None   # "ul" or "ol"
    in_table = False

    def flush_list():
        nonlocal in_list
        if in_list:
            html_parts.append(f"</{in_list}>")
            in_list = None

    def flush_table():
        nonlocal in_table
        if in_table:
            html_parts.append("</tbody></table>")
            in_table = False

    def inline(s):
        # code spans
        s = re.sub(r'`([^`]+)`', r'<code>\1</code>', s)
        # bold
        s = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', s)
        s = re.sub(r'__([^_]+)__', r'<strong>\1</strong>', s)
        # italic
        s = re.sub(r'\*([^*]+)\*', r'<em>\1</em>', s)
        s = re.sub(r'_([^_]+)_', r'<em>\1</em>', s)
        # links
        s = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', s)
        return s

    while i < len(lines):
        line = lines[i]

        # Fenced code block
        if line.strip().startswith("```"):
            flush_list()
            flush_table()
            lang = line.strip()[3:].strip()
            code_lines = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code_lines.append(lines[i].replace("&amp;", "&amp;amp;").replace("&lt;", "&lt;").replace("&gt;", "&gt;"))
                i += 1
            code_content = "\n".join(code_lines)
            html_parts.append(f'<pre><code class="lang-{lang}">{code_content}</code></pre>')
            i += 1
            continue

        # HR
        if re.match(r'^(\s*[-*_]){3,}\s*$', line):
            flush_list()
            flush_table()
            html_parts.append("<hr>")
            i += 1
            continue

        # Headings
        m = re.match(r'^(#{1,4})\s+(.*)', line)
        if m:
            flush_list()
            flush_table()
            level = len(m.group(1))
            content = inline(m.group(2))
            html_parts.append(f"<h{level}>{content}</h{level}>")
            i += 1
            continue

        # Table row (detect by | chars)
        if "|" in line and line.strip().startswith("|"):
            flush_list()
            if not in_table:
                html_parts.append('<table><thead><tr>')
                cells = [c.strip() for c in line.strip().strip("|").split("|")]
                for c in cells:
                    html_parts.append(f"<th>{inline(c)}</th>")
                html_parts.append("</tr></thead><tbody>")
                in_table = True
                # skip separator row
                if i + 1 < len(lines) and re.match(r'^[\|\s\-:]+$', lines[i+1]):
                    i += 2
                    continue
            else:
                cells = [c.strip() for c in line.strip().strip("|").split("|")]
                html_parts.append("<tr>")
                for c in cells:
                    html_parts.append(f"<td>{inline(c)}</td>")
                html_parts.append("</tr>")
            i += 1
            continue
        else:
            flush_table()

        # Unordered list
        m = re.match(r'^(\s*)[*\-+]\s+(.*)', line)
        if m:
            if in_list != "ul":
                flush_list()
                html_parts.append("<ul>")
                in_list = "ul"
            html_parts.append(f"<li>{inline(m.group(2))}</li>")
            i += 1
            continue

        # Ordered list
        m = re.match(r'^(\s*)\d+\.\s+(.*)', line)
        if m:
            if in_list != "ol":
                flush_list()
                html_parts.append("<ol>")
                in_list = "ol"
            html_parts.append(f"<li>{inline(m.group(2))}</li>")
            i += 1
            continue

        # Empty line
        if line.strip() == "":
            flush_list()
            flush_table()
            html_parts.append("")
            i += 1
            continue

        # Regular paragraph
        flush_list()
        flush_table()
        html_parts.append(f"<p>{inline(line)}</p>")
        i += 1

    flush_list()
    flush_table()
    return "\n".join(html_parts)


def highlight_json(json_str):
    """Add syntax highlighting spans to a JSON string (already HTML-escaped)."""
    # We work on raw (not yet escaped) string, escape it, then highlight
    escaped = json_str.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # Keys: "key":
    escaped = re.sub(
        r'"([^"]+)"(\s*:)',
        r'<span class="json-key">"\1"</span>\2',
        escaped
    )
    # String values: : "value"
    escaped = re.sub(
        r'(:\s*)"([^"]*)"',
        r'\1<span class="json-str">"\2"</span>',
        escaped
    )
    # Array string values (after [ or ,)
    escaped = re.sub(
        r'([,\[]\s*)"([^"]*)"',
        r'\1<span class="json-str">"\2"</span>',
        escaped
    )
    # Numbers
    escaped = re.sub(
        r'(:\s*)(-?\d+\.?\d*)',
        r'\1<span class="json-num">\2</span>',
        escaped
    )
    # Booleans and null
    escaped = re.sub(
        r'\b(true|false|null)\b',
        r'<span class="json-bool">\1</span>',
        escaped
    )
    return escaped


CSS = """
@import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Sans:wght@400;500&family=JetBrains+Mono:wght@400;500&display=swap');

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg:        #f1f5f9;
  --surface:   #ffffff;
  --sidebar:   #0f172a;
  --sidebar2:  #1e293b;
  --border:    #e2e8f0;
  --text:      #0f172a;
  --text2:     #64748b;
  --blue:      #2563eb;
  --purple:    #7c3aed;
  --cyan:      #0891b2;
  --red:       #dc2626;
  --orange:    #ea580c;
  --amber:     #d97706;
  --green:     #16a34a;
  --indigo:    #6366f1;
  --radius:    8px;
  --shadow:    0 1px 3px rgba(0,0,0,.08), 0 1px 2px rgba(0,0,0,.06);
  --shadow-md: 0 4px 16px rgba(0,0,0,.10);
}

html { height: 100%; }
body {
  font-family: 'DM Sans', sans-serif;
  background: var(--bg);
  color: var(--text);
  display: flex;
  min-height: 100vh;
  font-size: 14px;
  line-height: 1.6;
}

/* ── Sidebar ───────────────────────────────────── */
.sidebar {
  width: 220px;
  min-height: 100vh;
  background: var(--sidebar);
  display: flex;
  flex-direction: column;
  position: fixed;
  top: 0; left: 0; bottom: 0;
  z-index: 100;
  padding: 0;
}
.sidebar-logo {
  padding: 24px 20px 20px;
  border-bottom: 1px solid #1e293b;
}
.sidebar-logo .wordmark {
  font-family: 'Syne', sans-serif;
  font-weight: 800;
  font-size: 16px;
  color: #f8fafc;
  letter-spacing: -0.3px;
}
.sidebar-logo .sub {
  font-size: 11px;
  color: #475569;
  font-family: 'JetBrains Mono', monospace;
  margin-top: 2px;
}
.sidebar-nav {
  padding: 12px 0;
  flex: 1;
}
.nav-section {
  padding: 16px 20px 6px;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 1.2px;
  color: #334155;
  text-transform: uppercase;
}
.nav-link {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 20px;
  color: #94a3b8;
  text-decoration: none;
  font-size: 13.5px;
  font-weight: 500;
  transition: all .15s;
  border-left: 3px solid transparent;
}
.nav-link:hover { color: #f1f5f9; background: #1e293b; }
.nav-link.active { color: #f8fafc; border-left-color: var(--blue); background: #1e293b; }
.nav-icon { font-size: 16px; width: 18px; text-align: center; }
.sidebar-footer {
  padding: 16px 20px;
  border-top: 1px solid #1e293b;
  font-size: 11px;
  color: #334155;
  font-family: 'JetBrains Mono', monospace;
}

/* ── Main ──────────────────────────────────────── */
.main {
  margin-left: 220px;
  flex: 1;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}
.topbar {
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  padding: 0 32px;
  height: 56px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  position: sticky;
  top: 0;
  z-index: 50;
}
.topbar-title {
  font-family: 'Syne', sans-serif;
  font-weight: 700;
  font-size: 17px;
  color: var(--text);
}
.topbar-meta {
  font-size: 12px;
  color: var(--text2);
  font-family: 'JetBrains Mono', monospace;
}
.content { padding: 32px; }

/* ── Cards ─────────────────────────────────────── */
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 20px 24px;
  box-shadow: var(--shadow);
}

/* ── Stat row ──────────────────────────────────── */
.stats {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
  gap: 16px;
  margin-bottom: 32px;
}
.stat-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 20px 20px 16px;
  box-shadow: var(--shadow);
  position: relative;
  overflow: hidden;
}
.stat-card::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 3px;
  background: var(--accent, var(--blue));
}
.stat-num {
  font-family: 'Syne', sans-serif;
  font-size: 32px;
  font-weight: 800;
  color: var(--text);
  line-height: 1;
  margin-bottom: 6px;
}
.stat-lbl {
  font-size: 12px;
  color: var(--text2);
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: .5px;
}

/* ── Section title ─────────────────────────────── */
h2.section {
  font-family: 'Syne', sans-serif;
  font-size: 13px;
  font-weight: 700;
  letter-spacing: 1px;
  text-transform: uppercase;
  color: var(--text2);
  margin-bottom: 14px;
  display: flex;
  align-items: center;
  gap: 10px;
}
h2.section::after {
  content: '';
  flex: 1;
  height: 1px;
  background: var(--border);
}

/* ── Report cards ──────────────────────────────── */
.reports-grid { display: flex; flex-direction: column; gap: 12px; }
.report-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 18px 22px;
  box-shadow: var(--shadow);
  transition: box-shadow .2s, border-color .2s;
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 12px;
  align-items: start;
}
.report-card:hover { box-shadow: var(--shadow-md); border-color: #cbd5e1; }
.report-target {
  font-family: 'Syne', sans-serif;
  font-size: 15px;
  font-weight: 700;
  color: var(--text);
}
.report-agent-badge {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 2px 10px;
  border-radius: 100px;
  font-size: 11px;
  font-weight: 600;
  margin-left: 10px;
  font-family: 'JetBrains Mono', monospace;
}
.report-meta-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 4px;
  flex-wrap: wrap;
}
.report-ts { font-size: 12px; color: var(--text2); font-family: 'JetBrains Mono', monospace; }
.file-chip {
  display: inline-block;
  padding: 2px 8px;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 4px;
  font-size: 11px;
  color: var(--blue);
  text-decoration: none;
  font-family: 'JetBrains Mono', monospace;
  transition: background .15s;
}
.file-chip:hover { background: #dbeafe; border-color: #93c5fd; }
.file-chip.md { color: #2563eb; border-color: #bfdbfe; }
.file-chip.json { color: #64748b; border-color: #cbd5e1; }

/* Severity bar */
.sev-bar {
  display: flex;
  align-items: center;
  gap: 6px;
  white-space: nowrap;
}
.sev-pill {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 11px;
  font-weight: 600;
  font-family: 'JetBrains Mono', monospace;
}
.sev-dot {
  width: 8px; height: 8px;
  border-radius: 2px;
  flex-shrink: 0;
}
.sev-total {
  font-family: 'Syne', sans-serif;
  font-size: 22px;
  font-weight: 800;
  color: var(--text);
  line-height: 1;
}
.sev-total-lbl { font-size: 10px; color: var(--text2); font-weight: 500; }

/* Stacked bar */
.sev-stacked {
  height: 6px;
  border-radius: 3px;
  overflow: hidden;
  background: var(--bg);
  display: flex;
  margin-top: 8px;
  width: 100%;
}
.sev-segment { height: 100%; transition: width .3s; }

/* ── Skills ────────────────────────────────────── */
.skills-section { margin-bottom: 28px; }
.skills-group-label {
  font-family: 'Syne', sans-serif;
  font-size: 12px;
  font-weight: 700;
  letter-spacing: .8px;
  text-transform: uppercase;
  margin-bottom: 12px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.group-dot { width: 8px; height: 8px; border-radius: 2px; }
.skills-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 8px;
}
.skill-tile {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 13px 14px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  transition: all .15s;
  cursor: default;
}
.skill-tile.inactive { opacity: .35; filter: grayscale(1); }
.skill-tile:not(.inactive):hover {
  border-color: var(--tile-color, var(--blue));
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--tile-color, var(--blue)) 12%, transparent);
}
.skill-icon-box {
  width: 34px; height: 34px;
  border-radius: 6px;
  display: flex; align-items: center; justify-content: center;
  font-size: 14px;
  flex-shrink: 0;
  font-family: 'JetBrains Mono', monospace;
  font-weight: 500;
  margin-top: 1px;
}
.skill-name {
  font-weight: 600;
  font-size: 13px;
  color: var(--text);
  font-family: 'Syne', sans-serif;
  display: flex;
  align-items: center;
  gap: 7px;
  flex-wrap: wrap;
}
.skill-desc { font-size: 12px; color: var(--text2); margin-top: 3px; line-height: 1.5; }
.source-badge {
  display: inline-block;
  padding: 1px 7px;
  border-radius: 100px;
  font-size: 10px;
  font-weight: 600;
  font-family: 'JetBrains Mono', monospace;
  letter-spacing: .2px;
}

/* ── Finding rows ──────────────────────────────── */
.finding-row {
  display: flex;
  align-items: baseline;
  gap: 8px;
  padding: 5px 0;
  border-bottom: 1px solid var(--border);
  font-size: 12px;
}
.finding-row:last-child { border-bottom: none; }
.finding-sev {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  font-weight: 700;
  width: 52px;
  flex-shrink: 0;
  text-transform: uppercase;
}
.finding-cvss {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  color: var(--text2);
  width: 30px;
  flex-shrink: 0;
}
.finding-title { color: var(--text); flex: 1; line-height: 1.4; }
.skills-used {
  display: flex; gap: 5px; flex-wrap: wrap; margin-top: 8px;
}
.skill-chip {
  padding: 2px 8px;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 4px;
  font-size: 11px;
  color: var(--text2);
  font-family: 'JetBrains Mono', monospace;
}

/* ── Pipeline ──────────────────────────────────── */
.pipeline-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 18px 22px;
  box-shadow: var(--shadow);
  margin-bottom: 10px;
}
.pipeline-type {
  font-family: 'Syne', sans-serif;
  font-size: 13px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .5px;
  margin-bottom: 12px;
}
.pipeline-steps {
  display: flex;
  align-items: center;
  gap: 0;
  flex-wrap: wrap;
}
.pip-step {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 5px 12px;
  font-size: 12px;
  font-family: 'JetBrains Mono', monospace;
  color: var(--text);
  white-space: nowrap;
}
.pip-arrow {
  color: var(--text2);
  font-size: 12px;
  padding: 0 6px;
  flex-shrink: 0;
}

/* Flow steps inside pipeline cards */
.pip-flow-step {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 7px 12px;
  min-width: 120px;
}
.pip-flow-name {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  font-weight: 500;
  color: var(--text);
  white-space: nowrap;
}
.pip-flow-label {
  font-size: 10px;
  color: var(--text2);
  margin-top: 2px;
  line-height: 1.3;
}

/* ── Form ──────────────────────────────────────── */
.form-row { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
input[type=text], select {
  background: var(--bg);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 9px 14px;
  border-radius: var(--radius);
  font-size: 13px;
  font-family: 'DM Sans', sans-serif;
  outline: none;
  transition: border-color .15s, box-shadow .15s;
}
input[type=text] { width: 320px; }
input[type=text]:focus, select:focus {
  border-color: var(--blue);
  box-shadow: 0 0 0 3px rgba(37,99,235,.12);
}
.btn {
  background: var(--blue);
  color: #fff;
  border: none;
  padding: 9px 22px;
  border-radius: var(--radius);
  font-weight: 600;
  font-size: 13px;
  cursor: pointer;
  font-family: 'DM Sans', sans-serif;
  transition: opacity .15s;
}
.btn:hover { opacity: .88; }

/* ── Code box ──────────────────────────────────── */
.cmd-box {
  background: var(--sidebar);
  color: #7dd3fc;
  border-radius: var(--radius);
  padding: 14px 18px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 13px;
  margin-top: 12px;
  border: 1px solid #1e293b;
}
pre {
  background: var(--sidebar);
  color: #e2e8f0;
  border-radius: var(--radius);
  padding: 22px;
  overflow-x: auto;
  font-size: 12.5px;
  font-family: 'JetBrains Mono', monospace;
  white-space: pre-wrap;
  word-break: break-word;
  line-height: 1.7;
  border: 1px solid #1e293b;
}

/* ── Misc ──────────────────────────────────────── */
a { color: var(--blue); text-decoration: none; }
a:hover { text-decoration: underline; }
.tag {
  display: inline-block; padding: 2px 8px;
  border-radius: 4px; font-size: 11px; font-weight: 600;
}

@keyframes fadeIn { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:none; } }
.content > * { animation: fadeIn .25s ease both; }

/* ── Target cards on /reports ──────────────────── */
.target-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 28px 32px;
  box-shadow: var(--shadow);
  transition: box-shadow .2s, border-color .2s, transform .15s;
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 24px;
  align-items: start;
  margin-bottom: 16px;
}
.target-card:hover {
  box-shadow: var(--shadow-md);
  border-color: #cbd5e1;
  transform: translateY(-1px);
}
.target-name {
  font-family: 'Syne', sans-serif;
  font-size: 22px;
  font-weight: 800;
  color: var(--text);
  margin-bottom: 10px;
  letter-spacing: -0.4px;
}
.agent-badges-row {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
  margin-bottom: 12px;
}
.agent-badge-pill {
  display: inline-flex;
  align-items: center;
  padding: 3px 10px;
  border-radius: 100px;
  font-size: 11px;
  font-weight: 600;
  font-family: 'JetBrains Mono', monospace;
  border: 1px solid transparent;
}
.pipeline-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 9px;
  border-radius: 4px;
  font-size: 10px;
  font-weight: 700;
  font-family: 'JetBrains Mono', monospace;
  background: #f3f0ff;
  color: #7c3aed;
  border: 1px solid #ddd6fe;
  text-transform: uppercase;
  letter-spacing: .4px;
}
.target-meta-row {
  display: flex;
  align-items: center;
  gap: 16px;
  font-size: 12px;
  color: var(--text2);
  font-family: 'JetBrains Mono', monospace;
}
.view-link {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 8px 18px;
  background: var(--blue);
  color: #fff;
  border-radius: var(--radius);
  font-size: 13px;
  font-weight: 600;
  font-family: 'DM Sans', sans-serif;
  text-decoration: none;
  white-space: nowrap;
  transition: opacity .15s;
  align-self: center;
}
.view-link:hover { opacity: .88; text-decoration: none; }

/* ── Agent mini-cards on /target page ──────────── */
.agent-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 12px;
  margin-bottom: 28px;
}
.agent-mini-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 16px 18px;
  box-shadow: var(--shadow);
  border-left: 4px solid var(--agent-color, #64748b);
  transition: box-shadow .15s;
}
.agent-mini-card:hover { box-shadow: var(--shadow-md); }
.agent-mini-name {
  font-family: 'Syne', sans-serif;
  font-size: 14px;
  font-weight: 700;
  color: var(--text);
  margin-bottom: 6px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.agent-mini-sev {
  display: flex;
  gap: 5px;
  flex-wrap: wrap;
  margin-bottom: 10px;
}
.sev-badge {
  display: inline-flex;
  align-items: center;
  gap: 3px;
  padding: 2px 7px;
  border-radius: 4px;
  font-size: 10px;
  font-weight: 700;
  font-family: 'JetBrains Mono', monospace;
}
.agent-mini-findings {
  font-size: 11px;
  color: var(--text2);
  line-height: 1.6;
}
.agent-mini-files {
  margin-top: 8px;
  font-size: 10px;
  color: var(--text2);
  font-family: 'JetBrains Mono', monospace;
}

/* ── Unified finding rows ───────────────────────── */
.findings-unified { display: flex; flex-direction: column; gap: 0; }
.finding-unified-row {
  display: flex;
  align-items: baseline;
  gap: 10px;
  padding: 8px 12px;
  border-bottom: 1px solid var(--border);
  font-size: 12px;
  transition: background .1s;
}
.finding-unified-row:hover { background: #f8fafc; }
.finding-unified-row:last-child { border-bottom: none; }
.fu-sev {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  font-weight: 700;
  width: 58px;
  flex-shrink: 0;
  text-transform: uppercase;
  padding: 1px 5px;
  border-radius: 3px;
  text-align: center;
}
.fu-title { flex: 1; color: var(--text); line-height: 1.4; min-width: 0; }
.fu-agent {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  font-weight: 600;
  padding: 1px 7px;
  border-radius: 100px;
  white-space: nowrap;
  flex-shrink: 0;
}
.fu-cvss {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  color: var(--text2);
  width: 28px;
  flex-shrink: 0;
}
.fu-cwe {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  color: var(--text2);
  white-space: nowrap;
  flex-shrink: 0;
}
.agent-subheading {
  font-family: 'Syne', sans-serif;
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .8px;
  color: var(--text2);
  padding: 10px 12px 6px;
  background: var(--bg);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 8px;
}

/* ── Overlap cards ──────────────────────────────── */
.overlap-grid { display: flex; flex-direction: column; gap: 10px; margin-bottom: 28px; }
.overlap-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 14px 18px;
  box-shadow: var(--shadow);
  display: flex;
  align-items: flex-start;
  gap: 14px;
}
.overlap-count-badge {
  font-family: 'Syne', sans-serif;
  font-size: 20px;
  font-weight: 800;
  color: var(--purple);
  line-height: 1;
  flex-shrink: 0;
  min-width: 32px;
  text-align: center;
}
.overlap-count-lbl {
  font-size: 9px;
  color: var(--text2);
  text-transform: uppercase;
  letter-spacing: .5px;
  font-weight: 600;
  text-align: center;
}
.overlap-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--text);
  margin-bottom: 5px;
  line-height: 1.4;
}
.overlap-agents {
  display: flex;
  gap: 5px;
  flex-wrap: wrap;
}
.overlap-key {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  color: var(--text2);
  margin-bottom: 4px;
}

/* ── Confirmation badges ────────────────────────── */
.confirmed-badge {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  font-weight: 600;
  color: #16a34a;
  white-space: nowrap;
  flex-shrink: 0;
}
.unconfirmed-badge {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  font-weight: 600;
  color: #d97706;
  white-space: nowrap;
  flex-shrink: 0;
}

/* ── Breadcrumb ─────────────────────────────────── */
.breadcrumb {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
  color: var(--text2);
  margin-bottom: 20px;
  font-family: 'DM Sans', sans-serif;
}
.breadcrumb a { color: var(--blue); }
.breadcrumb-sep { color: var(--text2); }

/* ── Target header stats ────────────────────────── */
.target-stats-row {
  display: flex;
  gap: 24px;
  align-items: center;
  flex-wrap: wrap;
  margin-bottom: 28px;
  padding: 16px 20px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
}
.ts-stat {
  display: flex;
  flex-direction: column;
  align-items: center;
}
.ts-num {
  font-family: 'Syne', sans-serif;
  font-size: 28px;
  font-weight: 800;
  color: var(--text);
  line-height: 1;
}
.ts-lbl {
  font-size: 11px;
  color: var(--text2);
  text-transform: uppercase;
  letter-spacing: .4px;
  font-weight: 600;
  margin-top: 2px;
}
.ts-divider {
  width: 1px;
  height: 40px;
  background: var(--border);
}

/* ── Files section ──────────────────────────────── */
.files-agent-section {
  margin-bottom: 16px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
}
.files-agent-header {
  padding: 10px 16px;
  background: var(--bg);
  border-bottom: 1px solid var(--border);
  font-family: 'Syne', sans-serif;
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .6px;
  color: var(--text2);
  display: flex;
  align-items: center;
  gap: 8px;
}
.files-chips {
  padding: 12px 16px;
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

/* ── Markdown article ───────────────────────────── */
.md-article {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 36px 40px;
  box-shadow: var(--shadow);
  max-width: 900px;
  line-height: 1.8;
}
.md-article h1 {
  font-family: 'Syne', sans-serif;
  font-size: 24px;
  font-weight: 700;
  color: var(--text);
  margin-bottom: 16px;
  margin-top: 8px;
  line-height: 1.3;
}
.md-article h2 {
  font-family: 'Syne', sans-serif;
  font-size: 18px;
  font-weight: 700;
  color: var(--text);
  margin-top: 28px;
  margin-bottom: 12px;
  padding-bottom: 6px;
  border-bottom: 1px solid var(--border);
}
.md-article h3 {
  font-family: 'Syne', sans-serif;
  font-size: 14px;
  font-weight: 700;
  color: var(--text);
  margin-top: 20px;
  margin-bottom: 8px;
}
.md-article h4 {
  font-size: 13px;
  font-weight: 700;
  color: var(--text2);
  margin-top: 16px;
  margin-bottom: 6px;
  text-transform: uppercase;
  letter-spacing: .5px;
}
.md-article p {
  margin-bottom: 12px;
  color: var(--text);
  line-height: 1.8;
}
.md-article code {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  background: #f1f5f9;
  border: 1px solid var(--border);
  border-radius: 3px;
  padding: 1px 5px;
  color: #be185d;
}
.md-article pre {
  margin: 16px 0;
  border-radius: var(--radius);
}
.md-article pre code {
  background: none;
  border: none;
  padding: 0;
  color: #e2e8f0;
  font-size: 12.5px;
}
.md-article table {
  width: 100%;
  border-collapse: collapse;
  margin: 16px 0;
  font-size: 13px;
}
.md-article th {
  background: var(--bg);
  border: 1px solid var(--border);
  padding: 8px 12px;
  text-align: left;
  font-weight: 600;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: .4px;
  color: var(--text2);
}
.md-article td {
  border: 1px solid var(--border);
  padding: 8px 12px;
  vertical-align: top;
}
.md-article ul, .md-article ol {
  margin: 8px 0 12px 24px;
}
.md-article li { margin: 4px 0; }
.md-article strong { font-weight: 700; color: var(--text); }
.md-article em { font-style: italic; }
.md-article hr {
  border: none;
  border-top: 1px solid var(--border);
  margin: 24px 0;
}
.md-article a { color: var(--blue); }

/* ── JSON syntax highlighting ───────────────────── */
.json-view {
  background: var(--sidebar);
  color: #e2e8f0;
  border-radius: var(--radius);
  padding: 22px;
  overflow-x: auto;
  font-size: 12.5px;
  font-family: 'JetBrains Mono', monospace;
  white-space: pre-wrap;
  word-break: break-word;
  line-height: 1.7;
  border: 1px solid #1e293b;
}
.json-key { color: #93c5fd; }
.json-str { color: #86efac; }
.json-num { color: #fb923c; }
.json-bool { color: #c4b5fd; }
"""


def severity_bar_html(meta):
    if not meta or meta["total"] == 0:
        return ""
    total = meta["total"]
    parts = [
        ("critical", meta.get("critical", 0), SEV_COLORS["critical"]),
        ("high",     meta.get("high", 0),     SEV_COLORS["high"]),
        ("medium",   meta.get("medium", 0),   SEV_COLORS["medium"]),
        ("low",      meta.get("low", 0),      SEV_COLORS["low"]),
    ]
    pills = ""
    for key, count, color in parts:
        if count:
            pills += f'<span class="sev-pill"><span class="sev-dot" style="background:{color}"></span>{count}</span>'

    stacked = ""
    for key, count, color in parts:
        if count:
            pct = count / total * 100
            stacked += f'<div class="sev-segment" style="width:{pct:.1f}%;background:{color}"></div>'

    confirmed = meta.get("confirmed", 0)
    conf_html = f'<span style="font-size:11px;color:var(--green);font-family:JetBrains Mono,monospace">✓ {confirmed} confirmed</span>' if confirmed else ""

    return f"""
<div style="min-width:160px">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:6px">
    <div>
      <div class="sev-total">{total}</div>
      <div class="sev-total-lbl">findings</div>
    </div>
    <div>
      <div class="sev-bar">{pills}</div>
      {conf_html}
    </div>
  </div>
  <div class="sev-stacked" style="width:150px">{stacked}</div>
</div>"""


def findings_detail_html(meta):
    if not meta:
        return ""
    top = meta.get("top", [])
    skills_used = meta.get("skills", [])

    rows = ""
    for f in top:
        sev_raw = str(f.get("severity", "")).lower()
        color   = SEV_COLORS.get(sev_raw, "#64748b")
        cvss    = f.get("cvss_score") or f.get("cvss", "")
        title   = str(f.get("title", ""))[:72]
        rows += f"""<div class="finding-row">
  <span class="finding-sev" style="color:{color}">{sev_raw}</span>
  <span class="finding-cvss">{cvss}</span>
  <span class="finding-title">{title}</span>
</div>"""

    skills_html = ""
    if skills_used:
        chips = "".join(f'<span class="skill-chip">{s}</span>' for s in skills_used)
        skills_html = f'<div class="skills-used">{chips}</div>'

    if not rows and not skills_html:
        return ""

    return f"""<div style="margin-top:12px;padding-top:12px;border-top:1px solid var(--border)">
  {rows}
  {skills_html}
</div>"""


def agent_badge(agent_name):
    color = AGENT_COLORS.get(agent_name, "#64748b")
    bg = color + "18"
    return f'<span class="report-agent-badge" style="background:{bg};color:{color}">{agent_name}</span>'


def render(title, body, active=""):
    nav_links = [
        ("/",        "◎", "Dashboard", ""),
        ("/reports", "▤", "Reports",   "reports"),
        ("/audit",   "◈", "Audit",     "audit"),
        ("/skills",  "▦", "Skills",    "skills"),
        ("/run",     "⊕", "Run",       "run"),
    ]
    nav_html = ""
    for href, icon, label, key in nav_links:
        cls = "nav-link active" if active == key else "nav-link"
        nav_html += f'<a href="{href}" class="{cls}"><span class="nav-icon">{icon}</span>{label}</a>'

    skills = get_skills()
    installed = sum(1 for s in skills.values() if s["installed"])

    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — Security Lab</title>
<style>{CSS}</style>
</head>
<body>
<aside class="sidebar">
  <div class="sidebar-logo">
    <div class="wordmark">Security Lab</div>
    <div class="sub">pentest platform</div>
  </div>
  <nav class="sidebar-nav">
    <div class="nav-section">Navigation</div>
    {nav_html}
  </nav>
  <div class="sidebar-footer">{installed} skills active</div>
</aside>
<div class="main">
  <div class="topbar">
    <span class="topbar-title">{title}</span>
    <span class="topbar-meta">localhost:7777</span>
  </div>
  <div class="content">
    {body}
  </div>
</div>
</body>
</html>"""


def page_index():
    reports = get_reports()
    skills  = get_skills()
    installed = sum(1 for s in skills.values() if s["installed"])
    targets   = len(set(r["target"] for r in reports))

    total_findings = 0
    total_critical = 0
    for r in reports:
        if r["sev"]:
            total_findings += r["sev"]["total"]
            total_critical += r["sev"].get("critical", 0)

    stats = f"""
<div class="stats">
  <div class="stat-card" style="--accent:var(--blue)">
    <div class="stat-num">{installed}</div>
    <div class="stat-lbl">Skills Active</div>
  </div>
  <div class="stat-card" style="--accent:var(--purple)">
    <div class="stat-num">{targets}</div>
    <div class="stat-lbl">Targets</div>
  </div>
  <div class="stat-card" style="--accent:var(--green)">
    <div class="stat-num">{len(reports)}</div>
    <div class="stat-lbl">Reports</div>
  </div>
  <div class="stat-card" style="--accent:var(--orange)">
    <div class="stat-num">{total_findings}</div>
    <div class="stat-lbl">Findings</div>
  </div>
  <div class="stat-card" style="--accent:var(--red)">
    <div class="stat-num">{total_critical}</div>
    <div class="stat-lbl">Critical</div>
  </div>
</div>"""

    recent_cards = ""
    for r in reports[:6]:
        ts = datetime.fromtimestamp(r["mtime"]).strftime("%d %b %H:%M") if r["mtime"] else ""
        files_html = " ".join(
            f'<a class="file-chip" href="/view?path={r["path"]}&file={f}">{f}</a>'
            for f in r["files"][:3]
        )
        sev_html     = severity_bar_html(r["sev"])
        detail_html  = findings_detail_html(r["sev"])
        recent_cards += f"""
<div class="report-card">
  <div style="flex:1;min-width:0">
    <div style="margin-bottom:6px">
      <span class="report-target">{r["target"]}</span>
      {agent_badge(r["agent"])}
    </div>
    <div class="report-meta-row">
      <span class="report-ts">{ts}</span>
      {files_html}
    </div>
    {detail_html}
  </div>
  {sev_html}
</div>"""

    body = f"""
{stats}
<h2 class="section">Quick Launch</h2>
<div class="card" style="margin-bottom:28px">
  <div style="font-size:13px;color:var(--text2);margin-bottom:8px">Запустить пентест через Claude Code:</div>
  <div class="cmd-box">/pentest-orchestrator http://localhost:5050</div>
  <div style="margin-top:12px">
    <a href="/run" class="btn">⊕ Configure Pipeline</a>
  </div>
</div>
<h2 class="section">Recent Reports</h2>
<div class="reports-grid">
{recent_cards if recent_cards else '<div class="card" style="color:var(--text2)">Отчётов пока нет.</div>'}
</div>
{'<div style="margin-top:12px"><a href="/reports">All reports →</a></div>' if len(reports) > 6 else ''}
"""
    return render("Dashboard", body, active="")


def _build_agg_summary(agents_data):
    """Build aggregated severity summary across all agents."""
    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0, "confirmed": 0}
    for data in agents_data.values():
        s = data.get("summary", {})
        for k in totals:
            v = s.get(k, 0)
            try:
                totals[k] += int(v)
            except (TypeError, ValueError):
                pass
    return totals


def page_reports():
    reports = get_reports()
    if not reports:
        body = '<div class="card" style="color:var(--text2)">Нет отчётов. Запусти пентест через <a href="/run">Run</a>.</div>'
        return render("Reports", body, active="reports")

    # Group by target
    by_target = {}
    for r in reports:
        by_target.setdefault(r["target"], []).append(r)

    body = '<h2 class="section">All Targets</h2>'

    for target, items in sorted(by_target.items()):
        agents_data = get_target_data(target)
        agg = _build_agg_summary(agents_data)

        # Agent badges row
        agent_badge_html = ""
        pipeline_badge_html = ""
        for r in items:
            color = AGENT_COLORS.get(r["agent"], "#64748b")
            bg = color + "15"
            agent_badge_html += f'<span class="agent-badge-pill" style="background:{bg};color:{color};border-color:{color}30">{r["agent"]}</span>'

        # Pipeline badges
        for r in items:
            if r["agent"] in PIPELINE_AGENTS:
                badge_map = {
                    "orizon": ("Orizon Pipeline", "#7c3aed"),
                    "transilience": ("Multi-Agent", "#2563eb"),
                    "shannon": ("Autonomous", "#059669"),
                    "coordination": ("Coordination", "#2563eb"),
                }
                if r["agent"] in badge_map:
                    lbl, col = badge_map[r["agent"]]
                    pipeline_badge_html += f'<span class="pipeline-badge" style="background:{col}15;color:{col};border-color:{col}40">{lbl}</span>'

        # Aggregated severity bar (no "confirmed" from agg for display)
        sev_parts = [
            ("critical", agg.get("critical", 0), SEV_COLORS["critical"]),
            ("high",     agg.get("high", 0),     SEV_COLORS["high"]),
            ("medium",   agg.get("medium", 0),   SEV_COLORS["medium"]),
            ("low",      agg.get("low", 0),      SEV_COLORS["low"]),
        ]
        pills_html = ""
        stacked_html = ""
        total = agg.get("total", 0)
        for _, count, color in sev_parts:
            if count:
                pills_html += f'<span class="sev-pill"><span class="sev-dot" style="background:{color}"></span>{count}</span>'
        if total:
            for _, count, color in sev_parts:
                if count:
                    pct = count / total * 100
                    stacked_html += f'<div class="sev-segment" style="width:{pct:.1f}%;background:{color}"></div>'

        sev_block = ""
        if total:
            conf = agg.get("confirmed", 0)
            conf_lbl = f'<span style="font-size:11px;color:var(--green);font-family:\'JetBrains Mono\',monospace;margin-top:4px;display:block">✓ {conf} confirmed</span>' if conf else ""
            sev_block = f"""
<div>
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
    <div>
      <div class="sev-total">{total}</div>
      <div class="sev-total-lbl">findings</div>
    </div>
    <div class="sev-bar">{pills_html}</div>
  </div>
  <div class="sev-stacked" style="width:160px">{stacked_html}</div>
  {conf_lbl}
</div>"""

        # Last run date
        last_run = ""
        for data in agents_data.values():
            lr = data.get("last_run", "")
            if lr > last_run:
                last_run = lr

        n_agents = len(items)

        body += f"""
<div class="target-card">
  <div style="flex:1;min-width:0">
    <div class="target-name">{target}</div>
    <div class="agent-badges-row">
      {agent_badge_html}
      {pipeline_badge_html}
    </div>
    <div class="target-meta-row">
      <span>{n_agents} agent{"s" if n_agents != 1 else ""}</span>
      {f'<span>Last run: {last_run}</span>' if last_run else ''}
    </div>
  </div>
  <div style="display:flex;flex-direction:column;align-items:flex-end;gap:14px">
    {sev_block}
    <a href="/target?name={target}" class="view-link">View →</a>
  </div>
</div>"""

    return render("Reports", body, active="reports")


def page_target(target_name):
    if not target_name:
        return render("Target", '<div class="card">No target specified.</div>', active="reports")

    agents_data = get_target_data(target_name)
    if not agents_data:
        body = f'<div class="breadcrumb"><a href="/reports">Reports</a><span class="breadcrumb-sep">/</span><span>{target_name}</span></div>'
        body += '<div class="card" style="color:var(--text2)">No data found for this target.</div>'
        return render(target_name, body, active="reports")

    # ── Header stats ─────────────────────────────
    agg = _build_agg_summary(agents_data)
    n_agents = len(agents_data)
    total_f = agg.get("total", 0)
    total_c = agg.get("critical", 0)
    total_conf = agg.get("confirmed", 0)

    breadcrumb = f'''<div class="breadcrumb">
  <a href="/reports">Reports</a>
  <span class="breadcrumb-sep">/</span>
  <span style="color:var(--text);font-weight:600">{target_name}</span>
</div>'''

    stats_row = f'''<div class="target-stats-row">
  <div class="ts-stat"><div class="ts-num">{n_agents}</div><div class="ts-lbl">Agents</div></div>
  <div class="ts-divider"></div>
  <div class="ts-stat"><div class="ts-num">{total_f}</div><div class="ts-lbl">Findings total</div></div>
  <div class="ts-divider"></div>
  <div class="ts-stat" style="--col:{SEV_COLORS['critical']}">
    <div class="ts-num" style="color:{SEV_COLORS['critical']}">{total_c}</div>
    <div class="ts-lbl">Critical</div>
  </div>
  <div class="ts-divider"></div>
  <div class="ts-stat">
    <div class="ts-num" style="color:{SEV_COLORS['low']}">{total_conf}</div>
    <div class="ts-lbl">Confirmed</div>
  </div>
</div>'''

    # ── Section 1: Agent Overview ─────────────────
    agent_cards_html = ""
    for agent, data in sorted(agents_data.items()):
        color = AGENT_COLORS.get(agent, "#64748b")
        s = data.get("summary", {})
        findings = data.get("findings", [])
        files = data.get("files", [])
        is_pipeline = agent in PIPELINE_AGENTS

        # Source badge
        skill_meta = SKILLS_META.get(agent, {})
        src = skill_meta.get("source", "")
        smeta = SOURCE_META.get(src, {})
        src_badge_html = ""
        if smeta:
            src_badge_html = f'<span class="source-badge" style="background:{smeta["bg"]};color:{smeta["color"]}">{smeta["label"]}</span>'

        # Severity pills
        sev_html = ""
        for sev_k, sev_color in [("critical", SEV_COLORS["critical"]), ("high", SEV_COLORS["high"]),
                                   ("medium", SEV_COLORS["medium"]), ("low", SEV_COLORS["low"])]:
            cnt = int(s.get(sev_k, 0))
            if cnt:
                sev_html += f'<span class="sev-badge" style="background:{sev_color}15;color:{sev_color}">{cnt} {sev_k}</span>'

        # Top 3 findings
        SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        top3 = sorted(findings, key=lambda f: SEV_ORDER.get(f.get("_sev", ""), 9))[:3]
        top_html = ""
        for f in top3:
            sev_c = SEV_COLORS.get(f.get("_sev", ""), "#64748b")
            title_short = str(f.get("title", ""))[:60]
            top_html += f'<div style="display:flex;gap:6px;margin-bottom:3px"><span style="color:{sev_c};font-family:\'JetBrains Mono\',monospace;font-size:10px;font-weight:700;width:50px;flex-shrink:0;text-transform:uppercase">{f.get("_sev","")}</span><span style="font-size:11px;color:var(--text)">{title_short}</span></div>'

        if not top_html and not sev_html:
            top_html = '<span style="font-size:11px;color:var(--text2)">No structured findings — see files below</span>'

        border_style = "border-left-color:" + ("#7c3aed" if is_pipeline else color)

        agent_cards_html += f"""
<div class="agent-mini-card" style="--agent-color:{color};{border_style}">
  <div class="agent-mini-name">
    {agent}
    {src_badge_html}
  </div>
  <div class="agent-mini-sev">{sev_html if sev_html else '<span style="font-size:11px;color:var(--text2)">no severity data</span>'}</div>
  <div class="agent-mini-findings">{top_html}</div>
  <div class="agent-mini-files">
    {len(files)} file{"s" if len(files) != 1 else ""} · <a href="/target?name={target_name}#files-{agent}">browse ↓</a>
    · <a href="/print?target={target_name}&agent={agent}" target="_blank" style="color:#7c3aed;font-weight:600">⬇ PDF</a>
  </div>
</div>"""

    # ── Section 2: All Findings ───────────────────
    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    # Collect all findings flat
    all_findings = []
    for agent, data in agents_data.items():
        for f in data.get("findings", []):
            all_findings.append((agent, f))

    findings_html = ""
    if all_findings:
        # Sort by severity, then group by agent
        sorted_findings = sorted(all_findings,
                                  key=lambda x: SEV_ORDER.get(x[1].get("_sev", ""), 9))

        # Group by agent for subheadings
        by_agent_ordered = {}
        for agent, f in sorted_findings:
            by_agent_ordered.setdefault(agent, []).append(f)

        findings_html = '<div class="findings-unified">'
        for agent, fs in by_agent_ordered.items():
            color = AGENT_COLORS.get(agent, "#64748b")
            bg = color + "15"
            findings_html += f'''<div class="agent-subheading">
  <span class="agent-badge-pill" style="background:{bg};color:{color};border-color:{color}30">{agent}</span>
  <span>{len(fs)} finding{"s" if len(fs) != 1 else ""}</span>
</div>'''
            for f in fs:
                sev = f.get("_sev", "info")
                sev_color = SEV_COLORS.get(sev, "#64748b")
                title = str(f.get("title", "No title"))
                cvss = f.get("cvss_score") or f.get("cvss", "")
                cwe = str(f.get("cwe", ""))
                confirmed = f.get("_confirmed", False)
                conf_badge = '<span class="confirmed-badge">✓ confirmed</span>' if confirmed else '<span class="unconfirmed-badge">⚠ unconfirmed</span>'

                findings_html += f'''<div class="finding-unified-row">
  <span class="fu-sev" style="background:{sev_color}18;color:{sev_color}">{sev}</span>
  <span class="fu-title">{title}</span>
  <span class="fu-cvss">{cvss}</span>
  <span class="fu-cwe">{cwe}</span>
  {conf_badge}
</div>'''
        findings_html += "</div>"
    else:
        findings_html = '<div class="card" style="color:var(--text2);text-align:center;padding:32px">No structured findings — view raw files below</div>'

    # ── Section 3: Overlap Detection ─────────────
    overlaps = detect_overlap(agents_data)
    overlap_html = ""
    if overlaps:
        for ov in overlaps:
            matches = ov["matches"]
            n = len(matches)
            # Use first finding's title as display title
            title = str(matches[0]["finding"].get("title", ov["key"]))[:80]
            key_display = ov["key"]
            agent_pills = ""
            for m in matches:
                ag = m["agent"]
                ac = AGENT_COLORS.get(ag, "#64748b")
                agent_pills += f'<span class="agent-badge-pill" style="background:{ac}15;color:{ac};border-color:{ac}30">{ag}</span>'
            overlap_html += f"""
<div class="overlap-card">
  <div style="text-align:center;flex-shrink:0;min-width:40px">
    <div class="overlap-count-badge">{n}</div>
    <div class="overlap-count-lbl">tools</div>
  </div>
  <div style="flex:1;min-width:0">
    <div class="overlap-key">{key_display}</div>
    <div class="overlap-title">{title}</div>
    <div class="overlap-agents">{agent_pills}</div>
  </div>
</div>"""
        overlap_section = f'<div class="overlap-grid">{overlap_html}</div>'
    else:
        overlap_section = '<div class="card" style="color:var(--text2);text-align:center;padding:24px">No duplicate findings across tools</div>'

    # ── Section 4: Files ──────────────────────────
    files_section_html = ""
    for agent, data in sorted(agents_data.items()):
        files = data.get("files", [])
        path = data.get("path", "")
        color = AGENT_COLORS.get(agent, "#64748b")
        if not files:
            continue

        chips = ""
        for fname in files:
            ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
            chip_cls = "file-chip md" if ext == "md" else ("file-chip json" if ext == "json" else "file-chip")
            chips += f'<a class="{chip_cls}" href="/view?path={path}&file={fname}">{fname}</a>'

        files_section_html += f"""
<div class="files-agent-section" id="files-{agent}">
  <div class="files-agent-header" style="border-left:3px solid {color}">
    <span class="agent-badge-pill" style="background:{color}15;color:{color};border-color:{color}30">{agent}</span>
    <span>{len(files)} files</span>
  </div>
  <div class="files-chips">{chips}</div>
</div>"""

    # Assemble page
    target_title = target_name.upper()
    body = f"""
{breadcrumb}
<div style="margin-bottom:20px">
  <h1 style="font-family:'Syne',sans-serif;font-size:28px;font-weight:800;color:var(--text);letter-spacing:-0.5px">{target_title}</h1>
</div>
{stats_row}

<h2 class="section">Agent Overview</h2>
<div class="agent-grid">{agent_cards_html}</div>

<h2 class="section">All Findings</h2>
<div class="card" style="padding:0;margin-bottom:28px;overflow:hidden">
  {findings_html}
</div>

<h2 class="section">Overlap Detection</h2>
{overlap_section}

<h2 class="section">Files</h2>
{files_section_html if files_section_html else '<div class="card" style="color:var(--text2)">No files found.</div>'}
"""
    return render(target_name, body, active="reports")


def page_view(path, filename):
    content = get_report_content(path, filename)
    if content is None:
        return render("Not Found", "<p>Файл не найден.</p>")

    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    nav_bar = f"""
<div style="margin-bottom:18px;display:flex;align-items:center;gap:12px;flex-wrap:wrap">
  <a href="/reports">← Reports</a>
  <span style="color:var(--text2);font-family:'JetBrains Mono',monospace;font-size:12px">{path}/{filename}</span>
</div>"""

    if ext == "md":
        rendered = render_md(content)
        file_body = f'{nav_bar}<div class="md-article">{rendered}</div>'
    elif ext == "json":
        try:
            parsed = json.loads(content)
            pretty = json.dumps(parsed, indent=2, ensure_ascii=False)
        except Exception:
            pretty = content
        highlighted = highlight_json(pretty)
        file_body = f'{nav_bar}<div class="json-view">{highlighted}</div>'
    else:
        escaped = content.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        file_body = f'{nav_bar}<pre>{escaped}</pre>'

    return render(filename, file_body, active="reports")


PIPELINES_DEF = [
    {
        "name": "Orizon Pipeline",
        "cmd": "/pentest-orchestrator <url> black-box",
        "color": "#7c3aed",
        "source": "orizon",
        "desc": "Полный black-box пентест: разведка → эксплуатация → attack tree → exploit chains",
        "steps": [
            ("recon-dominator",       "Recon",          "субдомены, порты, endpoints"),
            ("webapp-exploit-hunter", "Exploit",         "SQLi, XSS, SSRF, IDOR"),
            ("api-breaker",           "API",             "REST/GraphQL testing"),
            ("attack-path-architect", "Attack Tree",     "MITRE ATT&CK mapping"),
            ("vuln-chain-composer",   "Chain + CVSS",    "exploit chains, severity amplification"),
        ],
    },
    {
        "name": "Coordination (Transilience)",
        "cmd": "/coordination <url>",
        "color": "#2563eb",
        "source": "transilience",
        "desc": "Multi-agent динамическое тестирование: executor → validator → aggregator",
        "steps": [
            ("techstack-identification", "Fingerprint", "tech stack, headers, CDN"),
            ("injection",                "Injection",   "SQLi, SSTI, Cmd"),
            ("authentication",           "Auth",        "JWT, OAuth, session"),
            ("server-side",              "SSRF",        "internal network pivot"),
            ("client-side",              "XSS/CORS",    "DOM, reflected, stored"),
        ],
    },
    {
        "name": "Bug Bounty Pipeline",
        "cmd": "/pentest-orchestrator <url> bug-bounty",
        "color": "#d97706",
        "source": "shuvonsec",
        "desc": "Полный BB workflow с обязательной валидацией и финальным отчётом для H1/Bugcrowd",
        "steps": [
            ("bb-methodology-shuvonsec",    "Mindset",   "scope, priority ranking"),
            ("recon-dominator",             "Recon",     "attack surface"),
            ("webapp-exploit-hunter",       "Hunt",      "automated exploitation"),
            ("idor-testing",                "IDOR",      "systematic BOLA testing"),
            ("triage-validation-shuvonsec", "Validate",  "7-Question Gate"),
            ("report-writing-shuvonsec",    "Report",    "H1/Bugcrowd format"),
        ],
    },
    {
        "name": "pentest-orchestrator",
        "cmd": "/pentest-orchestrator <url> [auto]",
        "color": "#2563eb",
        "source": "internal",
        "desc": "Meta-router — автоматически определяет тип цели и выбирает нужный pipeline",
        "steps": [
            ("pentest-orchestrator", "Auto-detect", "black-box / white-box / api / finance / ai-app / bug-bounty"),
        ],
        "is_router": True,
    },
]

# Skills that belong to pipelines (shown in pipeline view, not standalone)
PIPELINE_SKILLS = {
    "recon-dominator", "webapp-exploit-hunter", "api-breaker",
    "attack-path-architect", "vuln-chain-composer", "cloud-pivot-finder",
    "bb-methodology-shuvonsec", "triage-validation-shuvonsec", "report-writing-shuvonsec",
    "pentest-orchestrator", "coordination",
}

ATTACK_CLASSES = {
    "SQLi / Injection":      ["injection", "sentry-review", "orizon", "manual"],
    "IDOR / BAC":            ["idor-testing", "transilience", "orizon", "manual"],
    "Auth / JWT":            ["authentication", "manual", "orizon", "sentry-review"],
    "Business Logic":        ["web-app-logic", "transilience"],
    "SSRF / SSTI":           ["server-side", "orizon", "manual"],
    "XSS / Client-side":     ["client-side", "sentry-review", "manual"],
    "AI / LLM":              ["ai-threat-testing"],
    "Static Code Review":    ["sentry-review", "security-review", "source-code-scanning"],
    "Recon / Attack Surface":["recon-dominator", "reconnaissance", "orizon"],
    "Bug Bounty / Report":   ["bug-bounty-main-shuvonsec", "triage-validation-shuvonsec"],
}

STANDALONE_GROUPS = [
    {
        "key": "static",
        "label": "Static Analysis",
        "color": "#0891b2",
        "desc": "Запускаются на исходном коде — нужен ./static/<target>/",
    },
    {
        "key": "offensive",
        "label": "Offensive — Individual",
        "color": "#dc2626",
        "desc": "Запускаются отдельно против конкретного класса уязвимостей",
    },
    {
        "key": "bounty",
        "label": "Bug Bounty — Tools",
        "color": "#d97706",
        "desc": "Методологии и reference — используются внутри BB Pipeline или отдельно",
    },
    {
        "key": "autonomous",
        "label": "Autonomous Agents",
        "color": "#059669",
        "desc": "Полностью автономные агенты с собственным workflow",
    },
    {
        "key": "utils",
        "label": "Utilities",
        "color": "#64748b",
        "desc": "Вспомогательные инструменты",
    },
]


def skill_tile_html(name, meta, color):
    cls   = "" if meta.get("installed") else " inactive"
    src   = meta.get("source", "")
    smeta = SOURCE_META.get(src, {})
    src_badge = ""
    if smeta:
        src_badge = f'<span class="source-badge" style="background:{smeta["bg"]};color:{smeta["color"]}">{smeta["label"]}</span>'
    return f"""<div class="skill-tile{cls}" style="--tile-color:{color}">
  <div class="skill-icon-box" style="background:{color}18;color:{color}">{meta.get('icon','·')}</div>
  <div style="flex:1;min-width:0">
    <div class="skill-name">{name} {src_badge}</div>
    <div class="skill-desc">{meta.get('desc','')}</div>
  </div>
</div>"""


def page_audit():
    """Coverage audit across all targets."""
    targets = []
    if REPORTS_DIR.exists():
        for td in sorted(REPORTS_DIR.iterdir()):
            if td.is_dir() and not td.name.startswith("SUMMARY"):
                targets.append(td.name)

    rows = []
    for target in targets:
        agents_data = get_target_data(target)
        run_agents = set(agents_data.keys())

        # Aggregate findings
        total_c = total_h = total_m = total_l = 0
        total_confirmed = 0
        all_findings_count = 0
        agent_rows = []
        for ag, data in agents_data.items():
            s = data.get("summary", {})
            c = int(s.get("critical", 0))
            h = int(s.get("high", 0))
            m = int(s.get("medium", 0))
            l = int(s.get("low", 0))
            conf = int(s.get("confirmed", 0))
            tot = int(s.get("total", 0))
            total_c += c; total_h += h; total_m += m; total_l += l
            total_confirmed += conf; all_findings_count += tot
            agent_rows.append({
                "name": ag, "c": c, "h": h, "m": m, "l": l,
                "confirmed": conf, "total": tot,
                "last_run": data.get("last_run", ""),
                "files": data.get("files", []),
            })

        # Coverage matrix
        coverage = {}
        for cls, skills in ATTACK_CLASSES.items():
            tested_by = [a for a in run_agents if a in skills]
            coverage[cls] = tested_by  # empty = not tested

        rows.append({
            "target": target,
            "agents": agent_rows,
            "coverage": coverage,
            "total_c": total_c, "total_h": total_h,
            "total_m": total_m, "total_l": total_l,
            "total_confirmed": total_confirmed,
            "all_findings": all_findings_count,
        })

    # Build HTML
    _SEV_COLORS = {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706", "low": "#16a34a"}

    css = """
    .audit-target { background:#fff; border-radius:12px; border:1px solid #e2e8f0;
                    padding:24px; margin-bottom:32px; }
    .audit-target-header { display:flex; align-items:center; gap:16px; margin-bottom:20px;
                           flex-wrap:wrap; }
    .audit-target-name { font-family:'Syne',sans-serif; font-size:1.4rem; font-weight:700;
                         color:#0f172a; }
    .audit-agg { display:flex; gap:8px; flex-wrap:wrap; }
    .audit-agg-pill { padding:2px 10px; border-radius:999px; font-size:.78rem;
                      font-weight:600; border:1px solid; }
    .audit-sections { display:grid; grid-template-columns:1fr 1fr; gap:20px; }
    @media(max-width:900px){ .audit-sections { grid-template-columns:1fr; } }

    .audit-agents-table { width:100%; border-collapse:collapse; font-size:.82rem; }
    .audit-agents-table th { text-align:left; padding:6px 10px; border-bottom:2px solid #e2e8f0;
                              color:#64748b; font-weight:600; font-size:.75rem; text-transform:uppercase; }
    .audit-agents-table td { padding:5px 10px; border-bottom:1px solid #f1f5f9; }
    .audit-agents-table tr:last-child td { border-bottom:none; }
    .audit-agents-table tr:hover td { background:#f8fafc; }
    .sev-c { color:#dc2626; font-weight:700; }
    .sev-h { color:#ea580c; font-weight:700; }
    .sev-m { color:#d97706; font-weight:600; }
    .sev-l { color:#16a34a; }

    .coverage-grid { display:grid; grid-template-columns:1fr; gap:4px; }
    .cov-row { display:flex; align-items:center; gap:8px; padding:4px 0;
               border-bottom:1px solid #f1f5f9; font-size:.8rem; }
    .cov-row:last-child { border-bottom:none; }
    .cov-label { flex:0 0 180px; color:#374151; }
    .cov-status { display:flex; gap:4px; flex-wrap:wrap; }
    .cov-tag { padding:1px 8px; border-radius:4px; font-size:.72rem; font-weight:500; }
    .cov-tested { background:#dcfce7; color:#166534; }
    .cov-untested { background:#f1f5f9; color:#94a3b8; font-style:italic; }
    .audit-section-title { font-size:.85rem; font-weight:700; color:#475569;
                           text-transform:uppercase; letter-spacing:.05em; margin-bottom:12px; }
    .audit-link { color:#2563eb; text-decoration:none; font-size:.8rem; }
    .audit-link:hover { text-decoration:underline; }
    """

    html_parts = [f"<style>{css}</style>",
                  "<h2 style='font-family:Syne,sans-serif;font-size:1.6rem;margin-bottom:24px;'>Coverage Audit</h2>"]

    for row in rows:
        target = row["target"]

        # Aggregate pills
        pills = ""
        for sev, cnt, label in [("critical", row["total_c"], "C"),
                                  ("high",     row["total_h"], "H"),
                                  ("medium",   row["total_m"], "M"),
                                  ("low",      row["total_l"], "L")]:
            if cnt:
                color = _SEV_COLORS[sev]
                pills += (f'<span class="audit-agg-pill" '
                          f'style="color:{color};border-color:{color}20;background:{color}10">'
                          f'{cnt} {label}</span>')

        confirmed_pct = (
            f"{row['total_confirmed']}/{row['all_findings']} confirmed"
            if row['all_findings'] else "no findings"
        )

        # Agents table
        agent_rows_html = ""
        for ar in sorted(row["agents"], key=lambda x: -(x["c"]*4 + x["h"]*3 + x["m"]*2 + x["l"])):
            badge = agent_badge(ar["name"])
            agent_rows_html += f"""
            <tr>
              <td>{badge} <a class="audit-link" href="/target?name={target}">{ar['name']}</a></td>
              <td class="sev-c">{ar['c'] or '—'}</td>
              <td class="sev-h">{ar['h'] or '—'}</td>
              <td class="sev-m">{ar['m'] or '—'}</td>
              <td class="sev-l">{ar['l'] or '—'}</td>
              <td style="color:#64748b">{ar['confirmed']}/{ar['total']}</td>
              <td style="color:#94a3b8;font-size:.75rem">{ar['last_run']}</td>
            </tr>"""

        agents_table = f"""
        <div class="audit-section-title">Agents ran ({len(row['agents'])})</div>
        <table class="audit-agents-table">
          <thead><tr>
            <th>Agent</th><th>C</th><th>H</th><th>M</th><th>L</th>
            <th>Confirmed</th><th>Date</th>
          </tr></thead>
          <tbody>{agent_rows_html}</tbody>
        </table>"""

        # Coverage matrix
        cov_rows_html = ""
        for cls, tested_by in row["coverage"].items():
            if tested_by:
                tags = " ".join(f'<span class="cov-tag cov-tested">{a}</span>' for a in tested_by)
            else:
                tags = '<span class="cov-tag cov-untested">not tested</span>'
            cov_rows_html += f"""
            <div class="cov-row">
              <span class="cov-label">{cls}</span>
              <span class="cov-status">{tags}</span>
            </div>"""

        coverage_block = f"""
        <div>
          <div class="audit-section-title">Attack class coverage</div>
          <div class="coverage-grid">{cov_rows_html}</div>
        </div>"""

        html_parts.append(f"""
        <div class="audit-target">
          <div class="audit-target-header">
            <span class="audit-target-name">
              <a href="/target?name={target}" class="audit-link" style="font-size:1.4rem;font-weight:700;color:#0f172a">{target}</a>
            </span>
            <div class="audit-agg">{pills}</div>
            <span style="color:#64748b;font-size:.82rem">{confirmed_pct}</span>
            <a href="/target?name={target}" class="audit-link">View details →</a>
          </div>
          <div class="audit-sections">
            {agents_table}
            {coverage_block}
          </div>
        </div>""")

    body = "\n".join(html_parts)
    return render("Audit", body, active="audit")


def page_skills():
    skills = get_skills()
    installed_total = sum(1 for s in skills.values() if s["installed"])

    # ── Section 1: Pipelines ──────────────────────────────────
    pip_html = ""
    for pipe in PIPELINES_DEF:
        color  = pipe["color"]
        smeta  = SOURCE_META.get(pipe["source"], {})
        src_badge = f'<span class="source-badge" style="background:{smeta.get("bg","#f8fafc")};color:{smeta.get("color","#64748b")}">{smeta.get("label","")}</span>' if smeta else ""

        # flow steps
        if pipe.get("is_router"):
            steps_html = f"""<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:10px">
  <div style="font-size:12px;color:var(--text2)">Routes to →</div>
  {''.join(f'<span class="pip-step" style="border-color:{color}40;color:{color}">{k}</span>' for k in ["black-box","white-box","api","finance","ai-app","bug-bounty"])}
</div>"""
        else:
            steps_html = '<div style="display:flex;align-items:center;gap:0;flex-wrap:wrap;margin-top:10px">'
            for i, (sname, slabel, sdesc) in enumerate(pipe["steps"]):
                smeta_s = skills.get(sname, {})
                installed_cls = "" if smeta_s.get("installed", False) else " style='opacity:.5'"
                steps_html += f"""<div style="display:flex;align-items:center;gap:0">
  <div class="pip-flow-step"{installed_cls}>
    <div class="pip-flow-name">{sname}</div>
    <div class="pip-flow-label">{sdesc}</div>
  </div>
  {'<span class="pip-arrow">→</span>' if i < len(pipe["steps"])-1 else ''}
</div>"""
            steps_html += "</div>"

        pip_html += f"""
<div class="pipeline-card" style="border-left:3px solid {color};margin-bottom:12px">
  <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px">
    <div>
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
        <span style="font-family:'Syne',sans-serif;font-weight:700;font-size:15px;color:var(--text)">{pipe['name']}</span>
        {src_badge}
      </div>
      <div style="font-size:12px;color:var(--text2)">{pipe['desc']}</div>
    </div>
    <code style="font-family:'JetBrains Mono',monospace;font-size:11px;color:{color};background:{color}12;padding:4px 10px;border-radius:4px;white-space:nowrap;flex-shrink:0">{pipe['cmd']}</code>
  </div>
  {steps_html}
</div>"""

    # ── Section 2: Standalone skills ─────────────────────────
    standalone_html = ""
    groups_map = {}
    for name, meta in skills.items():
        if name not in PIPELINE_SKILLS:
            g = meta.get("group", "utils")
            groups_map.setdefault(g, []).append((name, meta))

    for grp in STANDALONE_GROUPS:
        items = groups_map.get(grp["key"], [])
        if not items:
            continue
        color = grp["color"]
        tiles = "".join(skill_tile_html(n, m, color) for n, m in sorted(items))
        standalone_html += f"""
<div class="skills-section">
  <div class="skills-group-label" style="color:{color}">
    <span class="group-dot" style="background:{color}"></span>
    {grp['label']}
    <span style="font-size:11px;font-weight:400;color:var(--text2);text-transform:none;letter-spacing:0">{grp['desc']}</span>
  </div>
  <div class="skills-grid">{tiles}</div>
</div>"""

    body = f"""
<div style="color:var(--text2);font-size:13px;margin-bottom:28px">{installed_total} skills active</div>

<h2 class="section">Pipelines — coordinated skill chains</h2>
<div style="margin-bottom:36px">{pip_html}</div>

<h2 class="section">Standalone Skills — run individually</h2>
{standalone_html}"""

    return render("Skills", body, active="skills")


def page_run(query="", message=""):
    chains_html = ""
    for ptype, chain in PIPELINE_CHAINS.items():
        steps_html = '<span class="pip-arrow">→</span>'.join(
            f'<span class="pip-step">{s}</span>' for s in chain
        )
        chains_html += f"""
<div class="pipeline-card">
  <div class="pipeline-type">{ptype}</div>
  <div class="pipeline-steps">{steps_html}</div>
</div>"""

    msg_html = f'<div class="cmd-box" style="margin-bottom:20px">{message}</div>' if message else ""

    body = f"""
{msg_html}
<div class="card" style="margin-bottom:28px">
  <form method="POST" action="/run">
    <div class="form-row">
      <input type="text" name="target" placeholder="http://localhost:5050" value="{query}" required>
      <select name="ptype">
        <option value="auto">Auto-detect</option>
        <option value="black-box">Black-box</option>
        <option value="white-box">White-box</option>
        <option value="api">API</option>
        <option value="bug-bounty">Bug Bounty</option>
        <option value="ai-app">AI App</option>
        <option value="finance">Finance</option>
      </select>
      <button class="btn" type="submit">Generate Command</button>
    </div>
  </form>
</div>
<h2 class="section">Available Pipelines</h2>
{chains_html}
<div class="card" style="margin-top:20px;color:var(--text2);font-size:13px;line-height:2">
  Скопируй команду → вставь в <strong style="color:var(--text)">Claude Code</strong> → Claude запустит цепочку автоматически.
</div>"""
    return render("Run Pipeline", body, active="run")


def page_run_post(target, ptype):
    if ptype == "auto":
        if "./static" in target or target.startswith("/"):
            ptype = "white-box"
        elif any(k in target for k in ["bank", "pay", "finance", "balance"]):
            ptype = "finance"
        elif any(k in target for k in ["/ai", "/llm", "/chat", "gpt"]):
            ptype = "ai-app"
        elif not target.startswith("http://localhost") and "127.0.0.1" not in target:
            ptype = "bug-bounty"
        else:
            ptype = "black-box"

    chain = PIPELINE_CHAINS.get(ptype, PIPELINE_CHAINS["black-box"])
    cmd = f"/pentest-orchestrator {target} {ptype}"
    skills_list = " → ".join(chain)
    message = f"✓ Type: <strong>{ptype}</strong> &nbsp;·&nbsp; Pipeline: {skills_list}<br><br>Команда:<br><strong>{cmd}</strong>"
    return page_run(target, message)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def send_page(self, html, code=200):
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        if path == "/print":
            target = qs.get("target", [""])[0]
            agent  = qs.get("agent",  [""])[0]
            html   = page_print(target, agent)
            body   = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/":
            self.send_page(page_index())
        elif path == "/reports":
            self.send_page(page_reports())
        elif path == "/target":
            name = qs.get("name", [""])[0]
            self.send_page(page_target(name))
        elif path == "/audit":
            self.send_page(page_audit())
        elif path == "/skills":
            self.send_page(page_skills())
        elif path == "/run":
            self.send_page(page_run())
        elif path == "/view":
            p = qs.get("path", [""])[0]
            f = qs.get("file", [""])[0]
            self.send_page(page_view(p, f))
        elif path.startswith("/static/"):
            static_file = Path(__file__).parent / "static" / path[len("/static/"):]
            if static_file.exists() and static_file.is_file():
                ext = static_file.suffix.lower()
                ct = {"html": "text/html", "css": "text/css", "js": "application/javascript",
                      "png": "image/png", "jpg": "image/jpeg", "svg": "image/svg+xml"}.get(ext[1:], "application/octet-stream")
                body = static_file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", ct)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_page("<h1>404</h1>", 404)
        else:
            self.send_page("<h1>404</h1>", 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        data = parse_qs(self.rfile.read(length).decode())
        target = data.get("target", [""])[0]
        ptype  = data.get("ptype", ["auto"])[0]
        self.send_page(page_run_post(target, ptype))


def page_print(target: str, agent: str) -> str:
    """Render report.md as a clean, print-optimised HTML page."""
    if not target or not agent:
        return "<h1>Missing target or agent</h1>"

    report_path = REPORTS_DIR / target / agent / "report.md"
    if not report_path.exists():
        return f"<h1>report.md not found: {target}/{agent}</h1>"

    raw_md = report_path.read_text(errors="replace")

    if _MD_AVAILABLE:
        content_html = _md_lib.markdown(
            raw_md,
            extensions=["tables", "fenced_code", "nl2br"],
        )
    else:
        # Fallback: wrap in <pre> if markdown lib not installed yet
        escaped = raw_md.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        content_html = f"<pre style='white-space:pre-wrap'>{escaped}</pre>"

    date_str = datetime.now().strftime("%Y-%m-%d")

    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pentest Report — {target} / {agent}</title>
<style>
  /* ── Base ── */
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    font-size: 13px;
    line-height: 1.65;
    color: #1a1a1a;
    background: #fff;
    max-width: 900px;
    margin: 0 auto;
    padding: 40px 48px;
  }}

  /* ── Print button (hidden when printing) ── */
  .print-bar {{
    position: fixed;
    top: 0; left: 0; right: 0;
    background: #7c3aed;
    color: #fff;
    padding: 10px 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    z-index: 999;
    font-size: 13px;
  }}
  .print-bar strong {{ font-size: 14px; }}
  .btn-print {{
    background: #fff;
    color: #7c3aed;
    border: none;
    padding: 7px 20px;
    border-radius: 6px;
    font-weight: 700;
    font-size: 13px;
    cursor: pointer;
    letter-spacing: .02em;
  }}
  .btn-print:hover {{ background: #f3f0ff; }}
  .content {{ margin-top: 52px; }}

  /* ── Report header ── */
  .report-header {{
    border-bottom: 2px solid #7c3aed;
    padding-bottom: 16px;
    margin-bottom: 28px;
  }}
  .report-header h1 {{
    font-size: 22px;
    font-weight: 700;
    color: #111;
    margin-bottom: 4px;
  }}
  .report-meta {{
    font-size: 11px;
    color: #666;
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
    margin-top: 6px;
  }}
  .report-meta span {{ display: flex; align-items: center; gap: 4px; }}

  /* ── Typography ── */
  h1 {{ font-size: 20px; font-weight: 700; color: #111; margin: 32px 0 12px; }}
  h2 {{ font-size: 16px; font-weight: 700; color: #1a1a1a; margin: 28px 0 10px;
        border-bottom: 1px solid #e5e7eb; padding-bottom: 6px; }}
  h3 {{ font-size: 14px; font-weight: 700; color: #374151; margin: 20px 0 8px; }}
  h4 {{ font-size: 13px; font-weight: 600; color: #4b5563; margin: 14px 0 6px; }}
  p  {{ margin: 6px 0 10px; }}
  ul, ol {{ margin: 6px 0 10px 20px; }}
  li {{ margin-bottom: 3px; }}
  strong {{ font-weight: 700; color: #111; }}
  em {{ font-style: italic; color: #555; }}
  a  {{ color: #7c3aed; text-decoration: none; }}
  hr {{ border: none; border-top: 1px solid #e5e7eb; margin: 24px 0; }}

  /* ── Finding headings — colour by severity ── */
  h2:has(+ *) {{ }}
  h2[id*="critical"], h2[id*="crit"] {{ color: #dc2626; }}
  h2[id*="high"]                     {{ color: #d97706; }}
  h2[id*="medium"], h2[id*="med"]    {{ color: #2563eb; }}

  /* Severity badges inline in headings */
  h2 {{ }}

  /* ── Code ── */
  code {{
    font-family: "JetBrains Mono", "Fira Code", "Courier New", monospace;
    font-size: 11px;
    background: #f3f4f6;
    padding: 2px 6px;
    border-radius: 4px;
    color: #c0254f;
  }}
  pre {{
    background: #1e1e2e;
    color: #cdd6f4;
    border-radius: 8px;
    padding: 14px 16px;
    overflow-x: auto;
    margin: 10px 0 14px;
    font-size: 11px;
    line-height: 1.55;
  }}
  pre code {{
    background: none;
    padding: 0;
    color: inherit;
    font-size: inherit;
  }}

  /* ── Tables ── */
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
    margin: 10px 0 16px;
  }}
  th {{
    background: #f3f4f6;
    font-weight: 700;
    text-align: left;
    padding: 7px 10px;
    border: 1px solid #e5e7eb;
    color: #374151;
  }}
  td {{
    padding: 6px 10px;
    border: 1px solid #e5e7eb;
    vertical-align: top;
  }}
  tr:nth-child(even) td {{ background: #fafafa; }}

  /* ── Blockquote (used for artifact warnings) ── */
  blockquote {{
    border-left: 3px solid #f59e0b;
    background: #fffbeb;
    padding: 8px 14px;
    margin: 10px 0;
    border-radius: 0 6px 6px 0;
    font-size: 12px;
    color: #92400e;
  }}

  /* ── Severity colours for table cells ── */
  td:first-child {{ white-space: nowrap; }}

  /* ── Page breaks ── */
  h2 {{ page-break-before: auto; }}
  pre, table, blockquote {{ page-break-inside: avoid; }}

  /* ── Print media ── */
  @media print {{
    * {{ -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }}
    .print-bar {{ display: none !important; }}
    .print-hint {{ display: none !important; }}
    .content {{ margin-top: 0; }}
    body {{ padding: 0; font-size: 11.5px; max-width: 100%; }}
    pre {{ white-space: pre-wrap !important; word-break: break-all !important;
           overflow-x: visible !important; page-break-inside: avoid; }}
    pre code {{ white-space: pre-wrap !important; word-break: break-all !important; }}
    h2 {{ page-break-after: avoid; }}
    @page {{ margin: 14mm 16mm; size: A4; }}
  }}
</style>
</head>
<body>

<div class="print-bar">
  <strong>Security Lab — {target} / {agent}</strong>
  <div style="display:flex;align-items:center;gap:16px">
    <span class="print-hint" style="font-size:12px;color:#6b7280">💡 В настройках печати снять галочку «Колонтитулы» (Headers and footers)</span>
    <button class="btn-print" onclick="window.print()">⬇ Сохранить PDF</button>
  </div>
</div>

<div class="content">
  <div class="report-header">
    <div class="report-meta">
      <span>🎯 <strong>Target:</strong> {target}</span>
      <span>🤖 <strong>Agent:</strong> {agent}</span>
      <span>📅 <strong>Printed:</strong> {date_str}</span>
    </div>
  </div>
  {content_html}
</div>

<script>
  // Highlight severity keywords in h2 headings
  document.querySelectorAll('h2').forEach(h => {{
    const t = h.textContent;
    if (/CRITICAL/i.test(t)) h.style.color = '#dc2626';
    else if (/HIGH/i.test(t))     h.style.color = '#d97706';
    else if (/MEDIUM/i.test(t))   h.style.color = '#2563eb';
    else if (/LOW/i.test(t))      h.style.color = '#059669';
  }});
</script>

</body>
</html>"""


if __name__ == "__main__":
    server = HTTPServer(("", PORT), Handler)
    print(f"Security Lab Dashboard")
    print(f"  http://localhost:{PORT}")
    print(f"  Ctrl+C to stop")
    server.serve_forever()
