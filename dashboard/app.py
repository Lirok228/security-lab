#!/usr/bin/env python3
"""
Security Lab Dashboard
Запуск: python3 dashboard/app.py
Открыть: http://localhost:7777
"""

import json
import os
import subprocess
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

LAB_DIR = Path(__file__).parent.parent
REPORTS_DIR = Path(os.environ.get("LAB_REPORTS", str(LAB_DIR / "reports")))
SKILLS_DIR  = Path(os.environ.get("LAB_SKILLS",  str(LAB_DIR / ".claude" / "skills")))
PORT = int(os.environ.get("PORT", 7777))

SKILLS_META = {
    "pentest-orchestrator": {"icon": "🎯", "group": "orchestrator", "desc": "Авто-роутинг по типу цели"},
    "recon-dominator":      {"icon": "🔍", "group": "orizon",       "desc": "Attack surface map"},
    "webapp-exploit-hunter":{"icon": "🕷️", "group": "orizon",       "desc": "SQLi, XSS, SSRF, IDOR"},
    "api-breaker":          {"icon": "🔓", "group": "orizon",       "desc": "REST/GraphQL тестирование"},
    "attack-path-architect":{"icon": "🗺️", "group": "orizon",       "desc": "MITRE ATT&CK mapping"},
    "vuln-chain-composer":  {"icon": "⛓️", "group": "orizon",       "desc": "Exploit chains + CVSS"},
    "cloud-pivot-finder":   {"icon": "☁️", "group": "orizon",       "desc": "Cloud misconfigs"},
    "security-review":      {"icon": "📋", "group": "static",       "desc": "Code review HIGH/MED/LOW"},
    "source-code-scanning": {"icon": "🔬", "group": "static",       "desc": "CodeQL, variant analysis"},
    "injection":            {"icon": "💉", "group": "offensive",    "desc": "SQL/NoSQL/SSTI/Cmd"},
    "web-app-logic":        {"icon": "🏦", "group": "offensive",    "desc": "Business logic flaws"},
    "server-side":          {"icon": "🌐", "group": "offensive",    "desc": "SSRF, HTTP smuggling"},
    "client-side":          {"icon": "🖥️", "group": "offensive",    "desc": "XSS, CORS, Prototype Pollution"},
    "authentication":       {"icon": "🔑", "group": "offensive",    "desc": "JWT, OAuth, 2FA bypass"},
    "idor-testing":         {"icon": "🆔", "group": "offensive",    "desc": "IDOR/BOLA systematic"},
    "api-security":         {"icon": "📡", "group": "offensive",    "desc": "GraphQL, REST, WebSocket"},
    "ai-threat-testing":    {"icon": "🤖", "group": "offensive",    "desc": "OWASP LLM Top 10"},
    "infrastructure":       {"icon": "🏗️", "group": "offensive",    "desc": "Network, AD, pivoting"},
    "cloud-containers":     {"icon": "🐳", "group": "offensive",    "desc": "AWS, K8s, Docker escapes"},
    "system":               {"icon": "💻", "group": "offensive",    "desc": "Linux/Windows privesc"},
    "triage-validation-shuvonsec": {"icon": "✅", "group": "bounty", "desc": "7-Question Gate"},
    "report-writing-shuvonsec":    {"icon": "📝", "group": "bounty", "desc": "H1/Bugcrowd reports"},
    "bug-bounty-main-shuvonsec":   {"icon": "💰", "group": "bounty", "desc": "Full BB pipeline"},
    "bb-methodology-shuvonsec":    {"icon": "🧠", "group": "bounty", "desc": "Mindset + workflow"},
    "web2-vuln-classes-shuvonsec": {"icon": "📚", "group": "bounty", "desc": "20 bug class reference"},
    "security-arsenal-shuvonsec":  {"icon": "🗡️", "group": "bounty", "desc": "Payloads + bypass tables"},
    "shannon":              {"icon": "🤖", "group": "autonomous",   "desc": "Autonomous pentester (Docker)"},
    "coordination":         {"icon": "🎛️", "group": "autonomous",   "desc": "Multi-agent orchestration"},
    "techstack-identification": {"icon": "🔭", "group": "utils",   "desc": "OSINT tech fingerprint"},
    "osint":                {"icon": "🕵️", "group": "utils",       "desc": "Company OSINT"},
    "cve-poc-generator":    {"icon": "💣", "group": "utils",       "desc": "CVE PoC scripts"},
    "ghidra-headless-tob":  {"icon": "⚙️",  "group": "utils",      "desc": "Reverse engineering"},
    "ffuf-web-fuzzing-tob": {"icon": "🌪️", "group": "utils",       "desc": "Web fuzzing"},
    "hackthebox":           {"icon": "📦", "group": "utils",       "desc": "HTB automation"},
    "hackerone":            {"icon": "🏅", "group": "utils",       "desc": "H1 platform automation"},
    "transilience-report-style": {"icon": "📄", "group": "utils",  "desc": "PDF отчёты"},
    "auth-bypass-testing":  {"icon": "🚪", "group": "utils",       "desc": "Auth checklist"},
}

GROUP_LABELS = {
    "orchestrator": "🎯 Оркестратор",
    "orizon":       "🔄 Orizon Pipeline",
    "static":       "📋 Static Analysis",
    "offensive":    "⚔️  Offensive",
    "bounty":       "💰 Bug Bounty",
    "autonomous":   "🤖 Autonomous",
    "utils":        "🛠️  Утилиты",
}

PIPELINE_CHAINS = {
    "black-box":   ["recon-dominator","webapp-exploit-hunter","api-breaker","attack-path-architect","vuln-chain-composer"],
    "white-box":   ["security-review","source-code-scanning","injection","authentication","triage-validation-shuvonsec"],
    "api":         ["api-breaker","api-security","idor-testing","injection"],
    "bug-bounty":  ["bb-methodology-shuvonsec","recon-dominator","webapp-exploit-hunter","idor-testing","web-app-logic","triage-validation-shuvonsec","report-writing-shuvonsec"],
    "ai-app":      ["ai-threat-testing","server-side","injection"],
    "finance":     ["web-app-logic","idor-testing","authentication","server-side"],
}


def get_reports():
    reports = []
    if not REPORTS_DIR.exists():
        return reports
    for target_dir in sorted(REPORTS_DIR.iterdir()):
        if not target_dir.is_dir() or target_dir.name == "SUMMARY.md":
            continue
        for agent_dir in sorted(target_dir.iterdir()):
            if not agent_dir.is_dir():
                continue
            md_files = list(agent_dir.glob("*.md"))
            json_files = list(agent_dir.glob("*.json"))
            if md_files or json_files:
                reports.append({
                    "target": target_dir.name,
                    "agent": agent_dir.name,
                    "path": str(agent_dir.relative_to(LAB_DIR)),
                    "files": [f.name for f in sorted(md_files + json_files)],
                    "mtime": max((f.stat().st_mtime for f in md_files + json_files), default=0),
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
            if d.is_dir() and (d / "SKILL.md").exists():
                installed.add(d.name)
    result = {}
    for name, meta in SKILLS_META.items():
        result[name] = {**meta, "installed": name in installed}
    # add any installed not in meta
    for name in installed:
        if name not in result:
            result[name] = {"icon": "📦", "group": "utils", "desc": "", "installed": True}
    return result


def render_html(title, body):
    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — Security Lab</title>
<style>
  :root {{
    --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
    --border: #30363d; --text: #c9d1d9; --text2: #8b949e;
    --green: #3fb950; --red: #f85149; --orange: #d29922;
    --blue: #58a6ff; --purple: #bc8cff; --cyan: #79c0ff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font: 14px/1.6 'SF Mono',monospace; }}
  a {{ color: var(--blue); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  nav {{ background: var(--bg2); border-bottom: 1px solid var(--border); padding: 0 24px;
         display: flex; align-items: center; gap: 24px; height: 52px; }}
  nav .logo {{ color: var(--green); font-weight: 700; font-size: 15px; }}
  nav a {{ color: var(--text2); font-size: 13px; }}
  nav a:hover {{ color: var(--text); text-decoration: none; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}
  h1 {{ font-size: 20px; margin-bottom: 20px; color: var(--cyan); }}
  h2 {{ font-size: 15px; margin: 20px 0 10px; color: var(--text2); text-transform: uppercase; letter-spacing: 1px; }}
  .card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 6px;
           padding: 16px; margin-bottom: 12px; }}
  .card:hover {{ border-color: var(--blue); }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }}
  .badge-critical {{ background: #3d1a1a; color: var(--red); }}
  .badge-high     {{ background: #2d1e0f; color: var(--orange); }}
  .badge-medium   {{ background: #1e2a1a; color: var(--green); }}
  .badge-low      {{ background: #1a1e2a; color: var(--blue); }}
  .badge-info     {{ background: var(--bg3); color: var(--text2); }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px; }}
  .skill-card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 6px;
                 padding: 12px 16px; display: flex; align-items: center; gap: 10px; }}
  .skill-card.installed {{ border-color: #21262d; }}
  .skill-card:not(.installed) {{ opacity: 0.4; }}
  .skill-icon {{ font-size: 20px; width: 28px; text-align: center; }}
  .skill-name {{ font-weight: 600; font-size: 13px; color: var(--cyan); }}
  .skill-desc {{ font-size: 12px; color: var(--text2); }}
  .pipeline {{ display: flex; align-items: center; gap: 6px; flex-wrap: wrap; margin: 8px 0; }}
  .pip-step {{ background: var(--bg3); border: 1px solid var(--border); border-radius: 4px;
               padding: 4px 10px; font-size: 12px; color: var(--cyan); }}
  .pip-arrow {{ color: var(--text2); font-size: 12px; }}
  form input, form select {{ background: var(--bg3); border: 1px solid var(--border); color: var(--text);
                              padding: 8px 12px; border-radius: 6px; font-size: 13px; font-family: inherit; }}
  form input {{ width: 360px; }}
  form select {{ width: 180px; }}
  button {{ background: var(--green); color: #000; border: none; padding: 8px 20px;
            border-radius: 6px; font-weight: 700; cursor: pointer; font-size: 13px; }}
  button:hover {{ opacity: 0.85; }}
  .cmd-box {{ background: var(--bg3); border: 1px solid var(--border); border-radius: 6px;
              padding: 12px 16px; font-size: 13px; color: var(--green); margin-top: 12px; }}
  .file-link {{ display: inline-block; margin: 2px 4px; padding: 2px 8px; background: var(--bg3);
                border-radius: 4px; font-size: 12px; color: var(--blue); }}
  .report-meta {{ color: var(--text2); font-size: 12px; margin-top: 4px; }}
  .report-target {{ font-weight: 700; color: var(--cyan); }}
  .report-agent {{ color: var(--purple); }}
  pre {{ background: var(--bg3); border: 1px solid var(--border); border-radius: 6px;
         padding: 16px; overflow-x: auto; font-size: 12px; white-space: pre-wrap; word-break: break-word; }}
  .summary-row {{ display: flex; gap: 16px; margin-bottom: 20px; flex-wrap: wrap; }}
  .summary-box {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 6px;
                  padding: 14px 20px; text-align: center; min-width: 120px; }}
  .summary-num {{ font-size: 28px; font-weight: 700; }}
  .summary-lbl {{ font-size: 12px; color: var(--text2); }}
</style>
</head>
<body>
<nav>
  <span class="logo">🛡️ Security Lab</span>
  <a href="/">Главная</a>
  <a href="/reports">Отчёты</a>
  <a href="/skills">Skills</a>
  <a href="/run">Запуск</a>
</nav>
<div class="container">
{body}
</div>
</body>
</html>"""


def page_index():
    reports = get_reports()
    skills = get_skills()
    installed_count = sum(1 for s in skills.values() if s["installed"])
    targets = len(set(r["target"] for r in reports))
    total_reports = len(reports)

    recent = ""
    for r in reports[:5]:
        recent += f"""<div class="card">
  <span class="report-target">{r['target']}</span> /
  <span class="report-agent">{r['agent']}</span>
  <div class="report-meta">{' '.join(f'<a class="file-link" href="/view?path={r["path"]}&file={f}">{f}</a>' for f in r['files'][:4])}</div>
</div>"""

    return render_html("Dashboard", f"""
<h1>Security Lab Dashboard</h1>
<div class="summary-row">
  <div class="summary-box"><div class="summary-num" style="color:var(--green)">{installed_count}</div><div class="summary-lbl">Skills</div></div>
  <div class="summary-box"><div class="summary-num" style="color:var(--blue)">{targets}</div><div class="summary-lbl">Таргетов</div></div>
  <div class="summary-box"><div class="summary-num" style="color:var(--purple)">{total_reports}</div><div class="summary-lbl">Отчётов</div></div>
</div>

<h2>Быстрый запуск</h2>
<div class="card">
  <a href="/run">🎯 Запустить pentest-orchestrator</a> — авто-роутинг по типу цели<br>
  <div style="margin-top:10px;color:var(--text2);font-size:13px;">Или вызови напрямую в Claude Code:
  <div class="cmd-box">/pentest-orchestrator http://localhost:5050</div></div>
</div>

<h2>Последние отчёты</h2>
{recent if recent else '<div class="card" style="color:var(--text2)">Отчётов пока нет</div>'}
<a href="/reports">Все отчёты →</a>
""")


def page_reports():
    reports = get_reports()
    if not reports:
        body = '<div class="card" style="color:var(--text2)">Нет отчётов. Запусти пентест через <a href="/run">Run</a>.</div>'
    else:
        body = ""
        current_target = None
        for r in reports:
            if r["target"] != current_target:
                current_target = r["target"]
                body += f'<h2>{current_target}</h2>'
            files_html = " ".join(
                f'<a class="file-link" href="/view?path={r["path"]}&file={f}">{f}</a>'
                for f in r["files"]
            )
            ts = datetime.fromtimestamp(r["mtime"]).strftime("%Y-%m-%d %H:%M") if r["mtime"] else ""
            body += f"""<div class="card">
  <span class="report-agent">{r['agent']}</span>
  <span style="color:var(--text2);font-size:12px;margin-left:12px">{ts}</span>
  <div class="report-meta" style="margin-top:8px">{files_html}</div>
</div>"""
    return render_html("Отчёты", f"<h1>Отчёты</h1>{body}")


def page_view(path, filename):
    content = get_report_content(path, filename)
    if content is None:
        return render_html("404", "<h1>Файл не найден</h1>")
    escaped = content.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    back = f'/reports'
    return render_html(filename, f"""
<div style="margin-bottom:16px">
  <a href="{back}">← Назад</a>
  <span style="color:var(--text2);margin-left:16px">{path}/{filename}</span>
</div>
<pre>{escaped}</pre>""")


def page_skills():
    skills = get_skills()
    groups = {}
    for name, meta in skills.items():
        g = meta["group"]
        groups.setdefault(g, []).append((name, meta))

    body = "<h1>Skills (38)</h1>"
    for gkey, glabel in GROUP_LABELS.items():
        items = groups.get(gkey, [])
        if not items:
            continue
        body += f"<h2>{glabel}</h2><div class='grid'>"
        for name, meta in sorted(items, key=lambda x: x[0]):
            cls = "installed" if meta["installed"] else ""
            body += f"""<div class="skill-card {cls}">
  <span class="skill-icon">{meta['icon']}</span>
  <div>
    <div class="skill-name">{name}</div>
    <div class="skill-desc">{meta['desc']}</div>
  </div>
</div>"""
        body += "</div>"
    return render_html("Skills", body)


def page_run(query="", message=""):
    chains_html = ""
    for ptype, chain in PIPELINE_CHAINS.items():
        steps = " ".join(
            f'<span class="pip-step">{s}</span><span class="pip-arrow">→</span>'
            for s in chain
        )[:-len('<span class="pip-arrow">→</span>')]
        chains_html += f"""<div class="card" style="margin-bottom:8px">
  <div style="color:var(--text2);font-size:12px;margin-bottom:6px">
    <strong style="color:var(--cyan)">{ptype}</strong>
  </div>
  <div class="pipeline">{steps}</div>
</div>"""

    msg_html = f'<div class="cmd-box" style="margin-bottom:16px">{message}</div>' if message else ""

    return render_html("Запуск", f"""
<h1>Запуск Pentest Orchestrator</h1>
{msg_html}
<div class="card">
  <form method="POST" action="/run">
    <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">
      <input name="target" placeholder="http://localhost:5050" value="{query}" required>
      <select name="ptype">
        <option value="auto">🤖 Авто-определение</option>
        <option value="black-box">🔲 Black-box</option>
        <option value="white-box">📋 White-box</option>
        <option value="api">📡 API</option>
        <option value="bug-bounty">💰 Bug Bounty</option>
        <option value="ai-app">🤖 AI App</option>
        <option value="finance">🏦 Finance</option>
      </select>
      <button type="submit">▶ Сгенерировать команду</button>
    </div>
  </form>
</div>

<h2>Доступные пайплайны</h2>
{chains_html}

<h2>Как запустить</h2>
<div class="card" style="color:var(--text2);font-size:13px">
  1. Скопируй команду ниже<br>
  2. Вставь в <strong style="color:var(--cyan)">Claude Code</strong> (этот чат)<br>
  3. Claude запустит нужную цепочку скиллов автоматически
</div>
""")


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

    message = f"""✅ Тип определён: <strong>{ptype}</strong><br>
Pipeline: {skills_list}<br><br>
Скопируй в Claude Code:<br>
<strong style="color:var(--green)">{cmd}</strong>"""

    return page_run(target, message)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # тишина в консоли

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

        if path == "/":
            self.send_page(page_index())
        elif path == "/reports":
            self.send_page(page_reports())
        elif path == "/skills":
            self.send_page(page_skills())
        elif path == "/run":
            self.send_page(page_run())
        elif path == "/view":
            p = qs.get("path", [""])[0]
            f = qs.get("file", [""])[0]
            self.send_page(page_view(p, f))
        else:
            self.send_page("<h1>404</h1>", 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        data = parse_qs(self.rfile.read(length).decode())
        target = data.get("target", [""])[0]
        ptype = data.get("ptype", ["auto"])[0]
        self.send_page(page_run_post(target, ptype))


if __name__ == "__main__":
    server = HTTPServer(("", PORT), Handler)
    print(f"🛡️  Security Lab Dashboard")
    print(f"   http://localhost:{PORT}")
    print(f"   Ctrl+C для остановки")
    server.serve_forever()
