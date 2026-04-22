#!/usr/bin/env python3
"""
Generate / update findings.json from individual finding description.md files.

Usage:
    python3 scripts/gen_findings_json.py reports/<target>/<agent>

Reads:  reports/<target>/<agent>/findings/finding-NNN/description.md
Writes: reports/<target>/<agent>/findings.json

Safe to run incrementally — merges new findings with existing ones by ID.
"""

import json
import re
import sys
from pathlib import Path

SEV_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
}


def parse_description(text: str, fid: str) -> dict:
    title_m = re.search(r'^#\s+FINDING-\d+[:\s]+(.+)', text, re.MULTILINE)
    sev_m   = re.search(r'\*\*Severity[:\*\s]+\**\s*([A-Za-z]+)', text, re.IGNORECASE)
    cvss_m  = re.search(r'\*\*CVSS[^:]*:\**\s*([\d.]+)', text, re.IGNORECASE)
    cwe_m   = re.search(r'(CWE-\d+)', text, re.IGNORECASE)
    ep_m    = re.search(r'\*\*Endpoint[:\*\s]+`?([^\n`\*]+)', text, re.IGNORECASE)
    # Also try Russian endpoint labels
    if not ep_m:
        ep_m = re.search(r'\*\*Эндпоинт[:\*\s]+`?([^\n`\*]+)', text, re.IGNORECASE)
    status_m = re.search(r'\*\*Status[:\*\s]+\**\s*([A-Za-z_]+)', text, re.IGNORECASE)

    sev_raw  = sev_m.group(1).lower().strip() if sev_m else "medium"
    severity = SEV_MAP.get(sev_raw, sev_raw)
    status   = status_m.group(1).upper() if status_m else "CONFIRMED"
    confirmed = status == "CONFIRMED"

    return {
        "id":         fid,
        "title":      title_m.group(1).strip() if title_m else f"Finding {fid}",
        "severity":   severity,
        "cvss_score": float(cvss_m.group(1)) if cvss_m else None,
        "cwe":        cwe_m.group(1).upper() if cwe_m else "",
        "endpoint":   ep_m.group(1).strip() if ep_m else "",
        "status":     status,
        "confirmed":  confirmed,
    }


def main(agent_dir: Path) -> None:
    findings_dir = agent_dir / "findings"
    output_file  = agent_dir / "findings.json"

    if not findings_dir.exists():
        print(f"[!] No findings directory: {findings_dir}")
        sys.exit(1)

    # Load existing findings to preserve manually edited fields
    existing: dict[str, dict] = {}
    if output_file.exists():
        try:
            data = json.loads(output_file.read_text())
            for f in data.get("findings", []):
                existing[f["id"]] = f
        except Exception:
            pass

    # Scan finding-NNN directories
    parsed: list[dict] = []
    for finding_dir in sorted(findings_dir.iterdir()):
        if not finding_dir.is_dir():
            continue
        desc = finding_dir / "description.md"
        if not desc.exists():
            continue

        # Derive ID: finding-006 → F-006
        num_m = re.search(r'(\d+)$', finding_dir.name)
        if not num_m:
            continue
        fid = f"F-{int(num_m.group(1)):03d}"

        f = parse_description(desc.read_text(errors="replace"), fid)

        # Preserve any extra fields from existing entry
        if fid in existing:
            merged = {**existing[fid], **f}
            f = merged

        parsed.append(f)

    if not parsed:
        print("[!] No findings found.")
        sys.exit(1)

    # Sort by finding ID
    parsed.sort(key=lambda x: x["id"])

    # Build summary
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    confirmed = 0
    for f in parsed:
        sev = f.get("severity", "").lower()
        if sev in counts:
            counts[sev] += 1
        if f.get("confirmed"):
            confirmed += 1

    output = {
        "findings": parsed,
        "summary": {
            **counts,
            "total": len(parsed),
            "confirmed": confirmed,
        },
    }

    output_file.write_text(json.dumps(output, ensure_ascii=False, indent=2))
    print(f"[+] Written {len(parsed)} findings → {output_file}")
    print(f"    Critical:{counts['critical']}  High:{counts['high']}  "
          f"Medium:{counts['medium']}  Low:{counts['low']}  "
          f"Confirmed:{confirmed}/{len(parsed)}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <agent_dir>")
        print(f"  e.g. {sys.argv[0]} reports/eyeflow.ru/manual")
        sys.exit(1)

    agent_dir = Path(sys.argv[1])
    if not agent_dir.exists():
        print(f"[!] Directory not found: {agent_dir}")
        sys.exit(1)

    main(agent_dir)
