#!/bin/bash
# Security Skills Toolkit — automated installer for Claude Code
# Usage: curl -sL https://raw.githubusercontent.com/timderbak/security-lab-setup/main/install.sh | bash
# Or: bash install.sh [project-directory]

set -e

PROJECT_DIR="${1:-.}"
cd "$PROJECT_DIR"

echo "🔧 Security Skills Toolkit installer"
echo "📁 Directory: $(pwd)"
echo ""

# Create structure
mkdir -p .claude/skills .claude/agents reports scans configs static

# 1. NPX installs
echo "📦 [1/8] NPX skills..."
npx skills install getsentry/skills@security-review 2>/dev/null && echo "  ✅ getsentry/security-review" || echo "  ⚠️  getsentry failed (install manually)"
npx skills install agamm/claude-code-owasp 2>/dev/null && echo "  ✅ agamm/owasp-security" || echo "  ⚠️  owasp failed"
npx skills install unicodeveloper/shannon 2>/dev/null && echo "  ✅ unicodeveloper/shannon" || echo "  ⚠️  shannon failed"

# 2. Antigravity (selected security skills only)
echo "📦 [2/8] Antigravity security skills..."
git clone --depth 1 -q https://github.com/sickn33/antigravity-awesome-skills.git /tmp/_ag 2>/dev/null || { echo "  ❌ git clone failed"; }
if [ -d "/tmp/_ag/skills" ]; then
  for skill in idor-testing api-security-best-practices broken-authentication; do
    if [ -d "/tmp/_ag/skills/$skill" ]; then
      cp -r "/tmp/_ag/skills/$skill" .claude/skills/
      echo "  ✅ $skill"
    else
      echo "  ❌ $skill not found in repo"
    fi
  done
fi
rm -rf /tmp/_ag

# 3. Trail of Bits curated
echo "📦 [3/8] Trail of Bits curated..."
git clone --depth 1 -q https://github.com/trailofbits/skills-curated.git /tmp/_tob 2>/dev/null || { echo "  ❌ git clone failed"; }
if [ -d "/tmp/_tob/.claude/skills" ]; then
  cp -r /tmp/_tob/.claude/skills/* .claude/skills/ 2>/dev/null
  echo "  ✅ Trail of Bits ($(ls /tmp/_tob/.claude/skills/ 2>/dev/null | wc -l | tr -d ' ') skills)"
else
  # Try alternative structure
  if [ -d "/tmp/_tob/plugins" ]; then
    find /tmp/_tob/plugins -name "SKILL.md" -exec dirname {} \; | while read dir; do
      skill_name=$(basename "$dir")
      cp -r "$dir" .claude/skills/"$skill_name" 2>/dev/null
    done
    echo "  ✅ Trail of Bits (from plugins/)"
  else
    echo "  ⚠️  Trail of Bits — unexpected repo structure, install manually"
  fi
fi
rm -rf /tmp/_tob

# 4. Transilience
echo "📦 [4/8] Transilience communitytools..."
git clone --depth 1 -q https://github.com/transilienceai/communitytools.git /tmp/_trans 2>/dev/null || { echo "  ❌ git clone failed"; }
if [ -d "/tmp/_trans/projects/pentest/.claude" ]; then
  cp -r /tmp/_trans/projects/pentest/.claude/skills/* .claude/skills/ 2>/dev/null
  cp -r /tmp/_trans/projects/pentest/.claude/agents/* .claude/agents/ 2>/dev/null
  cp /tmp/_trans/AGENTS.md ./AGENTS.md 2>/dev/null
  echo "  ✅ Transilience (skills + agents + AGENTS.md)"
else
  echo "  ⚠️  Transilience — unexpected structure"
fi
rm -rf /tmp/_trans

# 5. Shuvonsec
echo "📦 [5/8] Shuvonsec bug bounty..."
git clone --depth 1 -q https://github.com/shuvonsec/claude-bug-bounty.git /tmp/_shuv 2>/dev/null || { echo "  ❌ git clone failed"; }
if [ -d "/tmp/_shuv/.claude/skills" ]; then
  cp -r /tmp/_shuv/.claude/skills/* .claude/skills/ 2>/dev/null
  echo "  ✅ Shuvonsec"
else
  echo "  ⚠️  Shuvonsec — unexpected structure"
fi
rm -rf /tmp/_shuv

# 6. Orizon pentest pipeline
echo "📦 [6/8] Orizon pentest pipeline..."
git clone --depth 1 -q https://github.com/Orizon-eu/claude-code-pentest.git /tmp/_orizon 2>/dev/null || { echo "  ❌ git clone failed"; }
if [ -d "/tmp/_orizon/.claude/skills" ]; then
  cp -r /tmp/_orizon/.claude/skills/* .claude/skills/ 2>/dev/null
  echo "  ✅ Orizon ($(ls /tmp/_orizon/.claude/skills/ 2>/dev/null | wc -l | tr -d ' ') skills)"
else
  # Try alternative path
  find /tmp/_orizon -name "SKILL.md" -exec dirname {} \; 2>/dev/null | while read dir; do
    skill_name=$(basename "$dir")
    cp -r "$dir" .claude/skills/"$skill_name" 2>/dev/null
  done
  echo "  ✅ Orizon (found skills via search)"
fi
rm -rf /tmp/_orizon

# 7. Eyadkelleh SecLists
echo "📦 [7/8] Eyadkelleh SecLists toolkit..."
git clone --depth 1 -q https://github.com/Eyadkelleh/awesome-claude-skills-security.git /tmp/_eyad 2>/dev/null || { echo "  ❌ git clone failed"; }
if [ -d "/tmp/_eyad/.claude" ]; then
  cp -r /tmp/_eyad/.claude/skills/* .claude/skills/ 2>/dev/null
  cp -r /tmp/_eyad/.claude/agents/* .claude/agents/ 2>/dev/null
  echo "  ✅ Eyadkelleh SecLists"
else
  echo "  ⚠️  Eyadkelleh — unexpected structure"
fi
rm -rf /tmp/_eyad

# 8. alirezarezvani pentest
echo "📦 [8/8] alirezarezvani pentest..."
git clone --depth 1 -q https://github.com/alirezarezvani/claude-skills.git /tmp/_alireza 2>/dev/null || { echo "  ❌ git clone failed"; }
if [ -d "/tmp/_alireza/engineering-team/security-pen-testing" ]; then
  cp -r "/tmp/_alireza/engineering-team/security-pen-testing" .claude/skills/
  echo "  ✅ alirezarezvani security-pen-testing"
else
  echo "  ⚠️  alirezarezvani — path changed, install manually"
fi
rm -rf /tmp/_alireza

# Summary
echo ""
echo "==========================================="
SKILLS_COUNT=$(find .claude/skills -name "SKILL.md" 2>/dev/null | wc -l | tr -d ' ')
AGENTS_COUNT=$(find .claude/agents -name "*.md" 2>/dev/null | wc -l | tr -d ' ')
echo "✅ Installation complete!"
echo "   Skills: $SKILLS_COUNT"
echo "   Agents: $AGENTS_COUNT"
echo "==========================================="
echo ""
echo "Next steps:"
echo "  cd $(pwd)"
echo "  claude"
echo ""
echo "Try:"
echo '  /security-review ./path/to/source/'
echo '  /reconnaissance http://target:port'
echo '  "Тестируй на IDOR http://target:port"'
echo ""
