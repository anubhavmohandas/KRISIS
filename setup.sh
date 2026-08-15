#!/usr/bin/env bash
# KRISIS setup — creates .venv, installs everything, verifies. Safe to re-run.
set -euo pipefail
cd "$(dirname "$0")"

# Colors only when stdout is a terminal, so piping to a log stays clean.
if [ -t 1 ]; then
    R=$'\033[0m'; B=$'\033[1m'; DIM=$'\033[2m'
    CYAN=$'\033[96m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'
    # 256-colour deep-blue -> bright-cyan ramp, one step per banner line.
    G1=$'\033[38;5;27m'; G2=$'\033[38;5;33m'; G3=$'\033[38;5;39m'
    G4=$'\033[38;5;45m'; G5=$'\033[38;5;51m'; G6=$'\033[38;5;87m'
else
    R=''; B=''; DIM=''; CYAN=''; GREEN=''; YELLOW=''; RED=''
    G1=''; G2=''; G3=''; G4=''; G5=''; G6=''
fi

step() { echo "${CYAN}${B}▸${R} ${B}$1${R}"; }
ok()   { echo "  ${GREEN}✓ $1${R}"; }
warn() { echo "  ${YELLOW}⚠️  $1${R}"; }
die()  { echo "  ${RED}✗ $1${R}" >&2; exit 1; }

cat <<EOF

${B}${G1}  ██╗  ██╗██████╗ ██╗███████╗██╗███████╗
${G2}  ██║ ██╔╝██╔══██╗██║██╔════╝██║██╔════╝
${G3}  █████╔╝ ██████╔╝██║███████╗██║███████╗
${G4}  ██╔═██╗ ██╔══██╗██║╚════██║██║╚════██║
${G5}  ██║  ██╗██║  ██║██║███████║██║███████║
${G6}  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚═╝╚══════╝${R}
${DIM}   🔎 Knowledge-Driven Risk Intelligence  ·  Evidence · Correlation · Risk · Memory${R}

${G3}  ─────────────◇  ${B}${G5}A N U B H A V   M O H A N D A S${R}${G3}  ◇─────────────${R}

EOF

step "🐍 Checking Python"
PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || die "$PY not found. Install Python 3.10 or newer."
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' \
    || die "Python 3.10+ required, found $("$PY" -V 2>&1)"
ok "$("$PY" -V 2>&1)"

step "📦 Setting up virtual environment"
if [ -d .venv ]; then
    ok ".venv already exists — reusing"
else
    "$PY" -m venv .venv || die "Could not create .venv"
    ok "Created ./.venv"
fi

step "⬇️  Installing KRISIS + evidence collectors"
echo "${DIM}     dnspython · python-whois · ipwhois · pyOpenSSL · pytest${R}"
./.venv/bin/python -m pip install --upgrade --quiet pip || die "pip upgrade failed"
./.venv/bin/pip install --quiet -e '.[collectors,dev]' || die "Install failed — see pip output above"
ok "Dependencies installed"

step "🔑 Configuring API keys"
if [ -f api_keys.txt ]; then
    ok "api_keys.txt already present — left untouched"
else
    cp api_keys.example.txt api_keys.txt
    ok "Created api_keys.txt from api_keys.example.txt"
    echo "${DIM}     Every key is optional; KRISIS degrades gracefully without them.${R}"
fi

step "🧪 Verifying installation"
[ -x .venv/bin/krisis ] || die "krisis command missing. Re-run ./setup.sh"
ok "krisis"
./.venv/bin/krisis --help >/dev/null 2>&1 || die "krisis installed but won't run"
ok "krisis --help runs"

# Optional collector deps: each one missing only disables its own evidence source.
while IFS=: read -r mod label; do
    if ./.venv/bin/python -c "import $mod" >/dev/null 2>&1; then
        ok "$label"
    else
        warn "$label unavailable ($mod not importable) — that collector will be skipped"
    fi
done <<'MODS'
dns:DNS records
whois:WHOIS registration
ipwhois:IP / ASN ownership
OpenSSL:TLS certificates
MODS

if ./.venv/bin/pytest -q >/dev/null 2>&1; then
    ok "test suite passes"
else
    warn "test suite failed — run ./.venv/bin/pytest to see why"
fi

cat <<EOF

${GREEN}${B}  ✓ Setup complete!${R}

${B}  🔍 Start investigating:${R}

     ${CYAN}source .venv/bin/activate${R}
     ${CYAN}krisis investigate example.com${R}

${DIM}  Try also:  krisis investigate example.com --verbose
             krisis investigate message.txt --file
             krisis cases
             krisis outcome <case_id> confirmed_malicious${R}

${G3}  ─────────────◇  ${B}${G5}A N U B H A V   M O H A N D A S${R}${G3}  ◇─────────────${R}
${DIM}          🛡️  Use responsibly · authorized targets only${R}
${B}              💛  I   L O V E   Y O U U U U U  💛${R}

EOF
