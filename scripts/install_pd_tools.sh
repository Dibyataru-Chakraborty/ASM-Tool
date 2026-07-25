#!/bin/sh
# ═══════════════════════════════════════════════════════════════════
#  ProjectDiscovery Tools Installer
#  Docs: https://docs.projectdiscovery.io/opensource
#  Installs: subfinder, dnsx, naabu, httpx, nuclei, gowitness, nmap
# ═══════════════════════════════════════════════════════════════════

set -e

OUT="/usr/local/bin/pd"
mkdir -p "$OUT"

apk add --no-cache git curl nmap chromium

echo "[*] Installing Go tools from ProjectDiscovery..."

# ── subfinder — Subdomain discovery ─────────────────────────────
echo "[1/6] Installing subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
cp /root/go/bin/subfinder "$OUT/subfinder"
echo "    ✅ subfinder installed"

# ── dnsx — DNS resolution ────────────────────────────────────────
echo "[2/6] Installing dnsx..."
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
cp /root/go/bin/dnsx "$OUT/dnsx"
echo "    ✅ dnsx installed"

# ── naabu — Port scanning ────────────────────────────────────────
echo "[3/6] Installing naabu..."
apk add --no-cache libpcap-dev
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
cp /root/go/bin/naabu "$OUT/naabu"
echo "    ✅ naabu installed"

# ── httpx — HTTP probing ─────────────────────────────────────────
echo "[4/6] Installing httpx..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
cp /root/go/bin/httpx "$OUT/httpx"
echo "    ✅ httpx installed"

# ── nuclei — Vulnerability scanning ─────────────────────────────
echo "[5/6] Installing nuclei..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
cp /root/go/bin/nuclei "$OUT/nuclei"
# Pull latest templates
"$OUT/nuclei" -update-templates -silent || true
echo "    ✅ nuclei installed"

# ── gowitness — Screenshots ──────────────────────────────────────
echo "[6/6] Installing gowitness..."
go install -v github.com/sensepost/gowitness@latest
cp /root/go/bin/gowitness "$OUT/gowitness"
echo "    ✅ gowitness installed"

# ── nmap — copied from apk ───────────────────────────────────────
cp "$(which nmap)" "$OUT/nmap" 2>/dev/null || true
echo "    ✅ nmap available"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo " All ProjectDiscovery tools installed to $OUT"
echo "  subfinder  $(\"$OUT/subfinder\" -version 2>&1 | head -1)"
echo "  dnsx       $(\"$OUT/dnsx\" -version 2>&1 | head -1)"
echo "  naabu      $(\"$OUT/naabu\" -version 2>&1 | head -1)"
echo "  httpx      $(\"$OUT/httpx\" -version 2>&1 | head -1)"
echo "  nuclei     $(\"$OUT/nuclei\" -version 2>&1 | head -1)"
echo "  gowitness  $(\"$OUT/gowitness\" version 2>&1 | head -1)"
echo "═══════════════════════════════════════════════════════════"
