#!/bin/sh
#
# ============================================================
# ProjectDiscovery Complete Installer (Alpine/Docker)
# Installs the most common ProjectDiscovery tools.
# ============================================================

set -e

OUT="/usr/local/bin/pd"
if [ -z "$GOBIN" ]; then
    GOBIN=$(go env GOBIN)
    if [ -z "$GOBIN" ] || [ "$GOBIN" = "off" ]; then
        GOPATH=$(go env GOPATH)
        GOBIN="${GOPATH:-/root/go}/bin"
    fi
fi

mkdir -p "$OUT"

echo "[*] Installing system packages..."

apk update

apk add --no-cache \
    bash \
    git \
    curl \
    wget \
    ca-certificates \
    build-base \
    nmap \
    chromium \
    libpcap-dev \
    bind-tools \
    jq \
    unzip

echo ""
echo "[*] Installing ProjectDiscovery tools..."

TOOLS="
github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
github.com/projectdiscovery/dnsx/cmd/dnsx@latest
github.com/projectdiscovery/httpx/cmd/httpx@latest
github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
github.com/projectdiscovery/katana/cmd/katana@latest
github.com/projectdiscovery/uncover/cmd/uncover@latest
github.com/projectdiscovery/tlsx/cmd/tlsx@latest
github.com/projectdiscovery/alterx/cmd/alterx@latest
github.com/projectdiscovery/asnmap/cmd/asnmap@latest
github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
github.com/projectdiscovery/notify/cmd/notify@latest
github.com/projectdiscovery/proxify/cmd/proxify@latest
github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
github.com/projectdiscovery/chaos-client/cmd/chaos@latest
github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest
"

for TOOL in $TOOLS; do
    NAME=$(basename "$TOOL")

    echo ""
    echo "======================================="
    echo "Installing $NAME..."
    echo "======================================="

    # Retry up to 3 times in case of transient network errors
    success=false
    for attempt in 1 2 3; do
        echo "Attempt $attempt to install $NAME..."
        if go install -v "${TOOL}@latest"; then
            success=true
            break
        fi
        echo "Attempt $attempt failed. Retrying in 5 seconds..."
        sleep 5
    done

    if [ -f "$GOBIN/$NAME" ]; then
        cp "$GOBIN/$NAME" "$OUT/$NAME"
        chmod +x "$OUT/$NAME"
        echo "✅ $NAME installed"
    else
        echo "❌ $NAME binary not found"
    fi
done

echo ""
echo "[*] Updating Nuclei templates..."

"$OUT/nuclei" -update-templates -silent || true

echo ""
echo "[*] Copying nmap..."

cp "$(which nmap)" "$OUT/nmap" || true

echo ""
echo "============================================================"
echo "Installed tools:"
echo "============================================================"

for BIN in "$OUT"/*; do
    NAME=$(basename "$BIN")

    printf "%-20s" "$NAME"

    case "$NAME" in
        gowitness)
            "$BIN" version 2>/dev/null | head -1 || true
            ;;
        *)
            "$BIN" -version 2>/dev/null | head -1 || \
            "$BIN" version 2>/dev/null | head -1 || \
            echo ""
            ;;
    esac
done

echo ""
echo "============================================================"
echo "Installation completed."
echo "Binaries:"
echo "  $OUT"
echo ""
echo "Example:"
echo "  $OUT/subfinder -d example.com -silent"
echo "  $OUT/httpx -silent -ip"
echo "============================================================"