#!/usr/bin/env bash
set -Eeuo pipefail

TOOLS_DIR="${TOOLS_DIR:-/usr/local/pd_tools}"
SRC_DIR="${TOOLS_DIR}/src"
VENV_DIR="${TOOLS_DIR}/venv"
RUBY_GEMS_DIR="${TOOLS_DIR}/ruby-gems"

# Reproducible top-level tool versions. Override a value through the installer
# container environment only after validating the corresponding CLI flags.
SUBFINDER_VERSION="${SUBFINDER_VERSION:-v2.14.0}"
DNSX_VERSION="${DNSX_VERSION:-v1.3.0}"
NAABU_VERSION="${NAABU_VERSION:-v2.6.1}"
HTTPX_VERSION="${HTTPX_VERSION:-v1.10.0}"
NUCLEI_VERSION="${NUCLEI_VERSION:-v3.11.0}"
KATANA_VERSION="${KATANA_VERSION:-v1.6.1}"
UNCOVER_VERSION="${UNCOVER_VERSION:-v1.2.1}"
GOWITNESS_VERSION="${GOWITNESS_VERSION:-3.1.1}"
WAYBACKURLS_REF="${WAYBACKURLS_REF:-8d27cf3e3031de01179e8ba9127e968eb01008e9}"
DIRSEARCH_REF="${DIRSEARCH_REF:-467f66b107f5316f6da85ceb4bcfcddbea447ae4}"
SUBLIST3R_REF="${SUBLIST3R_REF:-729d649ec5370730172bf6f5314aafd68c874124}"
SECRETFINDER_REF="${SECRETFINDER_REF:-d06119dedd9c1505137d1ec4792d5d5b65c7425d}"
PARAMSPIDER_REF="${PARAMSPIDER_REF:-c44bdaae54789b237028e309b603d1aa5ad52e5e}"
XSSTRIKE_REF="${XSSTRIKE_REF:-ab27955d367432f944d8f29897e09c15356e76f7}"
XSSVIBES_REF="${XSSVIBES_REF:-011594759e47e6ece40923fba0fa664db4965212}"
NIKTO_REF="${NIKTO_REF:-d5067406bc0902f8174cb5f8d595f637951974ce}"
LAZYRECON_REF="${LAZYRECON_REF:-5a7a3a0b8dbedd3273886ae3cf3e4035403aa4d3}"
DROOPESCAN_VERSION="${DROOPESCAN_VERSION:-1.45.1}"
WAPPALYZER_VERSION="${WAPPALYZER_VERSION:-2.0.2}"
WPSCAN_VERSION="${WPSCAN_VERSION:-4.1.0}"
PIP_VERSION="${PIP_VERSION:-26.2}"
SETUPTOOLS_VERSION="${SETUPTOOLS_VERSION:-83.0.0}"
WHEEL_VERSION="${WHEEL_VERSION:-0.47.0}"

mkdir -p "${TOOLS_DIR}" "${SRC_DIR}" "${RUBY_GEMS_DIR}" "${TOOLS_DIR}/wpscan-cache"

log() {
  printf '[pd-installer] %s\n' "$*"
}

release_asset_url() {
  local repo="$1"
  local tag="$2"
  local regex="$3"
  local api_url="https://api.github.com/repos/${repo}/releases/tags/${tag}"
  local curl_args=(
    -fsSL
    -H "Accept: application/vnd.github+json"
    -H "X-GitHub-Api-Version: 2022-11-28"
  )
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    curl_args+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  fi
  curl "${curl_args[@]}" "${api_url}" \
    | jq -r --arg regex "${regex}" \
      '.assets[] | select(.name | test($regex; "i")) | .browser_download_url' \
    | head -n 1
}

install_release_binary() {
  local repo="$1"
  local binary="$2"
  local tag="$3"
  local regex="$4"
  local url archive work found

  url="$(release_asset_url "${repo}" "${tag}" "${regex}")"
  if [[ -z "${url}" || "${url}" == "null" ]]; then
    log "No compatible release asset found for ${binary} (${repo} ${tag})"
    return 1
  fi

  archive="/tmp/${binary}-release"
  work="/tmp/${binary}-extract"
  rm -rf "${archive}" "${work}"
  mkdir -p "${work}"
  log "Downloading ${binary}"
  curl -fL "${url}" -o "${archive}"

  case "${url}" in
    *.zip)
      unzip -oq "${archive}" -d "${work}"
      ;;
    *.tar.gz|*.tgz)
      tar -xzf "${archive}" -C "${work}"
      ;;
    *.tar.xz)
      tar -xJf "${archive}" -C "${work}"
      ;;
    *)
      cp "${archive}" "${TOOLS_DIR}/${binary}"
      chmod +x "${TOOLS_DIR}/${binary}"
      return 0
      ;;
  esac

  found="$(find "${work}" -type f -name "${binary}" -perm /111 2>/dev/null | head -n 1 || true)"
  if [[ -z "${found}" ]]; then
    found="$(find "${work}" -type f -name "${binary}" 2>/dev/null | head -n 1 || true)"
  fi
  if [[ -z "${found}" ]]; then
    log "Downloaded ${binary}, but the executable was not found in the release archive"
    return 1
  fi
  cp "${found}" "${TOOLS_DIR}/${binary}"
  chmod +x "${TOOLS_DIR}/${binary}"
}

fresh_clone() {
  local repo_url="$1"
  local destination="$2"
  local ref="$3"
  rm -rf "${destination}"
  log "Cloning $(basename "${destination}") at ${ref}"
  git init -q "${destination}"
  git -C "${destination}" remote add origin "${repo_url}"
  git -C "${destination}" fetch --depth 1 origin "${ref}"
  git -C "${destination}" -c advice.detachedHead=false checkout --detach FETCH_HEAD
}

write_wrapper() {
  local name="$1"
  shift
  {
    printf '#!/usr/bin/env bash\n'
    printf 'set -Eeuo pipefail\n'
    printf '%s\n' "$*"
  } > "${TOOLS_DIR}/${name}"
  chmod +x "${TOOLS_DIR}/${name}"
}

smoke_test_tool() {
  local name="$1"
  local accepted_codes="$2"
  shift 2
  local output="/tmp/${name}-smoke-test.log"
  local code
  log "Smoke-testing ${name}"
  if timeout 30 "$@" >"${output}" 2>&1; then
    code=0
  else
    code=$?
  fi
  if [[ " ${accepted_codes} " != *" ${code} "* ]]; then
    log "${name} smoke test failed with exit code ${code}"
    tail -n 20 "${output}" >&2 || true
    return 1
  fi
}

# Pinned ProjectDiscovery and screenshot binaries.
install_release_binary "projectdiscovery/subfinder" "subfinder" "${SUBFINDER_VERSION}" "subfinder_${SUBFINDER_VERSION#v}_linux_amd64\\.zip$"
install_release_binary "projectdiscovery/dnsx" "dnsx" "${DNSX_VERSION}" "dnsx_${DNSX_VERSION#v}_linux_amd64\\.zip$"
install_release_binary "projectdiscovery/naabu" "naabu" "${NAABU_VERSION}" "naabu_${NAABU_VERSION#v}_linux_amd64\\.zip$"
install_release_binary "projectdiscovery/httpx" "httpx" "${HTTPX_VERSION}" "httpx_${HTTPX_VERSION#v}_linux_amd64\\.zip$"
install_release_binary "projectdiscovery/nuclei" "nuclei" "${NUCLEI_VERSION}" "nuclei_${NUCLEI_VERSION#v}_linux_amd64\\.zip$"
install_release_binary "projectdiscovery/katana" "katana" "${KATANA_VERSION}" "katana_${KATANA_VERSION#v}_linux_amd64\\.zip$"
install_release_binary "projectdiscovery/uncover" "uncover" "${UNCOVER_VERSION}" "uncover_${UNCOVER_VERSION#v}_linux_amd64\\.zip$"
install_release_binary "sensepost/gowitness" "gowitness" "${GOWITNESS_VERSION}" "gowitness-${GOWITNESS_VERSION#v}-linux-amd64$"

# Historical URL collector.
log "Installing waybackurls"
GOBIN="${TOOLS_DIR}" go install "github.com/tomnomnom/waybackurls@${WAYBACKURLS_REF}"

# Shared Python environment. Recreate it on every installer run so console
# scripts cannot retain stale shebangs from an older volume mount path (for
# example /pd_tools instead of /usr/local/pd_tools). Only the venv is cleared;
# downloaded binaries, source checkouts, templates, and caches are preserved.
log "Rebuilding the shared Python environment"
python -m venv --clear "${VENV_DIR}"
"${VENV_DIR}/bin/pip" install --upgrade \
  "pip==${PIP_VERSION}" \
  "setuptools==${SETUPTOOLS_VERSION}" \
  "wheel==${WHEEL_VERSION}"

log "Installing dirsearch"
"${VENV_DIR}/bin/pip" install --upgrade \
  "git+https://github.com/maurosoria/dirsearch.git@${DIRSEARCH_REF}"
write_wrapper "dirsearch" 'exec /usr/local/pd_tools/venv/bin/dirsearch "$@"'

fresh_clone "https://github.com/aboul3la/Sublist3r.git" "${SRC_DIR}/Sublist3r" "${SUBLIST3R_REF}"
"${VENV_DIR}/bin/pip" install -r "${SRC_DIR}/Sublist3r/requirements.txt" || true
write_wrapper "sublist3r" 'exec /usr/local/pd_tools/venv/bin/python /usr/local/pd_tools/src/Sublist3r/sublist3r.py "$@"'

fresh_clone "https://github.com/m4ll0k/SecretFinder.git" "${SRC_DIR}/SecretFinder" "${SECRETFINDER_REF}"
if [[ -f "${SRC_DIR}/SecretFinder/requirements.txt" ]]; then
  "${VENV_DIR}/bin/pip" install -r "${SRC_DIR}/SecretFinder/requirements.txt"
fi
write_wrapper "secretfinder" 'exec /usr/local/pd_tools/venv/bin/python /usr/local/pd_tools/src/SecretFinder/SecretFinder.py "$@"'

fresh_clone "https://github.com/devanshbatham/ParamSpider.git" "${SRC_DIR}/ParamSpider" "${PARAMSPIDER_REF}"
"${VENV_DIR}/bin/pip" install "${SRC_DIR}/ParamSpider"
write_wrapper "paramspider" 'exec /usr/local/pd_tools/venv/bin/paramspider "$@"'

log "Installing droopescan"
"${VENV_DIR}/bin/pip" install --upgrade "droopescan==${DROOPESCAN_VERSION}"
# droopescan currently resolves an older Cement release which still imports
# reload from Python's removed `imp` module. Keep the upstream scanner usable
# on the Python 3.12 runtime shared by installer and backend.
CEMENT_PACKAGE="$(${VENV_DIR}/bin/python - <<'PY'
import pathlib
import cement
print(pathlib.Path(cement.__file__).parent)
PY
)"
if [[ -d "${CEMENT_PACKAGE}" ]]; then
  find "${CEMENT_PACKAGE}" -type f -name '*.py' -exec \
    sed -i 's/from imp import reload/from importlib import reload/' {} +
  CEMENT_PLUGIN="${CEMENT_PACKAGE}/ext/ext_plugin.py"
  if [[ -f "${CEMENT_PLUGIN}" ]]; then
    sed -i 's/^import imp$/import importlib.util/' "${CEMENT_PLUGIN}"
    sed -i \
      's/f, path, desc = imp.find_module(plugin_name, \[plugin_dir\])/path = os.path.join(plugin_dir, plugin_name + ".py")/' \
      "${CEMENT_PLUGIN}"
    LOAD_LINE="$(grep -n 'mod = imp.load_module' "${CEMENT_PLUGIN}" | cut -d: -f1 | head -n 1)"
    if [[ -n "${LOAD_LINE}" ]]; then
      sed -i "${LOAD_LINE}c\\        spec = importlib.util.spec_from_file_location(plugin_name, path)" "${CEMENT_PLUGIN}"
      sed -i "$((LOAD_LINE + 1))i\\        mod = importlib.util.module_from_spec(spec)" "${CEMENT_PLUGIN}"
      sed -i "$((LOAD_LINE + 2))i\\        spec.loader.exec_module(mod)" "${CEMENT_PLUGIN}"
    fi
  fi
fi
write_wrapper "droopescan" 'exec /usr/local/pd_tools/venv/bin/droopescan "$@"'

fresh_clone "https://github.com/s0md3v/XSStrike.git" "${SRC_DIR}/XSStrike" "${XSSTRIKE_REF}"
"${VENV_DIR}/bin/pip" install -r "${SRC_DIR}/XSStrike/requirements.txt"
write_wrapper "xsstrike" 'exec /usr/local/pd_tools/venv/bin/python /usr/local/pd_tools/src/XSStrike/xsstrike.py "$@"'

# ---------------------------------------------------------
# XSS Vibes
# ---------------------------------------------------------

log "Installing xss_vibes"

fresh_clone \
  "https://github.com/faiyazahmad07/xss_vibes.git" \
  "${SRC_DIR}/xss_vibes" \
  "${XSSVIBES_REF}"

if [[ -f "${SRC_DIR}/xss_vibes/requirements" ]]; then
  "${VENV_DIR}/bin/pip" install \
    -r "${SRC_DIR}/xss_vibes/requirements"
fi

write_wrapper "xssvibes" \
  'cd /usr/local/pd_tools/src/xss_vibes; exec /usr/local/pd_tools/venv/bin/python ./main.py "$@"'


# ---------------------------------------------------------
# Nikto
# ---------------------------------------------------------

log "Installing Nikto"

fresh_clone \
  "https://github.com/sullo/nikto.git" \
  "${SRC_DIR}/nikto" \
  "${NIKTO_REF}"

write_wrapper "nikto" \
  'exec perl /usr/local/pd_tools/src/nikto/program/nikto.pl "$@"'
# Maintained Wappalyzer-compatible CLI. The standard pipeline uses fast mode;
# HTTPx technology detection remains enabled as an additional source.
log "Installing Wappalyzer-compatible CLI"
"${VENV_DIR}/bin/pip" install --upgrade "wappalyzer==${WAPPALYZER_VERSION}"
write_wrapper "wappalyzer" 'exec /usr/local/pd_tools/venv/bin/wappalyzer "$@"'

# DIRB is installed from Debian in this installer image and exposed through the
# shared volume so the backend can invoke the same path as all other tools.
write_wrapper "dirb" 'exec /usr/bin/dirb "$@"'

# DirBuster legacy headless CLI. It is installed, but disabled by default.
DIRBUSTER_ARCHIVE="${SRC_DIR}/DirBuster-1.0-RC1.tar.bz2"
DIRBUSTER_DIR="${SRC_DIR}/DirBuster"
log "Installing DirBuster"
rm -rf "${DIRBUSTER_DIR}"
mkdir -p "${DIRBUSTER_DIR}"
if curl -fL \
  'https://sourceforge.net/projects/dirbuster/files/DirBuster%20%28jar%20%2B%20lists%29/1.0-RC1/DirBuster-1.0-RC1.tar.bz2/download' \
  -o "${DIRBUSTER_ARCHIVE}"; then
  tar -xjf "${DIRBUSTER_ARCHIVE}" -C "${DIRBUSTER_DIR}" --strip-components=1
  DIRBUSTER_JAR="$(find "${DIRBUSTER_DIR}" -type f -name 'DirBuster*.jar' | head -n 1 || true)"
  if [[ -n "${DIRBUSTER_JAR}" ]]; then
    ln -sf "${DIRBUSTER_JAR}" "${DIRBUSTER_DIR}/DirBuster.jar"
    write_wrapper "dirbuster" 'exec java -jar /usr/local/pd_tools/src/DirBuster/DirBuster.jar "$@"'
  else
    log "DirBuster archive did not contain a JAR; legacy scanner will remain unavailable"
  fi
else
  log "DirBuster download failed; continuing because it is disabled by default"
fi

# WPScan is installed into the persistent shared Ruby gem directory.
log "Installing WPScan"
GEM_HOME="${RUBY_GEMS_DIR}" GEM_PATH="${RUBY_GEMS_DIR}" \
  gem install wpscan -v "${WPSCAN_VERSION}" --no-document
GEM_HOME="${RUBY_GEMS_DIR}" GEM_PATH="${RUBY_GEMS_DIR}" \
XDG_CACHE_HOME="${TOOLS_DIR}/wpscan-cache" \
  "${RUBY_GEMS_DIR}/bin/wpscan" --update || true
write_wrapper "wpscan" 'export GEM_HOME=/usr/local/pd_tools/ruby-gems GEM_PATH=/usr/local/pd_tools/ruby-gems XDG_CACHE_HOME=/usr/local/pd_tools/wpscan-cache; exec /usr/local/pd_tools/ruby-gems/bin/wpscan "$@"'

# LazyRecon is a meta-wrapper around scanners already orchestrated by the ASM.
# It is available only as an opt-in compatibility stage.
fresh_clone "https://github.com/capt-meelo/LazyRecon.git" "${SRC_DIR}/LazyRecon" "${LAZYRECON_REF}"
chmod +x "${SRC_DIR}/LazyRecon/LazyRecon.sh" || true
write_wrapper "lazyrecon" 'cd /usr/local/pd_tools/src/LazyRecon; exec bash ./LazyRecon.sh "$@"'

smoke_test_tool "subfinder" "0" "${TOOLS_DIR}/subfinder" -version
smoke_test_tool "dnsx" "0" "${TOOLS_DIR}/dnsx" -version
smoke_test_tool "naabu" "0" "${TOOLS_DIR}/naabu" -version
smoke_test_tool "httpx" "0" "${TOOLS_DIR}/httpx" -version
smoke_test_tool "nuclei" "0" "${TOOLS_DIR}/nuclei" -version
smoke_test_tool "katana" "0" "${TOOLS_DIR}/katana" -version
smoke_test_tool "uncover" "0" "${TOOLS_DIR}/uncover" -version
smoke_test_tool "gowitness" "0" "${TOOLS_DIR}/gowitness" version
smoke_test_tool "waybackurls" "0 2" "${TOOLS_DIR}/waybackurls" -h
smoke_test_tool "dirsearch" "0" "${TOOLS_DIR}/dirsearch" --help
smoke_test_tool "sublist3r" "0" "${TOOLS_DIR}/sublist3r" -h
smoke_test_tool "secretfinder" "0" "${TOOLS_DIR}/secretfinder" -h
smoke_test_tool "paramspider" "0" "${TOOLS_DIR}/paramspider" --help
smoke_test_tool "droopescan" "0" "${TOOLS_DIR}/droopescan" --help
smoke_test_tool "xsstrike" "0" "${TOOLS_DIR}/xsstrike" --help
smoke_test_tool "xssvibes" "0" "${TOOLS_DIR}/xssvibes" -h
smoke_test_tool "nikto" "0" "${TOOLS_DIR}/nikto" -Version
smoke_test_tool "wappalyzer" "0" "${TOOLS_DIR}/wappalyzer" --help
smoke_test_tool "wpscan" "0" "${TOOLS_DIR}/wpscan" --version

cat >"${TOOLS_DIR}/.asm-tool-versions" <<EOF
subfinder=${SUBFINDER_VERSION}
dnsx=${DNSX_VERSION}
naabu=${NAABU_VERSION}
httpx=${HTTPX_VERSION}
nuclei=${NUCLEI_VERSION}
katana=${KATANA_VERSION}
uncover=${UNCOVER_VERSION}
gowitness=${GOWITNESS_VERSION}
waybackurls=${WAYBACKURLS_REF}
dirsearch=${DIRSEARCH_REF}
sublist3r=${SUBLIST3R_REF}
secretfinder=${SECRETFINDER_REF}
paramspider=${PARAMSPIDER_REF}
droopescan=${DROOPESCAN_VERSION}
xsstrike=${XSSTRIKE_REF}
xssvibes=${XSSVIBES_REF}
nikto=${NIKTO_REF}
wappalyzer=${WAPPALYZER_VERSION}
wpscan=${WPSCAN_VERSION}
pip=${PIP_VERSION}
setuptools=${SETUPTOOLS_VERSION}
wheel=${WHEEL_VERSION}
lazyrecon=${LAZYRECON_REF}
EOF

rm -rf /tmp/*-release /tmp/*-extract /tmp/*.zip
chmod -R a+rX "${TOOLS_DIR}"
chmod -R a+rwX "${TOOLS_DIR}/wpscan-cache"
log "All supported reconnaissance tools installed successfully"
