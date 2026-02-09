#!/usr/bin/env bash
set -euo pipefail

# Northuldra - Lab-only pentest helper (recon/vuln scan orchestration)
# SAFE USE DISCLAIMER:
# This tool is for authorized security testing in your own lab.
# Do NOT run against networks or systems you do not own or have explicit permission to test.
# Misuse may violate laws and policies. You are responsible for lawful use.

APP_NAME="Northuldra"
VERSION="0.2.0"
DEFAULT_OUT_DIR="${HOME}/pentestlab"
CONFIG_DIR="${HOME}/.northuldra"
PRESETS_URL_FILE="${CONFIG_DIR}/presets_url.txt"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "${CONFIG_DIR}"

warn_exploits() {
  echo "[!] Exploits are DISABLED by default."
  echo "    To enable (if you add exploit presets), run: ${APP_NAME} --enable-exploits ..."
}

usage() {
  cat <<USAGE
${APP_NAME} ${VERSION}
Usage:
  ${APP_NAME}                       # interactive menu
  ${APP_NAME} --targets CIDR         # interactive with default targets
  ${APP_NAME} run --targets CIDR --presets "1,3"
  ${APP_NAME} update                 # update preset references (if URL set)
  ${APP_NAME} self-update            # update this script (git clone only)

Options:
  --targets CIDR      Target range (e.g., 10.0.0.0/24)
  --out DIR           Output directory (default: ${DEFAULT_OUT_DIR})
  --presets LIST      Comma-separated preset IDs (e.g., "1,3,5")
  --enable-exploits   (not used in this build) gated future feature
  -h, --help          Show help
USAGE
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

# Monthly rotation (changes on the 1st of each month)
MONTH_KEY="$(date +"%Y-%m")"
hash_mod() {
  local key="$1" mod="$2"
  python3 - <<'PY' "$key" "$mod"
import hashlib, sys
key = sys.argv[1]
mod = int(sys.argv[2])
print(int(hashlib.sha256(key.encode()).hexdigest(), 16) % mod)
PY
}
pick_from_pool() {
  local label="$1"; shift
  local -a pool=("$@")
  if [[ ${#pool[@]} -eq 0 ]]; then
    echo ""
    return
  fi
  local idx
  idx="$(hash_mod "${MONTH_KEY}:${label}" "${#pool[@]}")"
  echo "${pool[$idx]}"
}

# Rotation pools (edit to fit your lab)
WORDLIST_POOL=(
  "/usr/share/wordlists/dirb/common.txt"
  "/usr/share/wordlists/dirb/big.txt"
  "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
  "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
)
WEB_FINGERPRINT_POOL=(
  "whatweb"
  "httpx"
)
WEB_SCAN_POOL=(
  "nikto"
  "nmap-vuln"
)
DIR_ENUM_POOL=(
  "gobuster"
  "feroxbuster"
)

ROT_WORDLIST="$(pick_from_pool "wordlist" "${WORDLIST_POOL[@]}")"
ROT_WEB_FINGERPRINT_TOOL="$(pick_from_pool "webfp" "${WEB_FINGERPRINT_POOL[@]}")"
ROT_WEB_SCAN_TOOL="$(pick_from_pool "webscan" "${WEB_SCAN_POOL[@]}")"
ROT_DIR_ENUM_TOOL="$(pick_from_pool "direnum" "${DIR_ENUM_POOL[@]}")"

json_escape() {
  python3 - <<'PY' "$1"
import json, sys
print(json.dumps(sys.argv[1]))
PY
}

log_json() {
  local json_file="$1"
  local tool="$2"
  local cmd="$3"
  local out="$4"
  local status="$5"
  local ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  printf '{"time":%s,"tool":%s,"command":%s,"output":%s,"status":%s}\n' \
    "$(json_escape "$ts")" \
    "$(json_escape "$tool")" \
    "$(json_escape "$cmd")" \
    "$(json_escape "$out")" \
    "$(json_escape "$status")" >> "$json_file"
}

run_cmd() {
  local tool="$1"
  local cmd="$2"
  local out_dir="$3"
  local json_file="$4"

  if ! has_cmd "$tool"; then
    echo "[!] Skipping $tool (not installed)"
    log_json "$json_file" "$tool" "$cmd" "$out_dir" "skipped_missing"
    return 0
  fi

  echo "[*] Running: $cmd"
  local out_file="${out_dir}/${tool}_$(date +"%Y%m%d_%H%M%S").log"
  if bash -c "$cmd" >"$out_file" 2>&1; then
    log_json "$json_file" "$tool" "$cmd" "$out_file" "ok"
  else
    log_json "$json_file" "$tool" "$cmd" "$out_file" "error"
  fi
}

# Preset commands
preset_1() {
  local t="$1" out_dir="$2" json="$3"
  # Nmap stealth scan: SYN scan + service detection, safe timing
  run_cmd "nmap" "nmap -sS -sV -T3 -oN ${out_dir}/nmap_stealth.txt ${t}" "$out_dir" "$json"
}

preset_2() {
  local t="$1" out_dir="$2" json="$3"
  # Nmap vuln scripts (safe subset)
  run_cmd "nmap" "nmap -sV --script vuln -T3 -oN ${out_dir}/nmap_vuln.txt ${t}" "$out_dir" "$json"
}

preset_3() {
  local t="$1" out_dir="$2" json="$3"
  # Web tech fingerprinting (rotates monthly)
  case "$ROT_WEB_FINGERPRINT_TOOL" in
    whatweb)
      run_cmd "whatweb" "whatweb -a 1 ${t}" "$out_dir" "$json"
      ;;
    httpx)
      run_cmd "httpx" "httpx -silent -title -tech-detect -status-code -u http://${t}" "$out_dir" "$json"
      ;;
    *)
      run_cmd "whatweb" "whatweb -a 1 ${t}" "$out_dir" "$json"
      ;;
  esac
}

preset_4() {
  local t="$1" out_dir="$2" json="$3"
  # Web vuln scan (rotates monthly)
  case "$ROT_WEB_SCAN_TOOL" in
    nikto)
      run_cmd "nikto" "nikto -h ${t}" "$out_dir" "$json"
      ;;
    nmap-vuln)
      run_cmd "nmap" "nmap -sV --script vuln -T3 -oN ${out_dir}/nmap_vuln.txt ${t}" "$out_dir" "$json"
      ;;
    *)
      run_cmd "nikto" "nikto -h ${t}" "$out_dir" "$json"
      ;;
  esac
}

preset_5() {
  local t="$1" out_dir="$2" json="$3"
  # Directory brute-force (rotating tool + wordlist)
  local wl="${ROT_WORDLIST:-/usr/share/wordlists/dirb/common.txt}"
  case "$ROT_DIR_ENUM_TOOL" in
    gobuster)
      run_cmd "gobuster" "gobuster dir -u http://${t} -w ${wl} -q" "$out_dir" "$json"
      ;;
    feroxbuster)
      run_cmd "feroxbuster" "feroxbuster -u http://${t} -w ${wl} -q" "$out_dir" "$json"
      ;;
    *)
      run_cmd "gobuster" "gobuster dir -u http://${t} -w ${wl} -q" "$out_dir" "$json"
      ;;
  esac
}

preset_6() {
  local t="$1" out_dir="$2" json="$3"
  # SSL/TLS scan
  run_cmd "sslscan" "sslscan ${t}" "$out_dir" "$json"
}

preset_7() {
  local t="$1" out_dir="$2" json="$3"
  # SMB enumeration (if target runs SMB)
  run_cmd "enum4linux" "enum4linux -a ${t}" "$out_dir" "$json"
}

preset_8() {
  local t="$1" out_dir="$2" json="$3"
  # SNMP walk (if SNMP is enabled)
  run_cmd "snmpwalk" "snmpwalk -v2c -c public ${t}" "$out_dir" "$json"
}

run_presets() {
  local targets="$1"
  local out_dir="$2"
  local presets="$3"

  mkdir -p "$out_dir"
  local json_file="${out_dir}/run_$(date +"%Y%m%d_%H%M%S").jsonl"
  echo "[*] Output directory: $out_dir"
  echo "[*] JSON log: $json_file"

  IFS=',' read -r -a plist <<< "$presets"
  for p in "${plist[@]}"; do
    case "$p" in
      1) preset_1 "$targets" "$out_dir" "$json_file" ;;
      2) preset_2 "$targets" "$out_dir" "$json_file" ;;
      3) preset_3 "$targets" "$out_dir" "$json_file" ;;
      4) preset_4 "$targets" "$out_dir" "$json_file" ;;
      5) preset_5 "$targets" "$out_dir" "$json_file" ;;
      6) preset_6 "$targets" "$out_dir" "$json_file" ;;
      7) preset_7 "$targets" "$out_dir" "$json_file" ;;
      8) preset_8 "$targets" "$out_dir" "$json_file" ;;
      *) echo "[!] Unknown preset: $p" ;;
    esac
  done
}

menu() {
  local targets="${1:-}"
  local out_dir="${2:-$DEFAULT_OUT_DIR}"

  warn_exploits
  echo
  echo "Northuldra Presets"
  echo "1) Nmap stealth scan"
  echo "2) Nmap vuln scripts (safe subset)"
  echo "3) Web tech fingerprint (monthly: ${ROT_WEB_FINGERPRINT_TOOL})"
  echo "4) Web vuln scan (monthly: ${ROT_WEB_SCAN_TOOL})"
  echo "5) Directory scan (monthly: ${ROT_DIR_ENUM_TOOL}; wordlist: ${ROT_WORDLIST})"
  echo "6) SSLscan TLS check"
  echo "7) Enum4linux SMB enum"
  echo "8) SNMP walk (public)"
  echo
  echo "Enter 1 or 2 preset numbers separated by comma (e.g., 1,3)"
  read -r -p "Presets: " presets

  if [[ -z "$targets" ]]; then
    read -r -p "Targets (CIDR or IP): " targets
  fi

  if [[ -z "$presets" || -z "$targets" ]]; then
    echo "[!] Presets and targets are required."
    exit 1
  fi

  run_presets "$targets" "$out_dir" "$presets"
}

update_presets() {
  echo "[*] Updating preset references (optional feature)"
  if [[ ! -f "$PRESETS_URL_FILE" ]]; then
    echo "[!] No presets URL set."
    echo "    Create ${PRESETS_URL_FILE} and put the URL of your presets JSON there."
    exit 1
  fi
  local url
  url="$(cat "$PRESETS_URL_FILE")"
  if [[ -z "$url" ]]; then
    echo "[!] Presets URL file is empty."
    exit 1
  fi
  if ! has_cmd "curl"; then
    echo "[!] curl not installed."
    exit 1
  fi
  mkdir -p "$CONFIG_DIR"
  curl -fsSL "$url" -o "${CONFIG_DIR}/presets.json"
  echo "[*] Updated presets saved to ${CONFIG_DIR}/presets.json"
}

self_update() {
  echo "[*] Self-update (git clone only)"
  if [[ ! -d "${SCRIPT_DIR}/.git" ]]; then
    echo "[!] Not a git clone. Please re-download the latest script."
    exit 1
  fi
  if ! has_cmd "git"; then
    echo "[!] git not installed."
    exit 1
  fi
  git -C "${SCRIPT_DIR}" pull --ff-only
  echo "[*] Update complete."
}

main() {
  if [[ $# -eq 0 ]]; then
    menu
    exit 0
  fi

  local targets=""
  local out_dir="$DEFAULT_OUT_DIR"
  local presets=""
  local enable_exploits="false"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --targets) targets="$2"; shift 2 ;;
      --out) out_dir="$2"; shift 2 ;;
      --presets) presets="$2"; shift 2 ;;
      --enable-exploits) enable_exploits="true"; shift ;;
      run) shift ;;
      update) update_presets; exit 0 ;;
      self-update) self_update; exit 0 ;;
      -h|--help) usage; exit 0 ;;
      *) echo "[!] Unknown argument: $1"; usage; exit 1 ;;
    esac
  done

  warn_exploits
  if [[ "$enable_exploits" == "true" ]]; then
    echo "[!] Exploit presets are not implemented in this build."
  fi

  if [[ -z "$targets" ]]; then
    echo "[!] --targets is required for non-interactive run."
    exit 1
  fi
  if [[ -z "$presets" ]]; then
    echo "[!] --presets is required for non-interactive run."
    exit 1
  fi

  run_presets "$targets" "$out_dir" "$presets"
}

main "$@"
