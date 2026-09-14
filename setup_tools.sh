#!/bin/bash
# Installs the core binaries ASRA's tool registry expects on PATH: nmap, nuclei, msfconsole
# (Metasploit), sqlmap, nikto, interactsh-client, whatweb, wpscan, ffuf, subfinder, hydra, plus the
# Reverse Engineering mode's own toolset: radare2 (+ r2ghidra, radiff2 -- both bundled with it),
# gdb, strace (behavioral/syscall triage), wine (runs a Windows PE target directly for dynamic
# analysis -- driven via custom_re_script, no dedicated ToolSpec), heimdall (binaries/contracts),
# upx (packed-binary unpacking), osv-scanner +
# trufflehog (source-repo SCA/secrets), apktool + jadx (Android APK decompilation), binwalk
# (firmware), tshark (packet capture/analysis -- dumpcap granted cap_net_raw/cap_net_admin so live
# capture never needs root). Frida (dynamic instrumentation), pwntools (exploit-primitive scripting)
# and scapy (packet crafting/parsing for custom_re_script) install via requirements.txt instead --
# all three are pip packages, not system binaries.
# Health-checking in agent/tools/runner.py is just shutil.which — so "installed" here means exactly
# "installed", nothing project-specific needed after this runs. Also makes sure the wordlists
# Metasploit brute-force modules expect (USER_FILE/PASS_FILE) are reachable at the Kali-convention
# path the exploit-phase model assumes, plus an opt-in step for a bigger rockyou.txt/SecLists set.
#
# Safe to re-run: every install_* function checks whether its binary already exists before
# touching anything, so running this again on an already-provisioned machine is just a status
# report, not a reinstall.
#
# Works on any Debian/Ubuntu (apt), Fedora/RHEL (dnf), or Arch (pacman) based distro, inside
# WSL2 or on native Linux — detects the package manager instead of assuming one, same reasoning
# README already applies to the WSL2 distro choice itself. Not for macOS, with one deliberate
# exception: install_radare2/install_gdb each have their own Homebrew branch (see their own
# comments for why that's scoped to just those two, not the whole script) — every other tool here
# still follows README's separate manual Homebrew list on macOS.
set -uo pipefail

GREEN="$(tput setaf 2 2>/dev/null || true)"
YELLOW="$(tput setaf 3 2>/dev/null || true)"
RED="$(tput setaf 1 2>/dev/null || true)"
BOLD="$(tput bold 2>/dev/null || true)"
RESET="$(tput sgr0 2>/dev/null || true)"

log()  { printf '%s\n' "$*"; }
ok()   { printf '%s[OK]%s   %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '%s[WARN]%s %s\n' "$YELLOW" "$RESET" "$*"; }
fail() { printf '%s[FAIL]%s %s\n' "$RED" "$RESET" "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }

# GitHub's release-asset redirects (github.com -> release-assets.githubusercontent.com) have been
# observed to blip with a transient 000/404 on an otherwise-good connection -- confirmed live, a
# same request retried a few seconds later succeeded every time. Applied to every curl call that
# hits the network (both the GitHub API version lookups and the actual asset downloads), not just
# one tool's, since none of them are any less exposed to the same blip.
CURL_RETRY_OPTS="--retry 3 --retry-delay 2 --retry-connrefused"

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
elif have sudo; then
    SUDO="sudo"
else
    fail "Not root and no sudo on PATH — re-run this script as root, or install sudo first."
    exit 1
fi

# This script's own directory == the repo root -- used to reach ASRA's ./venv (for the qiling pip
# install below) whether run from the Tools-page Install button (cwd may differ) or by hand.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# --- package manager detection ---------------------------------------------------------------
if have apt-get; then
    PKG_MANAGER="apt"
elif have dnf; then
    PKG_MANAGER="dnf"
elif have pacman; then
    PKG_MANAGER="pacman"
else
    warn "No supported package manager found (apt-get/dnf/pacman) — package-based installs below will be skipped; GitHub-release/git-clone based ones (nuclei, and the sqlmap/nikto fallbacks) will still work."
    PKG_MANAGER=""
fi

_pkg_index_updated=0
pkg_update_once() {
    [ "$_pkg_index_updated" -eq 1 ] && return 0
    case "$PKG_MANAGER" in
        apt)    $SUDO apt-get update -y ;;
        pacman) $SUDO pacman -Sy --noconfirm ;;
        *)      : ;; # dnf refreshes its own metadata per-install; nothing to do up front
    esac
    _pkg_index_updated=1
}

pkg_install() {
    # $@ = package name(s) for the *current* PKG_MANAGER — callers below pass whatever that
    # distro actually calls the package, not a single hardcoded name.
    [ -z "$PKG_MANAGER" ] && return 1
    pkg_update_once
    case "$PKG_MANAGER" in
        apt)    $SUDO apt-get install -y "$@" ;;
        dnf)    $SUDO dnf install -y "$@" ;;
        pacman) $SUDO pacman -S --noconfirm --needed "$@" ;;
    esac
}

# --- base dependencies (used by the install steps below, not part of the 5-tool arsenal) ------
for base_pkg in curl git unzip; do
    have "$base_pkg" || pkg_install "$base_pkg" || warn "Could not install base dependency '$base_pkg' — later steps needing it may fail."
done

# --- Python venv/pip (not part of the arsenal either, but ./run.sh needs it to even start) ----
python_venv_ready() { have python3 && have pip3 && python3 -c "import venv" >/dev/null 2>&1; }

install_python_prereqs() {
    python_venv_ready && { ok "python3 venv/pip already available"; return 0; }
    log "Installing Python venv/pip (needed by ./run.sh, not by any scan tool)..."
    case "$PKG_MANAGER" in
        # Debian/Ubuntu splits venv out of the base python3 package; Fedora and Arch don't.
        apt)    pkg_install python3-pip python3-venv ;;
        dnf)    pkg_install python3-pip ;;
        pacman) pkg_install python-pip ;;
        *)      warn "No supported package manager detected — make sure 'python3 -m venv' and pip work before running ./run.sh." ;;
    esac
}
install_python_prereqs

# --- dnsutils (dig/nslookup/host) ----------------------------------------------------------------
# Not one of ASRA's own registered tools (nothing in agent/tools/builders/ shells out to these) --
# this is here purely because custom_exploit_run's own model-written Python scripts routinely reach
# for subprocess.run(['dig', ...])/['nslookup', ...] as the obvious way to do a DNS lookup, and a
# bare WSL2/Debian base image doesn't ship any of the three. Real, confirmed incident: a real
# session's model wrote three separate custom_exploit_run scripts in a row (dig, then nslookup, then
# a dnspython import) that each failed with FileNotFoundError before it finally fell back to a raw
# DNS-over-HTTPS request that actually worked -- two full wasted tool-call round-trips discovering
# by trial and error what installing this package once avoids entirely. Python's own socket module
# already covers plain A/AAAA lookups without any of this, but MX/TXT/NS/SOA records need a real
# resolver a script can shell out to.
install_dnsutils() {
    have dig && { ok "dnsutils (dig/nslookup/host) already installed ($(command -v dig))"; return 0; }
    log "Installing dnsutils (dig/nslookup/host — custom_exploit_run scripts routinely shell out to these for MX/TXT/NS/SOA lookups)..."
    case "$PKG_MANAGER" in
        apt)    pkg_install dnsutils ;;
        dnf)    pkg_install bind-utils ;;
        pacman) pkg_install bind-tools ;;
        *)      warn "No supported package manager detected — install dig/nslookup/host manually, or expect custom_exploit_run's own DNS scripts to fall back to a pure-Python resolver (dnspython) or DNS-over-HTTPS instead."; return 1 ;;
    esac
}

# --- nmap ---------------------------------------------------------------------------------------
install_nmap() {
    have nmap && { ok "nmap already installed ($(command -v nmap))"; return 0; }
    log "Installing nmap..."
    pkg_install nmap || fail "Could not install nmap via $PKG_MANAGER."
}

# --- sqlmap -------------------------------------------------------------------------------------
install_sqlmap() {
    have sqlmap && { ok "sqlmap already installed ($(command -v sqlmap))"; return 0; }
    log "Installing sqlmap..."
    if pkg_install sqlmap; then
        return 0
    fi
    # Not every distro repo carries sqlmap (Arch does, some minimal repos don't) — the upstream
    # repo is the same source the package itself is built from, so this is not a lesser install.
    warn "sqlmap not available via $PKG_MANAGER — cloning the upstream repo instead."
    if [ ! -f /opt/sqlmap/sqlmap.py ] && ! $SUDO git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap; then
        fail "Could not clone sqlmap from GitHub (no network access?) — install it manually."
        return 1
    fi
    $SUDO tee /usr/local/bin/sqlmap >/dev/null <<'WRAPPER'
#!/bin/sh
exec python3 /opt/sqlmap/sqlmap.py "$@"
WRAPPER
    $SUDO chmod +x /usr/local/bin/sqlmap
}

# --- nikto --------------------------------------------------------------------------------------
install_bubblewrap() {
    have bwrap && { ok "bubblewrap already installed ($(command -v bwrap))"; return 0; }
    log "Installing bubblewrap (process/filesystem isolation for custom_exploit_run's own model-written scripts)..."
    if ! pkg_install bubblewrap; then
        warn "bubblewrap not available via $PKG_MANAGER — custom_exploit_run will run unsandboxed on this system (see agent/tools/sandbox.py's own graceful fallback). Install manually if your distro packages it under a different name."
        return 1
    fi
}

install_nikto() {
    have nikto && { ok "nikto already installed ($(command -v nikto))"; return 0; }
    log "Installing nikto..."
    if pkg_install nikto; then
        return 0
    fi
    warn "nikto not available via $PKG_MANAGER — cloning the upstream repo instead."
    if [ ! -f /opt/nikto/program/nikto.pl ] && ! $SUDO git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto; then
        fail "Could not clone nikto from GitHub (no network access?) — install it manually."
        return 1
    fi
    $SUDO tee /usr/local/bin/nikto >/dev/null <<'WRAPPER'
#!/bin/sh
exec perl /opt/nikto/program/nikto.pl "$@"
WRAPPER
    $SUDO chmod +x /usr/local/bin/nikto
    have perl || warn "nikto needs perl to actually run — install it via your package manager (e.g. 'perl' or 'perl-base')."
}

# --- hydra ----------------------------------------------------------------------------------------
install_hydra() {
    have hydra && { ok "hydra already installed ($(command -v hydra))"; return 0; }
    log "Installing hydra (credential brute-forcing — agent/tools/builders/hydra.py)..."
    if pkg_install hydra; then
        return 0
    fi
    # Unlike nikto/whatweb/sqlmap (pure Perl/Ruby/Python, no compilation needed), Hydra is C/C++
    # with a real ./configure && make dependency chain (OpenSSL, libssh, and others depending on
    # which protocol modules get built) that varies enough across distros that an automated
    # from-source build here would be a real risk of silently producing a broken/partial binary
    # this script has no way to verify -- honest failure with a clear next step instead, same
    # discipline as never shipping an unverified fallback.
    warn "hydra has no $PKG_MANAGER package available — install it manually from https://github.com/vanhauser-thc/thc-hydra (needs a real ./configure && make build, not something this script can safely automate)."
    return 1
}

# --- whatweb --------------------------------------------------------------------------------------
install_whatweb() {
    have whatweb && { ok "whatweb already installed ($(command -v whatweb))"; return 0; }
    log "Installing whatweb..."
    if pkg_install whatweb; then
        return 0
    fi
    warn "whatweb not available via $PKG_MANAGER — cloning the upstream repo instead."
    if [ ! -f /opt/whatweb/whatweb ] && ! $SUDO git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb; then
        fail "Could not clone whatweb from GitHub (no network access?) — install it manually."
        return 1
    fi
    $SUDO tee /usr/local/bin/whatweb >/dev/null <<'WRAPPER'
#!/bin/sh
exec ruby /opt/whatweb/whatweb "$@"
WRAPPER
    $SUDO chmod +x /usr/local/bin/whatweb
    have ruby || warn "whatweb needs ruby to actually run — install it via your package manager (e.g. 'ruby')."
}

# --- wpscan ---------------------------------------------------------------------------------------
install_wpscan() {
    have wpscan && { ok "wpscan already installed ($(command -v wpscan))"; return 0; }
    log "Installing wpscan..."
    if pkg_install wpscan; then
        return 0
    fi
    # Not every distro repo carries wpscan (Kali does; plain Debian/Ubuntu don't) — the official
    # install path is the RubyGem, which needs a real Ruby + native-extension toolchain first.
    warn "wpscan not available via $PKG_MANAGER — installing the official RubyGem instead."
    # gem install needs a Ruby interpreter *and* native-extension build headers (mkmf) to build
    # wpscan's C-extension dependencies (yajl-ruby, etc). A bare 'ruby'/'gem' on PATH pulled in as
    # someone else's dependency (e.g. whatweb pulling in plain ruby3.2) satisfies a binary-presence
    # check but has no headers — so gate on the dev toolchain unconditionally, not on ruby/gem
    # already being present.
    case "$PKG_MANAGER" in
        apt)    pkg_install ruby-full build-essential ;;
        dnf)    pkg_install ruby ruby-devel gcc make redhat-rpm-config ;;
        pacman) pkg_install ruby base-devel ;;
        *)      warn "No supported package manager detected — install Ruby (with a working gem/native-extension toolchain) manually before wpscan can be gem-installed." ;;
    esac
    if ! { have ruby && have gem; }; then
        fail "Ruby still not available — cannot gem-install wpscan."
        return 1
    fi
    $SUDO gem install wpscan || fail "gem install wpscan failed — check the output above."
}

# --- nuclei -------------------------------------------------------------------------------------
install_nuclei() {
    have nuclei && { ok "nuclei already installed ($(command -v nuclei))"; return 0; }
    log "Installing nuclei (no distro packages this one — always from the official GitHub release)..."
    case "$(uname -m)" in
        x86_64)        arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *)             fail "Unsupported CPU architecture for nuclei: $(uname -m) — install manually from https://github.com/projectdiscovery/nuclei/releases"; return 1 ;;
    esac
    version="$(curl -fsSL $CURL_RETRY_OPTS https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep -oP '"tag_name":\s*"v\K[^"]+')"
    if [ -z "$version" ]; then
        fail "Could not resolve the latest nuclei release (GitHub API unreachable or rate-limited) — install manually."
        return 1
    fi
    tmp_dir="$(mktemp -d)"
    if ! curl -fsSL $CURL_RETRY_OPTS -o "$tmp_dir/nuclei.zip" "https://github.com/projectdiscovery/nuclei/releases/download/v${version}/nuclei_${version}_linux_${arch}.zip"; then
        fail "Could not download nuclei v${version} for linux_${arch} — install manually."
        rm -rf "$tmp_dir"
        return 1
    fi
    unzip -oq "$tmp_dir/nuclei.zip" -d "$tmp_dir" nuclei
    $SUDO install -m 0755 "$tmp_dir/nuclei" /usr/local/bin/nuclei
    rm -rf "$tmp_dir"
}

# --- interactsh-client ---------------------------------------------------------------------------
install_interactsh_client() {
    have interactsh-client && { ok "interactsh-client already installed ($(command -v interactsh-client))"; return 0; }
    log "Installing interactsh-client (blind SSRF/XSS confirmation — always from the official GitHub release)..."
    case "$(uname -m)" in
        x86_64)        arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *)             fail "Unsupported CPU architecture for interactsh-client: $(uname -m) — install manually from https://github.com/projectdiscovery/interactsh/releases"; return 1 ;;
    esac
    version="$(curl -fsSL $CURL_RETRY_OPTS https://api.github.com/repos/projectdiscovery/interactsh/releases/latest | grep -oP '"tag_name":\s*"v\K[^"]+')"
    if [ -z "$version" ]; then
        fail "Could not resolve the latest interactsh release (GitHub API unreachable or rate-limited) — install manually."
        return 1
    fi
    tmp_dir="$(mktemp -d)"
    if ! curl -fsSL $CURL_RETRY_OPTS -o "$tmp_dir/interactsh-client.zip" "https://github.com/projectdiscovery/interactsh/releases/download/v${version}/interactsh-client_${version}_linux_${arch}.zip"; then
        fail "Could not download interactsh-client v${version} for linux_${arch} — install manually."
        rm -rf "$tmp_dir"
        return 1
    fi
    unzip -oq "$tmp_dir/interactsh-client.zip" -d "$tmp_dir" interactsh-client
    $SUDO install -m 0755 "$tmp_dir/interactsh-client" /usr/local/bin/interactsh-client
    rm -rf "$tmp_dir"
}

# --- dalfox ---------------------------------------------------------------------------------------
install_dalfox() {
    have dalfox && { ok "dalfox already installed ($(command -v dalfox))"; return 0; }
    log "Installing dalfox (XSS confirmation — always from the official GitHub release)..."
    # Unlike nuclei/interactsh's amd64/arm64 naming, dalfox's release assets are named after
    # uname -m's own output directly (x86_64/aarch64) — no translation needed for the common cases.
    case "$(uname -m)" in
        x86_64|aarch64) arch="$(uname -m)" ;;
        *)              fail "Unsupported CPU architecture for dalfox: $(uname -m) — install manually from https://github.com/hahwul/dalfox/releases"; return 1 ;;
    esac
    version="$(curl -fsSL $CURL_RETRY_OPTS https://api.github.com/repos/hahwul/dalfox/releases/latest | grep -oP '"tag_name":\s*"v\K[^"]+')"
    if [ -z "$version" ]; then
        fail "Could not resolve the latest dalfox release (GitHub API unreachable or rate-limited) — install manually."
        return 1
    fi
    tmp_dir="$(mktemp -d)"
    if ! curl -fsSL $CURL_RETRY_OPTS -o "$tmp_dir/dalfox.tar.gz" "https://github.com/hahwul/dalfox/releases/download/v${version}/dalfox-v${version}-linux-${arch}.tar.gz"; then
        fail "Could not download dalfox v${version} for linux-${arch} — install manually."
        rm -rf "$tmp_dir"
        return 1
    fi
    # Unlike nuclei's flat zip, this tarball extracts into its own subdirectory
    # (dalfox-v<version>-linux-<arch>/dalfox) — confirmed against a real download, not assumed.
    tar -xzf "$tmp_dir/dalfox.tar.gz" -C "$tmp_dir"
    $SUDO install -m 0755 "$tmp_dir/dalfox-v${version}-linux-${arch}/dalfox" /usr/local/bin/dalfox
    rm -rf "$tmp_dir"
}

# --- ffuf -----------------------------------------------------------------------------------------
install_ffuf() {
    have ffuf && { ok "ffuf already installed ($(command -v ffuf))"; return 0; }
    log "Installing ffuf (content/endpoint discovery — always from the official GitHub release)..."
    case "$(uname -m)" in
        x86_64)        arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *)             fail "Unsupported CPU architecture for ffuf: $(uname -m) — install manually from https://github.com/ffuf/ffuf/releases"; return 1 ;;
    esac
    version="$(curl -fsSL $CURL_RETRY_OPTS https://api.github.com/repos/ffuf/ffuf/releases/latest | grep -oP '"tag_name":\s*"v\K[^"]+')"
    if [ -z "$version" ]; then
        fail "Could not resolve the latest ffuf release (GitHub API unreachable or rate-limited) — install manually."
        return 1
    fi
    tmp_dir="$(mktemp -d)"
    if ! curl -fsSL $CURL_RETRY_OPTS -o "$tmp_dir/ffuf.tar.gz" "https://github.com/ffuf/ffuf/releases/download/v${version}/ffuf_${version}_linux_${arch}.tar.gz"; then
        fail "Could not download ffuf v${version} for linux_${arch} — install manually."
        rm -rf "$tmp_dir"
        return 1
    fi
    # Flat tarball (ffuf binary at the root, alongside README/LICENSE/CHANGELOG) -- confirmed
    # against a real download, not assumed; unlike dalfox's tarball it does NOT extract into its
    # own version-named subdirectory.
    tar -xzf "$tmp_dir/ffuf.tar.gz" -C "$tmp_dir" ffuf
    $SUDO install -m 0755 "$tmp_dir/ffuf" /usr/local/bin/ffuf
    rm -rf "$tmp_dir"
}

# ffuf is useless with no wordlist at all -- unlike install_large_wordlists below (rockyou.txt +
# SecLists username/password lists, sized for credential guessing and gated behind an explicit
# opt-in flag), this is a single small (~40KB) well-known content-discovery list, installed
# unconditionally so ffuf actually has something to run against out of the box. Same env-override
# story as everything else: agent/tools/builders/ffuf.py reads FFUF_WORDLIST_PATH first, falling
# back to this exact path only when that's unset.
install_ffuf_wordlist() {
    dest="/usr/share/wordlists/ffuf/common.txt"
    [ -f "$dest" ] && { ok "$dest already present"; return 0; }
    log "Installing ffuf's default content-discovery wordlist (SecLists common.txt, ~40KB)..."
    $SUDO mkdir -p "$(dirname "$dest")"
    tmp_file="$(mktemp)"
    if curl -fsSL $CURL_RETRY_OPTS -o "$tmp_file" "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"; then
        $SUDO install -m 0644 "$tmp_file" "$dest"
        ok "installed $dest"
    else
        fail "Could not download the default ffuf wordlist from SecLists — install manually, or point FFUF_WORDLIST_PATH at your own."
    fi
    rm -f "$tmp_file"
}

# --- subfinder --------------------------------------------------------------------------------------
install_subfinder() {
    have subfinder && { ok "subfinder already installed ($(command -v subfinder))"; return 0; }
    log "Installing subfinder (passive subdomain aggregation — always from the official GitHub release)..."
    case "$(uname -m)" in
        x86_64)        arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *)             fail "Unsupported CPU architecture for subfinder: $(uname -m) — install manually from https://github.com/projectdiscovery/subfinder/releases"; return 1 ;;
    esac
    version="$(curl -fsSL $CURL_RETRY_OPTS https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | grep -oP '"tag_name":\s*"v\K[^"]+')"
    if [ -z "$version" ]; then
        fail "Could not resolve the latest subfinder release (GitHub API unreachable or rate-limited) — install manually."
        return 1
    fi
    tmp_dir="$(mktemp -d)"
    if ! curl -fsSL $CURL_RETRY_OPTS -o "$tmp_dir/subfinder.zip" "https://github.com/projectdiscovery/subfinder/releases/download/v${version}/subfinder_${version}_linux_${arch}.zip"; then
        fail "Could not download subfinder v${version} for linux_${arch} — install manually."
        rm -rf "$tmp_dir"
        return 1
    fi
    unzip -oq "$tmp_dir/subfinder.zip" -d "$tmp_dir" subfinder
    $SUDO install -m 0755 "$tmp_dir/subfinder" /usr/local/bin/subfinder
    rm -rf "$tmp_dir"
}

# --- amass (active subdomain brute-force + recursion + wildcard-DNS detection, agent/tools/
# amass_runner.py) -- confirmed against the real v5.1.1 GitHub release (repo owasp-amass/amass, NOT
# the older OWASP/Amass path): the archive extracts into its own amass_linux_<arch>/ subdirectory
# (same shape as dalfox's own tarball above), not flat like ffuf/subfinder/trufflehog's.
install_amass() {
    have amass && { ok "amass already installed ($(command -v amass))"; return 0; }
    log "Installing amass (active subdomain brute-force -- agent/tools/amass_runner.py, always from the official GitHub release)..."
    case "$(uname -m)" in
        x86_64)        arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *)             fail "Unsupported CPU architecture for amass: $(uname -m) -- install manually from https://github.com/owasp-amass/amass/releases"; return 1 ;;
    esac
    version="$(curl -fsSL $CURL_RETRY_OPTS https://api.github.com/repos/owasp-amass/amass/releases/latest | grep -oP '"tag_name":\s*"v\K[^"]+')"
    if [ -z "$version" ]; then
        fail "Could not resolve the latest amass release (GitHub API unreachable or rate-limited) -- install manually."
        return 1
    fi
    tmp_dir="$(mktemp -d)"
    if ! curl -fsSL $CURL_RETRY_OPTS -o "$tmp_dir/amass.tar.gz" "https://github.com/owasp-amass/amass/releases/download/v${version}/amass_linux_${arch}.tar.gz"; then
        fail "Could not download amass v${version} for linux_${arch} -- install manually."
        rm -rf "$tmp_dir"
        return 1
    fi
    tar -xzf "$tmp_dir/amass.tar.gz" -C "$tmp_dir"
    $SUDO install -m 0755 "$tmp_dir/amass_linux_${arch}/amass" /usr/local/bin/amass
    rm -rf "$tmp_dir"
}

# amass_enum (agent/tools/amass_runner.py) and subdomain_enum's own assigned-wordlist path
# (agent/tools/native.py, Settings -> Wordlists role "subdomain_enum") both read this same file --
# one wordlist, two consumers. A real, curated SecLists list (5000 real-world subdomain prefixes),
# not the ~40KB ffuf content-discovery list above (different purpose: hostnames, not paths).
install_subdomain_wordlist() {
    dest="/usr/share/wordlists/dns/subdomains-top1million-5000.txt"
    [ -f "$dest" ] && { ok "$dest already present"; return 0; }
    log "Installing the default subdomain brute-force wordlist (SecLists subdomains-top1million-5000.txt, ~50KB)..."
    $SUDO mkdir -p "$(dirname "$dest")"
    tmp_file="$(mktemp)"
    if curl -fsSL $CURL_RETRY_OPTS -o "$tmp_file" "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt"; then
        $SUDO install -m 0644 "$tmp_file" "$dest"
        ok "installed $dest"
    else
        fail "Could not download the default subdomain wordlist from SecLists -- install manually, or assign a different one in Settings -> Wordlists."
    fi
    rm -f "$tmp_file"
}

# --- httpx (ProjectDiscovery's Go HTTP toolkit — NOT the identically-named Python `httpx` pip
# package) ------------------------------------------------------------------------------------
# Real incident this fixes: a live session's own auto-discovery (agent/tools/discovery.py) picked
# up whatever `httpx` binary happened to already be on this machine's PATH and offered it to the
# model as a tool -- 8 real, wasted tool calls across one session, every single one immediately
# failing with "The httpx command line client could not run because the required dependencies
# were not installed. Make sure you've installed everything with: pip install 'httpx[cli]'" --
# that's the Python `httpx` package's OWN CLI entry point (a completely different tool, an HTTP
# client library with an optional Click-based CLI extra, not the recon tool of the same name),
# shadowing the real one. `have httpx` alone (subfinder's own guard, just above) is NOT a safe
# "already installed" check here specifically BECAUSE the whole bug is that a broken same-named
# binary is already on PATH -- a plain presence check would report false-positive "already
# installed" forever and never fix anything. Installed to /usr/local/bin, which normally takes
# PATH precedence over a user-level pip console-script install, so this genuinely replaces the
# broken shim rather than adding a second, still-shadowed copy.
install_httpx() {
    if have httpx && httpx -version >/dev/null 2>&1; then
        ok "httpx already installed and responds to -version ($(command -v httpx)) — the real ProjectDiscovery tool"
        return 0
    fi
    if have httpx; then
        warn "a broken/non-ProjectDiscovery 'httpx' is already on PATH at $(command -v httpx) (doesn't respond to -version) — installing the real one to /usr/local/bin, which should take priority"
    fi
    log "Installing httpx (ProjectDiscovery's HTTP probing/fingerprinting toolkit)..."
    case "$(uname -m)" in
        x86_64)        arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *)             fail "Unsupported CPU architecture for httpx: $(uname -m) — install manually from https://github.com/projectdiscovery/httpx/releases"; return 1 ;;
    esac
    version="$(curl -fsSL $CURL_RETRY_OPTS https://api.github.com/repos/projectdiscovery/httpx/releases/latest | grep -oP '"tag_name":\s*"v\K[^"]+')"
    if [ -z "$version" ]; then
        fail "Could not resolve the latest httpx release (GitHub API unreachable or rate-limited) — install manually."
        return 1
    fi
    tmp_dir="$(mktemp -d)"
    if ! curl -fsSL $CURL_RETRY_OPTS -o "$tmp_dir/httpx.zip" "https://github.com/projectdiscovery/httpx/releases/download/v${version}/httpx_${version}_linux_${arch}.zip"; then
        fail "Could not download httpx v${version} for linux_${arch} — install manually."
        rm -rf "$tmp_dir"
        return 1
    fi
    unzip -oq "$tmp_dir/httpx.zip" -d "$tmp_dir" httpx
    $SUDO install -m 0755 "$tmp_dir/httpx" /usr/local/bin/httpx
    rm -rf "$tmp_dir"
}

# --- metasploit ---------------------------------------------------------------------------------
install_metasploit() {
    have msfconsole && { ok "msfconsole already installed ($(command -v msfconsole))"; return 0; }
    case "$PKG_MANAGER" in
        apt|dnf)
            log "Installing Metasploit Framework via the official Rapid7 installer (large download, be patient)..."
            tmp_installer="$(mktemp)"
            if ! curl -fsSL $CURL_RETRY_OPTS https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb -o "$tmp_installer"; then
                fail "Could not download the Metasploit installer — check network access."
                rm -f "$tmp_installer"
                return 1
            fi
            chmod +x "$tmp_installer"
            $SUDO "$tmp_installer"
            rm -f "$tmp_installer"
            ;;
        *)
            warn "No official Metasploit installer for this distro's package manager (${PKG_MANAGER:-none}) — install manually (e.g. Arch: AUR package 'metasploit'), or run this script inside a Debian/Ubuntu/Fedora WSL2 distro instead."
            return 1
            ;;
    esac
}

# --- metasploit's own bundled wordlists, reachable at the path the LLM already expects ---------
# The exploit-phase model writes raw msfconsole resource-script commands from its own training
# data, which defaults to the Kali convention (/usr/share/wordlists/metasploit/*.txt) regardless of
# what distro this actually runs on. Real incident: a mysql_login brute-force attempt failed
# USER_FILE/PASS_FILE validation before ever reaching the target because that path didn't exist
# here (WSL2 Ubuntu, not Kali) — Metasploit's own omnibus installer already ships the exact same
# wordlists under the framework's own embedded/framework/data/wordlists, just not reachable at the
# path being guessed. A symlink is the entire fix — no separate download, nothing to keep in sync,
# and it transparently covers every current and future msf module that expects the Kali layout.
install_metasploit_wordlists() {
    [ -e /usr/share/wordlists/metasploit ] && { ok "/usr/share/wordlists/metasploit already present"; return 0; }
    have msfconsole || { warn "msfconsole not on PATH — skipping the wordlists symlink (re-run this script once Metasploit installs)."; return 1; }
    # Resolved from the real binary rather than hardcoded, since the omnibus installer's own
    # install prefix is the only thing this depends on, not a guessed distro-specific path.
    msf_bin="$(readlink -f "$(command -v msfconsole)")"
    msf_wordlists="$(dirname "$(dirname "$msf_bin")")/embedded/framework/data/wordlists"
    if [ ! -d "$msf_wordlists" ]; then
        warn "Metasploit's bundled wordlists not found at the expected path ($msf_wordlists) — skipping symlink; brute-force modules that need USER_FILE/PASS_FILE will keep failing until this is set up manually."
        return 1
    fi
    $SUDO mkdir -p /usr/share/wordlists
    $SUDO ln -s "$msf_wordlists" /usr/share/wordlists/metasploit
    ok "linked /usr/share/wordlists/metasploit -> $msf_wordlists"
}

# --- optional larger wordlists: rockyou.txt + a couple of SecLists username lists ---------------
# Off by default (config, not a hardcoded yes) — a genuine ~60-70MB download that most setups
# don't need: msf's own bundled wordlists above already cover default-credential checks, this is
# only for the heavier, separate case of guessing a real *weak* (non-default) password against a
# login endpoint. Installed at the same paths a real Kali box would use
# (/usr/share/wordlists/rockyou.txt, /usr/share/seclists/...) so the exploit-phase model's own
# path guesses resolve without needing to be taught a new convention, same reasoning as the msf
# wordlists symlink above. This is a one-time provisioning flag for this script, not something
# the running app reads — pass it on invocation, not in .env: INSTALL_LARGE_WORDLISTS=true ./setup_tools.sh
install_large_wordlists() {
    if [ "${INSTALL_LARGE_WORDLISTS:-false}" != "true" ]; then
        log "INSTALL_LARGE_WORDLISTS is not 'true' — skipping rockyou.txt/SecLists (re-run as INSTALL_LARGE_WORDLISTS=true ./setup_tools.sh for real weak-password brute-forcing, not just default-creds checks)."
        return 0
    fi
    log "INSTALL_LARGE_WORDLISTS=true — installing rockyou.txt + SecLists username/password lists..."

    if [ -f /usr/share/wordlists/rockyou.txt ]; then
        ok "/usr/share/wordlists/rockyou.txt already present"
    else
        tmp_dir="$(mktemp -d)"
        if curl -fsSL $CURL_RETRY_OPTS -o "$tmp_dir/rockyou.txt.tar.gz" "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz" \
            && tar -xzf "$tmp_dir/rockyou.txt.tar.gz" -C "$tmp_dir"; then
            $SUDO mkdir -p /usr/share/wordlists
            $SUDO install -m 0644 "$tmp_dir/rockyou.txt" /usr/share/wordlists/rockyou.txt
            ok "installed /usr/share/wordlists/rockyou.txt"
        else
            fail "Could not download/extract rockyou.txt from SecLists — install manually."
        fi
        rm -rf "$tmp_dir"
    fi

    # A handful of small, specifically-picked files fetched directly — not a full SecLists clone
    # (that repo is several GB, almost none of it relevant to what ASRA's tools actually consume).
    for relpath in "Usernames/top-usernames-shortlist.txt" "Passwords/Common-Credentials/10k-most-common.txt"; do
        dest="/usr/share/seclists/$relpath"
        [ -f "$dest" ] && { ok "$dest already present"; continue; }
        $SUDO mkdir -p "$(dirname "$dest")"
        tmp_file="$(mktemp)"
        if curl -fsSL $CURL_RETRY_OPTS -o "$tmp_file" "https://raw.githubusercontent.com/danielmiessler/SecLists/master/$relpath"; then
            $SUDO install -m 0644 "$tmp_file" "$dest"
            ok "installed $dest"
        else
            fail "Could not download $relpath from SecLists — install manually."
        fi
        rm -f "$tmp_file"
    done
}

# --- radare2 (+ r2ghidra plugin) and gdb -- Reverse Engineering mode's binary-analysis tools
# (agent/tools/builders/radare2.py, gdb.py). Each gets its own explicit Darwin branch (calling
# `brew install` directly) rather than folding "brew" into the shared PKG_MANAGER/pkg_install
# machinery above -- that machinery backs every OTHER tool's own install_* function too (nmap,
# sqlmap, nikto, ...), each with package names only ever chosen/verified for apt/dnf/pacman; widening
# PKG_MANAGER to include "brew" would silently change behavior for all of them on a Mac, not just
# these two. README's own macOS section documents the existing arsenal as a separate manual
# Homebrew list for exactly this reason -- these two functions are the one deliberate exception,
# automated per the user's own explicit choice for the new Reverse Engineering toolset specifically.
# -------------------------------------------------------------------------------------------------
install_radare2() {
    # Distro packages (apt/dnf/pacman) lag radare2 upstream badly -- confirmed live: Ubuntu
    # noble's own apt radare2 (5.5.0, from 2022) is missing API r2ghidra's current build actually
    # needs (R_VEC_FOREACH, RAnalFunction.callconv, RFlagItem.addr, RAnal.config among others),
    # so r2ghidra either fails to build against it or silently never loads -- not a config
    # problem, a genuine version gap. radare2's own project explicitly recommends building from
    # source (sys/install.sh) over any distro package for exactly this reason. Version-gate the
    # "already installed" short-circuit on the major version, not just presence on PATH, so a
    # machine that already has the too-old apt package still gets rebuilt here instead of being
    # silently accepted.
    if have radare2; then
        # awk '{print $2}' takes the SECOND whitespace-separated field of `r2 -v`'s first line
        # ("radare2 6.2.1 +0 abi:136 @ linux-x86_64") -- deliberately not a bare
        # `grep -oE '[0-9]+' | head -1`, which was tried first and confirmed live to match the
        # "2" inside the literal word "radare2" before ever reaching the real "6.2.1" version
        # token, permanently mis-detecting every install (even a freshly-built 6.2.1) as too old
        # and forcing a pointless full rebuild-from-source on every single re-run.
        _r2_major="$(r2 -v 2>/dev/null | head -1 | awk '{print $2}' | cut -d. -f1)"
        if [ -n "$_r2_major" ] && [ "$_r2_major" -ge 6 ] 2>/dev/null; then
            ok "radare2 already installed and new enough ($(r2 -v 2>/dev/null | head -1))"
            return 0
        fi
        warn "radare2 present but too old for r2ghidra ($(r2 -v 2>/dev/null | head -1)) -- rebuilding from source."
    else
        log "Installing radare2 (static binary analysis/decompilation -- agent/tools/builders/radare2.py)..."
    fi
    if [ "$(uname -s)" = "Darwin" ]; then
        have brew || { fail "Homebrew not found -- install it first (https://brew.sh), then re-run this script."; return 1; }
        brew install radare2 || { fail "brew install radare2 failed -- see output above."; return 1; }
        return 0
    fi
    for base_pkg in git make gcc; do
        have "$base_pkg" || pkg_install "$base_pkg" || warn "Could not install build dependency '$base_pkg' -- radare2's own build may fail below."
    done
    # Building must happen on a native (ext4) path, never a Windows drvfs mount (/mnt/c/... under
    # WSL2) -- confirmed live: building the identical source tree from /mnt/c fails partway
    # through with a raw "OSError: [Errno 22] Invalid argument" from one of the build's own helper
    # scripts, a drvfs concurrent-file-I/O quirk under a parallel `make`, not a real code/config
    # error; the exact same tree builds clean once copied to $HOME first. $HOME is always native
    # under WSL2's own default layout (only an explicit /mnt/c cwd triggers this), so no special
    # detection is needed here -- just always stage the clone under $HOME regardless of OS.
    _r2_build_dir="$HOME/.cache/asra-build/radare2"
    $SUDO rm -rf "$_r2_build_dir"
    mkdir -p "$(dirname "$_r2_build_dir")"
    git clone --depth 1 https://github.com/radareorg/radare2 "$_r2_build_dir" || { fail "git clone of radare2 failed -- check network access."; return 1; }
    # `--install` is load-bearing, not optional -- radare2's own sys/install.sh DEFAULTS to
    # `make symstall` (symlinks the installed binary straight back into THIS build directory,
    # meant for a developer actively hacking on radare2's own source, so a rebuild is picked up
    # without reinstalling) rather than a real `cp`-based `make install`. Confirmed live, a real,
    # confirmed regression from an earlier pass that used the bare (no-flag) form: building as root
    # staged the clone under /root/.cache/asra-build/radare2, and the resulting symlink-based
    # install pointed straight back into /root/... -- invisible to any non-root invocation of ASRA
    # (the default `run.bat` path, not just `run-root.bat`), so radare2 showed as "not found on
    # PATH" for a plain unprivileged run despite `have radare2` succeeding right here (running this
    # very script, as whichever user invoked it). `--install` makes the install a real, independent
    # copy any user can execute, exactly like every other tool this script provisions.
    ( cd "$_r2_build_dir" && $SUDO sh sys/install.sh --install ) || { fail "radare2 build/install failed -- see output above."; return 1; }
    have radare2 || { fail "radare2 build reported success but the binary still isn't on PATH."; return 1; }
    # Refresh r2pm's own package index against the just-installed version before anything below
    # tries to use it -- a stale index from a much older radare2 install can point r2pm at recipes
    # that no longer match the new build.
    have r2pm && r2pm -U >/dev/null 2>&1
    ok "radare2 built from source ($(r2 -v 2>/dev/null | head -1))"
}

install_r2ghidra() {
    have radare2 || { warn "radare2 not installed -- skipping r2ghidra (re-run once radare2 is installed)."; return 1; }
    have r2pm || { warn "r2pm (radare2's own package manager) not on PATH -- skipping r2ghidra; install manually via 'r2pm -ci r2ghidra' once available."; return 1; }
    # r2's own major/minor/patch version, used below to build the system plugin dir path
    # (/usr/local/lib/radare2/<version>) -- NOT via `$(r2 -H | ...)`, confirmed live to be
    # unreliable: `r2 -H` prints its env-info block correctly when piped directly, but produces
    # EMPTY output when captured through a command-substitution subshell (`X=$(r2 -H | ...)`),
    # reproduced cleanly and repeatedly outside any of this project's own known shell-escaping
    # issues -- a genuine r2 quirk, not ours. `r2 -v`'s own first line has no such problem.
    _r2_version="$(r2 -v 2>/dev/null | head -1 | awk '{print $2}')"
    _r2_sys_plugin_dir="/usr/local/lib/radare2/${_r2_version}"
    # A REAL, confirmed-live gap this whole system-wide-copy step exists to close: r2pm always
    # installs into the INVOKING user's own per-user plugin dir (~/.local/share/radare2/plugins,
    # the XDG basedir convention -- r2pm has no system-wide install mode at all). Running this
    # script as root (a real, supported ASRA launch path -- run-root.bat) installs r2ghidra for
    # root only; a later plain, non-root `run.bat` launch sees a radare2 with NO decompile plugin
    # at all, decompile_function silently degrading to a raw error -- confirmed live on this exact
    # machine. Copying the built .so into radare2's own SYSTEM plugin dir (world-readable, unlike
    # any one user's home directory) makes it visible to every user's own r2 regardless of which
    # one built it, matching every other tool this script provisions (a real system-wide install,
    # not tied to whoever happened to run this script).
    # The system copy alone is what actually matters (it's what every user's own r2 resolves,
    # regardless of who built it) -- checked FIRST and on its own, so a machine where root already
    # ran this once short-circuits cleanly for a later non-root run too, instead of redundantly
    # rebuilding r2ghidra from source again just because THIS user's own r2pm has no record of it.
    if [ -f "${_r2_sys_plugin_dir}/core_ghidra.so" ]; then
        ok "r2ghidra plugin already installed system-wide (${_r2_sys_plugin_dir})"
        return 0
    fi
    _r2ghidra_so="$(find "$HOME/.local/share/radare2/plugins" -maxdepth 1 -iname 'core_ghidra.so' 2>/dev/null | head -1)"
    if [ -z "$_r2ghidra_so" ]; then
        log "Installing r2ghidra (Ghidra's own decompiler, ported to a lightweight radare2 plugin -- no JVM/Java needed)..."
        r2pm -ci r2ghidra || { warn "r2pm could not install r2ghidra -- decompile_function analysis (agent/tools/builders/radare2.py) will fail until this is retried manually (r2pm -ci r2ghidra)."; return 1; }
        _r2ghidra_so="$(find "$HOME/.local/share/radare2/plugins" -maxdepth 1 -iname 'core_ghidra.so' 2>/dev/null | head -1)"
    fi
    if [ -n "$_r2ghidra_so" ] && [ -d "$_r2_sys_plugin_dir" ]; then
        $SUDO cp -f "$_r2ghidra_so" "$_r2_sys_plugin_dir/" && $SUDO chmod 755 "${_r2_sys_plugin_dir}/core_ghidra.so"
        ok "r2ghidra plugin installed system-wide (${_r2_sys_plugin_dir}) -- visible to every user, not just $(whoami)"
    else
        warn "r2pm installed r2ghidra for $(whoami) only -- could not confirm the system plugin dir (${_r2_sys_plugin_dir}); a different user may still see decompile_function fail until this is retried."
    fi
}

install_gdb() {
    have gdb && { ok "gdb already installed ($(command -v gdb))"; return 0; }
    log "Installing gdb (one-shot dynamic binary triage -- agent/tools/builders/gdb.py)..."
    if [ "$(uname -s)" = "Darwin" ]; then
        have brew || { fail "Homebrew not found -- install it first (https://brew.sh), then re-run this script."; return 1; }
        brew install gdb || { fail "brew install gdb failed -- see output above."; return 1; }
        # macOS also needs gdb code-signed once before it can actually attach to/run a process
        # (System Integrity Protection) -- brew installing the binary is not enough on its own, and
        # the codesign step itself needs an interactive `sudo security` sequence this script can't
        # safely automate unattended. Surfaced as a warning, not silently assumed to work.
        warn "macOS also needs gdb code-signed once before it can run/attach to a process (System Integrity Protection) -- see 'brew info gdb' for the exact steps."
        return 0
    fi
    pkg_install gdb || fail "Could not install gdb via ${PKG_MANAGER:-a supported package manager}."
}

install_strace() {
    have strace && { ok "strace already installed ($(command -v strace))"; return 0; }
    log "Installing strace (RE mode's behavioral/syscall triage -- agent/tools/builders/strace.py)..."
    if [ "$(uname -s)" = "Darwin" ]; then
        # Genuinely no macOS equivalent to install here, unlike gdb/wine above -- strace is a
        # ptrace-based Linux tool with no Homebrew formula; macOS's own syscall tracer (dtruss) is a
        # different tool entirely (needs SIP disabled, a different CLI/output format). Surfaced
        # honestly as a real gap rather than silently installing something that isn't actually
        # strace -- ASRA's own tool registry health-check will just show strace_run as unavailable
        # here, same as any other tool genuinely not installed.
        warn "strace has no macOS equivalent this script can install -- strace_run will show as unavailable on this machine. macOS's own syscall tracer (dtruss) needs SIP disabled and isn't a drop-in substitute."
        return 0
    fi
    pkg_install strace || fail "Could not install strace via ${PKG_MANAGER:-a supported package manager}."
}

# --- wine (runs a Windows PE binary directly on Linux, for RE mode's dynamic-analysis path) ------
# Not invoked through its own ToolSpec/builder -- there is no dedicated "wine" tool in the registry.
# custom_re_script (agent/tools/__init__.py, reuses custom_exploit_run's pwntools-capable native
# function) is what actually drives it, via a real model-written script (e.g. pwntools'
# process(["wine", target_exe, ...])) once static analysis alone can't answer a question -- this
# function's only job is making sure the `wine`/`wine64` binaries exist on PATH for that script to
# find. Confirmed live before adding this: on a fresh Ubuntu noble WSL2 install, apt's own `wine`
# meta-package resolves to a pure 64-bit install (no i386/multiarch needed) for a 64-bit PE target,
# ~100MB download / ~700-900MB installed (the bulk is one package, libwine) -- real disk space on
# a real machine is essentially never the constraint that matters here.
install_wine() {
    have wine && { ok "wine already installed ($(command -v wine))"; return 0; }
    log "Installing wine (runs a Windows PE target directly for RE mode's dynamic-analysis path -- driven via custom_re_script, no dedicated ToolSpec)..."
    if [ "$(uname -s)" = "Darwin" ]; then
        have brew || { fail "Homebrew not found -- install it first (https://brew.sh), then re-run this script."; return 1; }
        # wine on macOS is genuinely more fragile than radare2/gdb's own brew formulas (Rosetta on
        # Apple Silicon, XQuartz for anything GUI) -- brew's own cask still gets the CLI binary onto
        # PATH for custom_re_script's headless use case, so attempted here same as the other two,
        # but surfaced as a real caveat rather than assumed to just work everywhere.
        brew install --cask wine-stable || { fail "brew install --cask wine-stable failed -- see output above. wine on macOS can need Rosetta/XQuartz depending on the target; see https://gitlab.winehq.org/wine/wine/-/wikis/MacOS-FAQ for troubleshooting."; return 1; }
        return 0
    fi
    pkg_install wine || { warn "wine not available via $PKG_MANAGER -- RE mode's dynamic-analysis path (custom_re_script driving a Windows PE target) will fail until this is retried manually."; return 1; }
    # Xvfb (agent/tools/sandbox.py's own run_sandboxed/_start_offscreen_display) is what actually
    # makes wine headless on this project's real Windows-hosted runtime -- confirmed live, real
    # incident: WSLg forwards the sandbox's own DISPLAY straight to the operator's real Windows
    # desktop by default, so without this, every custom_re_script call driving wine popped a
    # genuine, visible window (an RE session can call it hundreds of times). Best-effort here --
    # run_sandboxed already degrades gracefully (logs a debug note, runs without the offscreen
    # display) if this specific install fails.
    pkg_install xvfb || warn "xvfb (Xvfb) not available via $PKG_MANAGER -- wine will show a real, visible window on the desktop when custom_re_script drives it (see agent/tools/sandbox.py)."
    # cap_sys_ptrace on the REAL wineserver64 binary (not /usr/bin/wineserver, a tiny dispatcher
    # script setcap can't attach anything to -- same "capabilities go on the real binary, not a
    # wrapper" reasoning install_tshark applies to dumpcap) -- same fix class install_scanmem
    # already applies for the identical Yama ptrace_scope=1 restriction (confirmed live on this
    # project's own WSL2 runtime), attempted here because winedbg's own internal debugging of a
    # wine-hosted process is ptrace-based too. Confirmed NOT sufficient on its own to fix
    # agent/tools/wine_debug.py's own documented `continue` hang (see that file's own module
    # docstring for the full, honest status) -- kept anyway as a real, low-risk prerequisite in case
    # a future fix there needs it, not a claim that wine_debug_run itself currently works.
    wineserver64_bin="$(find /usr/lib -maxdepth 3 -iname 'wineserver64' -type f 2>/dev/null | head -1)"
    if [ -n "$wineserver64_bin" ]; then
        if $SUDO setcap cap_sys_ptrace+ep "$wineserver64_bin"; then
            ok "wine installed, wineserver64 granted cap_sys_ptrace ($wineserver64_bin)"
        else
            warn "wine installed, but setcap cap_sys_ptrace on wineserver64 ($wineserver64_bin) failed."
        fi
    else
        warn "could not locate the real wineserver64 binary under /usr/lib to grant cap_sys_ptrace -- skipping."
    fi
}

# --- heimdall (EVM bytecode decompilation, agent/tools/builders/heimdall.py) --------------------
# No distro/brew package for this one -- heimdall-rs's own official install path (confirmed against
# its README) is its "bifrost" installer/version-manager (itself a small Rust binary, not heimdall
# itself), on top of a real Rust/Cargo toolchain -- `curl ... | bash` only installs bifrost; a
# SEPARATE `bifrost` invocation afterward is what actually compiles and installs the real `heimdall`
# binary (confirmed live: skipping this step leaves bifrost installed but no heimdall on PATH at
# all -- the exact gap this function used to have). bifrost's own build needs pkg-config to locate
# OpenSSL for one of heimdall's own dependencies (openssl-sys) -- confirmed live: without it, the
# build fails outright with "Could not find directory of OpenSSL installation ... requires the
# `pkg-config` utility" -- bifrost auto-installs libssl-dev itself on a Debian-based system but does
# NOT install pkg-config, so this is provisioned explicitly here first.
install_heimdall() {
    have heimdall && { ok "heimdall already installed ($(command -v heimdall))"; return 0; }
    log "Installing heimdall (EVM bytecode decompilation -- agent/tools/builders/heimdall.py)..."
    if [ "$(uname -s)" = "Darwin" ]; then
        have brew || { fail "Homebrew not found -- install it first (https://brew.sh), then re-run this script."; return 1; }
        brew install pkg-config openssl || warn "brew install pkg-config/openssl failed -- heimdall's own build may fail without them, see output above."
    else
        pkg_install pkg-config || warn "Could not install pkg-config via $PKG_MANAGER -- heimdall's own build needs it to locate OpenSSL, may fail without it."
    fi
    if ! have cargo; then
        log "heimdall needs Rust/Cargo first -- installing via rustup..."
        if ! curl -fsSL $CURL_RETRY_OPTS https://sh.rustup.rs | sh -s -- -y -q; then
            fail "Could not install Rust via rustup -- install heimdall manually: https://github.com/Jon-Becker/heimdall-rs"
            return 1
        fi
        # rustup installs into $HOME/.cargo/bin -- not yet on PATH for the rest of THIS script's
        # own process (a fresh shell picks it up via rustup's own profile edit; this one won't).
        export PATH="$HOME/.cargo/bin:$PATH"
    fi
    if ! curl -fsSL $CURL_RETRY_OPTS http://get.heimdall.rs | bash; then
        fail "Could not run heimdall's own bifrost installer -- install manually: https://github.com/Jon-Becker/heimdall-rs"
        return 1
    fi
    # bifrost installs itself to $HOME/.bifrost/bin -- same "not yet on PATH for the rest of THIS
    # script's own process" reasoning as cargo above.
    export PATH="$HOME/.bifrost/bin:$PATH"
    log "Building heimdall itself via bifrost (a real cargo build from source -- can take a few minutes)..."
    if ! bifrost; then
        fail "bifrost could not build/install heimdall -- see its own output above for the real cargo error, or install manually: https://github.com/Jon-Becker/heimdall-rs"
        return 1
    fi
    # bifrost installs the real binary to $HOME/.bifrost/bin and adds that to $HOME/.bashrc's own
    # PATH -- but .bashrc is only reliably sourced by an INTERACTIVE shell, not every way ASRA's own
    # server process might actually get started (confirmed live: a fresh `bash -lc` login shell,
    # closer to how a script/service invocation runs, did NOT have heimdall on PATH even right after
    # a successful bifrost build, while radare2/gdb -- both real apt packages under /usr/bin -- were
    # fine). Symlinking into /usr/local/bin matches the exact same reliable-regardless-of-shell-type
    # pattern every other GitHub-release-binary tool in this script already uses (nuclei/dalfox/ffuf/
    # subfinder/httpx), instead of trusting bifrost's own shell-profile PATH edit to be in effect by
    # the time ./run.sh actually starts.
    if [ -f "$HOME/.bifrost/bin/heimdall" ]; then
        $SUDO install -m 0755 "$HOME/.bifrost/bin/heimdall" /usr/local/bin/heimdall
    fi
    have heimdall || warn "bifrost reported success, but 'heimdall' still isn't found on PATH -- check $HOME/.bifrost/bin/heimdall exists and re-run this script."
}

# --- upx (packed-binary detection/unpacking, agent/tools/builders/upx.py) ----------------------
install_upx() {
    have upx && { ok "upx already installed ($(command -v upx))"; return 0; }
    log "Installing upx (packed-binary detection/unpacking -- agent/tools/builders/upx.py)..."
    if [ "$(uname -s)" = "Darwin" ]; then
        have brew || { fail "Homebrew not found -- install it first (https://brew.sh), then re-run this script."; return 1; }
        brew install upx || { fail "brew install upx failed -- see output above."; return 1; }
        return 0
    fi
    # Debian/Ubuntu package the binary as 'upx-ucl' (the upstream project's old name) while still
    # providing an 'upx' command via alternatives -- dnf/pacman both just call it 'upx' directly.
    case "$PKG_MANAGER" in
        apt) pkg_install upx-ucl ;;
        *)   pkg_install upx ;;
    esac || { warn "upx not available via $PKG_MANAGER -- install manually from https://github.com/upx/upx/releases."; return 1; }
}

# --- JRE (prerequisite for apktool/jadx, agent/tools/builders/apktool.py, jadx.py) --------------
# Neither of ASRA's own arsenal tools before this needed a JVM at all -- both apktool and jadx are
# real Java applications (not a thin Go/Rust CLI with a native binary release), so this is the one
# genuinely new runtime prerequisite the Mobile RE addition brings in.
install_jre() {
    have java && { ok "java already installed ($(command -v java))"; return 0; }
    log "Installing a JRE (needed by apktool and jadx, both real Java applications)..."
    if [ "$(uname -s)" = "Darwin" ]; then
        have brew || { fail "Homebrew not found -- install it first (https://brew.sh), then re-run this script."; return 1; }
        brew install openjdk || { fail "brew install openjdk failed -- see output above."; return 1; }
        return 0
    fi
    case "$PKG_MANAGER" in
        apt)    pkg_install default-jre-headless ;;
        dnf)    pkg_install java-latest-openjdk-headless ;;
        pacman) pkg_install jre-openjdk-headless ;;
        *)      warn "No supported package manager detected -- install a JRE manually before apktool/jadx can run."; return 1 ;;
    esac || { warn "Could not install a JRE via $PKG_MANAGER -- apktool/jadx will fail to run until one is installed manually."; return 1; }
}

# --- osv-scanner (dependency/SCA scanning, agent/tools/builders/osv_scanner.py) -----------------
install_osv_scanner() {
    have osv-scanner && { ok "osv-scanner already installed ($(command -v osv-scanner))"; return 0; }
    log "Installing osv-scanner (dependency-lockfile SCA against the OSV database -- always from the official GitHub release)..."
    case "$(uname -m)" in
        x86_64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) fail "Unsupported CPU architecture for osv-scanner: $(uname -m) -- install manually from https://github.com/google/osv-scanner/releases"; return 1 ;;
    esac
    os_name="linux"
    [ "$(uname -s)" = "Darwin" ] && os_name="darwin"
    version="$(curl -fsSL $CURL_RETRY_OPTS https://api.github.com/repos/google/osv-scanner/releases/latest | grep -oP '"tag_name":\s*"v\K[^"]+')"
    if [ -z "$version" ]; then
        fail "Could not resolve the latest osv-scanner release (GitHub API unreachable or rate-limited) -- install manually."
        return 1
    fi
    tmp_file="$(mktemp)"
    # Unlike nuclei/dalfox/ffuf's archive releases, osv-scanner ships each platform's build as a
    # single raw binary asset (goreleaser's "no archive" mode, confirmed against the real release
    # asset list) -- downloaded and chmod'd directly, no unzip/tar step needed.
    if ! curl -fsSL $CURL_RETRY_OPTS -o "$tmp_file" "https://github.com/google/osv-scanner/releases/download/v${version}/osv-scanner_${os_name}_${arch}"; then
        fail "Could not download osv-scanner v${version} for ${os_name}_${arch} -- install manually."
        rm -f "$tmp_file"
        return 1
    fi
    $SUDO install -m 0755 "$tmp_file" /usr/local/bin/osv-scanner
    rm -f "$tmp_file"
}

# --- trufflehog (secrets-in-git scanning, agent/tools/builders/trufflehog.py) --------------------
install_trufflehog() {
    have trufflehog && { ok "trufflehog already installed ($(command -v trufflehog))"; return 0; }
    log "Installing trufflehog (secrets scanning, full git history included -- always from the official GitHub release)..."
    case "$(uname -m)" in
        x86_64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) fail "Unsupported CPU architecture for trufflehog: $(uname -m) -- install manually from https://github.com/trufflesecurity/trufflehog/releases"; return 1 ;;
    esac
    os_name="linux"
    [ "$(uname -s)" = "Darwin" ] && os_name="darwin"
    version="$(curl -fsSL $CURL_RETRY_OPTS https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest | grep -oP '"tag_name":\s*"v\K[^"]+')"
    if [ -z "$version" ]; then
        fail "Could not resolve the latest trufflehog release (GitHub API unreachable or rate-limited) -- install manually."
        return 1
    fi
    tmp_dir="$(mktemp -d)"
    if ! curl -fsSL $CURL_RETRY_OPTS -o "$tmp_dir/trufflehog.tar.gz" "https://github.com/trufflesecurity/trufflehog/releases/download/v${version}/trufflehog_${version}_${os_name}_${arch}.tar.gz"; then
        fail "Could not download trufflehog v${version} for ${os_name}_${arch} -- install manually."
        rm -rf "$tmp_dir"
        return 1
    fi
    # Flat tarball (trufflehog binary at the root, alongside README/LICENSE) -- same shape as ffuf's
    # own tarball, confirmed against the real goreleaser-produced asset.
    tar -xzf "$tmp_dir/trufflehog.tar.gz" -C "$tmp_dir" trufflehog
    $SUDO install -m 0755 "$tmp_dir/trufflehog" /usr/local/bin/trufflehog
    rm -rf "$tmp_dir"
}

# --- apktool (Android APK smali/resource decompilation, agent/tools/builders/apktool.py) --------
# No distro/brew package reliable enough across apt/dnf/pacman/brew to depend on -- installed the
# same way the project's own official docs describe: the upstream wrapper script plus its jar,
# both fetched directly and paired together under /usr/local/bin, same "wrapper script calling a
# real interpreter" shape this file already uses for sqlmap/nikto/whatweb.
install_apktool() {
    have apktool && { ok "apktool already installed ($(command -v apktool))"; return 0; }
    install_jre || { warn "No JRE available -- apktool would not be able to run even if installed; skipping."; return 1; }
    log "Installing apktool (Android APK smali/resource decompilation -- agent/tools/builders/apktool.py)..."
    version="$(curl -fsSL $CURL_RETRY_OPTS https://api.github.com/repos/iBotPeaches/Apktool/releases/latest | grep -oP '"tag_name":\s*"v\K[^"]+')"
    if [ -z "$version" ]; then
        fail "Could not resolve the latest apktool release (GitHub API unreachable or rate-limited) -- install manually."
        return 1
    fi
    if ! $SUDO curl -fsSL $CURL_RETRY_OPTS -o /usr/local/bin/apktool.jar "https://github.com/iBotPeaches/Apktool/releases/download/v${version}/apktool_${version}.jar"; then
        fail "Could not download apktool_${version}.jar -- install manually from https://apktool.org/."
        return 1
    fi
    $SUDO tee /usr/local/bin/apktool >/dev/null <<'WRAPPER'
#!/bin/sh
exec java -jar /usr/local/bin/apktool.jar "$@"
WRAPPER
    $SUDO chmod +x /usr/local/bin/apktool
}

# --- jadx (Android APK/DEX decompilation to readable Java, agent/tools/builders/jadx.py) --------
install_jadx() {
    have jadx && { ok "jadx already installed ($(command -v jadx))"; return 0; }
    install_jre || { warn "No JRE available -- jadx would not be able to run even if installed; skipping."; return 1; }
    log "Installing jadx (Android APK/DEX decompilation to readable Java source -- agent/tools/builders/jadx.py)..."
    version="$(curl -fsSL $CURL_RETRY_OPTS https://api.github.com/repos/skylot/jadx/releases/latest | grep -oP '"tag_name":\s*"v\K[^"]+')"
    if [ -z "$version" ]; then
        fail "Could not resolve the latest jadx release (GitHub API unreachable or rate-limited) -- install manually."
        return 1
    fi
    tmp_dir="$(mktemp -d)"
    if ! curl -fsSL $CURL_RETRY_OPTS -o "$tmp_dir/jadx.zip" "https://github.com/skylot/jadx/releases/download/v${version}/jadx-${version}.zip"; then
        fail "Could not download jadx-${version}.zip -- install manually from https://github.com/skylot/jadx/releases."
        rm -rf "$tmp_dir"
        return 1
    fi
    # The release zip's own top-level layout (bin/jadx, bin/jadx-gui, lib/*.jar) is installed
    # wholesale under /opt so the wrapper script's relative jar lookups keep working, rather than
    # cherry-picking just the bin/ scripts out -- same "keep the upstream layout intact" reasoning
    # heimdall's own bifrost-built binary install does NOT need (that one really is a single binary).
    $SUDO rm -rf /opt/jadx
    $SUDO mkdir -p /opt/jadx
    # /opt/jadx is root-owned (created via $SUDO above) -- unzip itself must run as $SUDO too, or
    # every file write inside it fails with Permission denied (confirmed live: this is exactly what
    # happened the first time this function ran unprivileged against a root-owned target directory).
    $SUDO unzip -oq "$tmp_dir/jadx.zip" -d /opt/jadx
    $SUDO chmod +x /opt/jadx/bin/jadx /opt/jadx/bin/jadx-gui 2>/dev/null
    $SUDO ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx
    rm -rf "$tmp_dir"
}

# --- binwalk (firmware/embedded-image analysis, agent/tools/builders/binwalk.py) ----------------
# apt, not pip -- confirmed live: PyPI's own "binwalk" package (2.1.0) is genuinely broken, missing
# its own binwalk.core submodule entirely (a plain `import binwalk` throws ModuleNotFoundError the
# instant the CLI script runs), a real upstream packaging gap, not something a version pin fixes.
# apt's own package (ReFirmLabs' binwalk v2.3.x on Debian/Ubuntu) is complete and correctly wired.
install_binwalk() {
    have binwalk && { ok "binwalk already installed ($(command -v binwalk))"; return 0; }
    log "Installing binwalk (firmware/embedded-image analysis -- agent/tools/builders/binwalk.py)..."
    if [ "$(uname -s)" = "Darwin" ]; then
        have brew || { fail "Homebrew not found -- install it first (https://brew.sh), then re-run this script."; return 1; }
        brew install binwalk || { fail "brew install binwalk failed -- see output above."; return 1; }
        return 0
    fi
    pkg_install binwalk || { warn "binwalk not available via $PKG_MANAGER -- install manually from https://github.com/ReFirmLabs/binwalk."; return 1; }
}

# --- scanmem (live-process memory scan/patch, agent/tools/memscan_manager.py's memscan_* tools) --
# apt-only, no Darwin branch -- same precedent as install_afl below: scanmem is a Linux/proc-based
# ptrace tool with no real macOS story. Confirmed live (this project's own WSL2 dev environment): a
# stock Ubuntu's default Yama ptrace_scope=1 blocks scanmem from attaching even to a same-uid
# process it didn't itself fork ("error: failed to attach to <pid>, Operation not permitted") --
# granting the scanmem BINARY cap_sys_ptrace via setcap once, here, is the standard fix scanmem/
# GameConqueror's own docs recommend as the alternative to running everything as root, and avoids
# any runtime sudo escalation on every single memscan_attach call. Re-applied even when scanmem is
# already installed (idempotent either way) -- a package upgrade replaces the binary file, which
# silently drops any capability bit set on the old one.
install_scanmem() {
    if [ "$(uname -s)" = "Darwin" ]; then
        warn "scanmem has no automated macOS install here (it's a Linux/proc-based ptrace tool) -- see https://github.com/scanmem/scanmem for manual build steps."
        return 1
    fi
    if ! have scanmem; then
        log "Installing scanmem (live-process memory scan/patch -- agent/tools/memscan_manager.py)..."
        pkg_install scanmem || { warn "scanmem not available via $PKG_MANAGER -- install manually from https://github.com/scanmem/scanmem."; return 1; }
    fi
    scanmem_bin="$(command -v scanmem)"
    if $SUDO setcap cap_sys_ptrace+ep "$scanmem_bin"; then
        ok "scanmem installed and granted cap_sys_ptrace ($scanmem_bin)"
    else
        warn "scanmem installed, but setcap cap_sys_ptrace failed -- memscan_attach will only work run as root."
        return 1
    fi
}

# --- tshark (packet capture/analysis, agent/tools/builders/tshark.py's tshark_capture/
# tshark_read_pcap) -------------------------------------------------------------------------------
# Same setcap-not-setuid reasoning as install_scanmem right above, applied to dumpcap (the actual
# capture helper tshark shells out to internally -- capabilities attach to THAT binary, not tshark
# itself) instead of scanmem's own binary. Re-applied even when tshark is already installed --
# idempotent either way, and a package upgrade replacing the dumpcap binary silently drops any
# capability bit set on the old one, same as scanmem's own comment explains.
install_tshark() {
    if [ "$(uname -s)" = "Darwin" ]; then
        warn "tshark has no automated macOS install here -- 'brew install wireshark' ships it, then run: sudo chmod +a \"user:\$(whoami) allow read,execute\" \$(brew --prefix)/bin/dumpcap (Wireshark's own documented macOS non-root-capture step)."
        return 1
    fi
    if ! have tshark; then
        log "Installing tshark (Wireshark CLI -- packet capture/analysis, agent/tools/builders/tshark.py)..."
        case "$PKG_MANAGER" in
            apt)
                # wireshark-common's own postinst asks (via debconf) whether non-superusers should be
                # able to capture packets, defaulting to a SETUID-root dumpcap if answered yes --
                # broader than needed here (setuid root on a common package is a persistent attack
                # surface). Preseeded "false" -- the narrower cap_net_raw/cap_net_admin capability
                # granted explicitly below (setcap, not setuid) gets the same non-root-capture outcome
                # without leaving a setuid-root binary on the system.
                echo "wireshark-common wireshark-common/install-setuid boolean false" | $SUDO debconf-set-selections
                pkg_update_once
                DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y tshark || { fail "apt-get install tshark failed."; return 1; }
                ;;
            dnf)    pkg_install wireshark-cli || { fail "dnf install wireshark-cli failed."; return 1; } ;;
            pacman) pkg_install wireshark-cli || { fail "pacman install wireshark-cli failed."; return 1; } ;;
            *)      fail "No supported package manager detected -- install tshark manually."; return 1 ;;
        esac
    fi
    have tshark || { fail "tshark install reported success but still isn't on PATH."; return 1; }

    dumpcap_bin="$(command -v dumpcap 2>/dev/null || true)"
    if [ -z "$dumpcap_bin" ]; then
        warn "tshark installed but dumpcap not found on PATH -- live capture (tshark_capture) will need root until this is resolved."
        return 1
    fi
    if $SUDO setcap cap_net_raw,cap_net_admin+eip "$dumpcap_bin"; then
        ok "tshark installed, dumpcap granted cap_net_raw/cap_net_admin ($dumpcap_bin)"
    else
        warn "tshark installed, but setcap on dumpcap ($dumpcap_bin) failed -- tshark_capture will only work run as root until this is set manually: sudo setcap cap_net_raw,cap_net_admin+eip $dumpcap_bin"
        return 1
    fi
}

# --- AFL++ (dumb-mode fuzzing, agent/tools/native.py's afl_fuzz_start) --------------------------
# apt-only for now -- confirmed live: the apt afl++ package does NOT ship a working afl-qemu-trace
# binary (only a static libAFLQemuDriver.a), so QEMU mode (-Q, needed to fuzz a black-box binary
# with no source) isn't actually usable here; building it from source is a genuinely heavy, slow
# compile step this script deliberately does not attempt. afl_fuzz_start uses dumb/non-instrumented
# mode (-n) instead -- no coverage feedback, but works on any binary with nothing beyond afl-fuzz
# itself, an honest tradeoff for what's actually installable this way. No Darwin branch: AFL++'s
# own Homebrew formula has historically lagged/been unreliable -- see https://github.com/AFLplusplus/AFLplusplus
# for the manual macOS build steps if needed.
install_afl() {
    have afl-fuzz && { ok "AFL++ already installed ($(command -v afl-fuzz))"; return 0; }
    if [ "$(uname -s)" = "Darwin" ]; then
        warn "AFL++ has no automated macOS install here -- see https://github.com/AFLplusplus/AFLplusplus for manual build steps."
        return 1
    fi
    log "Installing AFL++ (dumb-mode fuzzing -- agent/tools/native.py's afl_fuzz_start)..."
    pkg_install afl++ || { warn "afl++ not available via $PKG_MANAGER -- install manually from https://github.com/AFLplusplus/AFLplusplus."; return 1; }
}

# --- .NET SDK + ilspycmd (.NET/C# decompilation, agent/tools/builders/ilspycmd.py) --------------
# ilspycmd is a `dotnet tool`, not a distro package -- needs the real SDK (not just the runtime)
# to install at all. Pinned to 9.1.0.7988, not left floating -- confirmed live, TWO real failure
# modes hit trying to find a working version: `dotnet tool install -g ilspycmd` with no version at
# all resolved to a genuinely broken NuGet package ("Settings file 'DotnetToolSettings.xml' was not
# found in the package"); the next version tried (8.2.0.7535) installed cleanly but targets the
# now-EOL .NET 6.0 runtime, which this script's own dotnet-sdk-8.0 doesn't provide and Ubuntu
# noble's apt repos no longer carry at all. 9.1.0.7988 is the first version confirmed live to both
# install cleanly and actually run against .NET 8.
install_dotnet_ilspycmd() {
    have ilspycmd && { ok "ilspycmd already installed ($(command -v ilspycmd))"; return 0; }
    log "Installing .NET SDK + ilspycmd (.NET/C# decompilation -- agent/tools/builders/ilspycmd.py)..."
    if ! have dotnet; then
        if [ "$(uname -s)" = "Darwin" ]; then
            have brew || { fail "Homebrew not found -- install it first (https://brew.sh), then re-run this script."; return 1; }
            brew install --cask dotnet-sdk || { fail "brew install --cask dotnet-sdk failed -- see output above."; return 1; }
        else
            pkg_install dotnet-sdk-8.0 || { warn "dotnet-sdk-8.0 not available via $PKG_MANAGER -- install manually from https://dotnet.microsoft.com/download, then re-run this script."; return 1; }
        fi
    fi
    if ! dotnet tool install -g ilspycmd --version 9.1.0.7988; then
        fail "dotnet tool install -g ilspycmd failed -- see output above."
        return 1
    fi
    # dotnet tools install to $HOME/.dotnet/tools -- same "don't trust a shell-profile PATH edit,
    # symlink into /usr/local/bin instead" reasoning install_jadx/install_heimdall already
    # established for their own non-apt install locations.
    if [ -f "$HOME/.dotnet/tools/ilspycmd" ]; then
        $SUDO ln -sf "$HOME/.dotnet/tools/ilspycmd" /usr/local/bin/ilspycmd
    fi
    have ilspycmd || warn "ilspycmd installed but still isn't found on PATH -- check $HOME/.dotnet/tools/ilspycmd exists and re-run this script."
}

# --- Foundry (forge/cast/anvil) + vendored forge-std (real, EXECUTED contract PoCs -- the dynamic
# complement to slither/mythril's static analysis, agent/tools/native.py's forge_poc_run) --------
# No distro package exists for Foundry on any of the three PKG_MANAGERs this script supports --
# vendor's own official installer only (curl | bash installs `foundryup`, which then installs the
# real forge/cast/anvil/chisel binaries). Installs to $HOME/.foundry/bin regardless of platform,
# symlinked into /usr/local/bin -- same "don't trust a shell-profile PATH edit" reasoning
# install_dotnet_ilspycmd/install_jadx above already established for their own non-apt locations.
install_foundry() {
    if have forge && have cast && have anvil; then
        ok "foundry (forge/cast/anvil) already installed ($(command -v forge))"
    else
        log "Installing Foundry (forge/cast/anvil -- agent/tools/native.py's forge_poc_run)..."
        if ! curl -fsSL $CURL_RETRY_OPTS https://foundry.paradigm.xyz | bash >/dev/null 2>&1; then
            fail "Foundry's own installer (foundry.paradigm.xyz) failed -- see https://getfoundry.sh for manual install steps."
            return 1
        fi
        if [ ! -x "$HOME/.foundry/bin/foundryup" ]; then
            fail "foundryup was not installed at $HOME/.foundry/bin/foundryup as expected -- see https://getfoundry.sh for manual install steps."
            return 1
        fi
        if ! "$HOME/.foundry/bin/foundryup"; then
            fail "foundryup failed to install forge/cast/anvil -- see output above."
            return 1
        fi
        for bin in forge cast anvil chisel; do
            [ -f "$HOME/.foundry/bin/$bin" ] && $SUDO ln -sf "$HOME/.foundry/bin/$bin" "/usr/local/bin/$bin"
        done
        have forge || { warn "forge installed but still isn't found on PATH -- check $HOME/.foundry/bin/forge exists and re-run this script."; return 1; }
    fi

    # Vendor forge-std ONCE here (real network access guaranteed at this install step) into a
    # shared scaffold every session's own forge_poc_run call reuses afterward via an absolute-path
    # remapping, never re-fetched per session -- see agent/tools/native.py's _foundry_scaffold_dir
    # for why this lives at $HOME/.foundry-asra-scaffold, not Documents/ASRA.
    scaffold_dir="$HOME/.foundry-asra-scaffold"
    if [ -f "$scaffold_dir/lib/forge-std/src/Test.sol" ]; then
        ok "forge-std already vendored at $scaffold_dir"
        return 0
    fi
    log "Vendoring forge-std into $scaffold_dir (forge_poc_run's shared Test-contract dependency)..."
    mkdir -p "$scaffold_dir"
    if ! (cd "$scaffold_dir" && forge init --no-git --force . >/dev/null 2>&1); then
        fail "forge init failed inside $scaffold_dir -- see output above."
        return 1
    fi
    if [ ! -f "$scaffold_dir/lib/forge-std/src/Test.sol" ]; then
        # forge init's own default template usually vendors forge-std already -- this is the
        # explicit fallback for whichever Foundry version/flag combination didn't do that on its own.
        if ! (cd "$scaffold_dir" && forge install foundry-rs/forge-std --no-git); then
            fail "forge install foundry-rs/forge-std failed inside $scaffold_dir -- see output above."
            return 1
        fi
    fi
    [ -f "$scaffold_dir/lib/forge-std/src/Test.sol" ] || { fail "forge-std still missing Test.sol after install -- see output above."; return 1; }
}

# --- playwright / chromium (headless-browser tools, agent/tools/browser_manager.py) -----------
# Unlike every other tool above, this isn't a standalone binary on PATH -- it's a pip package
# (requirements.txt, installed automatically into ./venv by run.sh) plus a separately-downloaded
# ~150MB Chromium build `playwright install` fetches. That download has to happen as the SAME
# user who'll later actually run ./run.sh, not as root/sudo -- Playwright caches it under that
# user's own $HOME/.cache/ms-playwright by default, so downloading it as root here would leave it
# invisible to the app's own runtime check (agent/tools/browser_manager.py's _chromium_installed)
# once the real server starts as a normal user. The OS-level shared libraries Chromium itself
# needs to actually launch headless (libnss3, libatk-bridge2.0-0, ...) DO need root, so this is
# deliberately split into two separate playwright CLI subcommands with two different privilege
# levels, not one `install --with-deps` call run entirely under sudo: `install chromium` (browser
# download, no sudo) then, apt-only, `install-deps chromium` (system libraries, $SUDO).
install_playwright() {
    playwright_version="$(grep -oP '(?<=^playwright==)\S+' requirements.txt)"
    if [ -z "$playwright_version" ]; then
        fail "No pinned 'playwright==X.Y.Z' line found in requirements.txt -- add one first."
        return 1
    fi

    log "Ensuring Playwright's Chromium (v${playwright_version}) is downloaded for the current user..."
    tmp_venv="$(mktemp -d)"
    if ! python3 -m venv "$tmp_venv" >/dev/null 2>&1; then
        fail "Could not create a temporary venv to run the playwright CLI -- see install_python_prereqs above for python3-venv, then re-run."
        rm -rf "$tmp_venv"
        return 1
    fi
    if ! "$tmp_venv/bin/pip" install -q "playwright==$playwright_version"; then
        fail "pip install playwright==$playwright_version failed."
        rm -rf "$tmp_venv"
        return 1
    fi
    # No $SUDO here on purpose -- see the function's own comment above for why the browser
    # download specifically must run as the real invoking user, not root.
    if ! "$tmp_venv/bin/python" -m playwright install chromium; then
        fail "playwright install chromium failed -- see output above."
        rm -rf "$tmp_venv"
        return 1
    fi
    case "$PKG_MANAGER" in
        apt)
            log "Installing Chromium's OS-level shared-library dependencies (apt, needs sudo)..."
            if ! $SUDO "$tmp_venv/bin/python" -m playwright install-deps chromium; then
                fail "playwright install-deps chromium failed -- see output above."
                rm -rf "$tmp_venv"
                return 1
            fi
            ;;
        dnf|pacman)
            warn "playwright install-deps only automates apt -- Chromium's own browser build downloaded fine, but its OS-level shared-library dependencies on $PKG_MANAGER aren't installed automatically. If headless Chromium fails to launch, see https://playwright.dev/python/docs/browsers#install-system-dependencies for the manual package list."
            ;;
        *)
            warn "No supported package manager detected -- Chromium's own browser build downloaded, but its OS-level shared-library dependencies were not installed. See https://playwright.dev/python/docs/browsers#install-system-dependencies if headless Chromium fails to launch."
            ;;
    esac
    # Verified here, with the temp venv's own python (has playwright importable) -- not in the
    # final summary loop below, which by then has nothing left to check WITH: this venv is
    # deleted the moment this function returns, and bare system python3 was never given playwright
    # at all (only ever installed into this throwaway venv). Deliberately does NOT import
    # agent.tools.browser_manager itself (confirmed live: that import triggers Python's normal
    # package-init machinery for the WHOLE agent.tools package first -- agent/tools/__init__.py's
    # own long import chain needs fastapi/openai/httpx/... none of which this minimal
    # playwright-only temp venv has, so it failed with an ImportError every real run). Reimplements
    # _chromium_installed()'s own small, stable check directly instead -- same class of deliberate
    # duplication as browser_manager.py's own _loopback_or_link_local (a shared helper isn't worth
    # the churn for logic this small and this unlikely to change).
    if "$tmp_venv/bin/python" -c "
import os
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    ok = os.path.isfile(p.chromium.executable_path)
raise SystemExit(0 if ok else 1)
" 2>/dev/null; then
        PLAYWRIGHT_CHROMIUM_INSTALLED=1
    else
        PLAYWRIGHT_CHROMIUM_INSTALLED=0
        fail "chromium (playwright) -- installed but not detected by the app's own check; see https://playwright.dev/python/docs/browsers for troubleshooting"
    fi
    rm -rf "$tmp_venv"
}

# --- qiling (cross-platform binary emulation -- agent/tools/builders/qiling.py, the replacement for
# the removed Windows-only cdb tool) --------------------------------------------------------------
# Two halves: the `qiling` pip package (installed into ASRA's OWN venv -- the same interpreter
# qiling_runner.py runs under, so `import qiling` there is exactly what the tool's availability check
# consults), and a rootfs collection (per-OS system libraries it emulates against) cloned once to
# /opt/qiling-rootfs, which qiling_runner.py defaults to and auto-indexes per target arch.
# Not in requirements.txt on purpose (its deps pin an older wcwidth + pull a heavy TUI chain), so a
# run.sh venv rebuild drops it -- re-running this (the Install button) restores it; present halves
# are skipped.
QILING_ROOTFS_DIR="/opt/qiling-rootfs"
install_qiling() {
    venv_py="$SCRIPT_DIR/venv/bin/python"
    if [ ! -x "$venv_py" ]; then
        warn "qiling: ASRA venv not found at $SCRIPT_DIR/venv — run ./run.sh once to create it, then re-run this script."
    elif "$venv_py" -c "import qiling" >/dev/null 2>&1; then
        ok "qiling already installed in ASRA's venv"
    else
        log "Installing qiling into ASRA's venv (cross-platform binary emulation — agent/tools/builders/qiling.py)..."
        "$venv_py" -m pip install qiling || fail "pip install qiling failed."
    fi

    if [ -d "$QILING_ROOTFS_DIR/x8664_linux" ]; then
        ok "Qiling rootfs already present at $QILING_ROOTFS_DIR"
    else
        log "Cloning the Qiling rootfs to $QILING_ROOTFS_DIR (~520MB — per-OS system libraries qiling emulates against)..."
        if $SUDO git clone --depth 1 https://github.com/qilingframework/rootfs.git "$QILING_ROOTFS_DIR"; then
            # Windows PE emulation additionally needs REAL Windows DLLs, which the free rootfs can't
            # ship for licensing reasons -- Linux ELF works out of the box; for a Windows PE, drop the
            # target OS's DLLs into $QILING_ROOTFS_DIR/<arch>_windows/Windows/System32 yourself.
            ok "Qiling rootfs cloned (Linux ELF ready; Windows PE additionally needs real DLLs added — licensing)"
        else
            warn "Could not clone the Qiling rootfs — qiling is installed but an actual run needs a rootfs (set QILING_ROOTFS, or see github.com/qilingframework/rootfs)."
        fi
    fi
}

log ""
log "${BOLD}ASRA — installing the core tool arsenal (nmap, nuclei, dalfox, msfconsole, sqlmap, nikto, interactsh-client, whatweb, wpscan, ffuf, subfinder, hydra, chromium/playwright, bubblewrap, dnsutils) plus the Reverse Engineering toolset (radare2/r2ghidra/radiff2, gdb, strace, wine, heimdall, upx, osv-scanner, trufflehog, apktool, jadx, binwalk, foundry -- frida-tools/pwntools install via requirements.txt, not this script)${RESET}"
log "Package manager detected: ${PKG_MANAGER:-none}"
log ""

install_dnsutils
install_nmap
install_sqlmap
install_nikto
install_whatweb
install_wpscan
install_nuclei
install_dalfox
install_interactsh_client
install_ffuf
install_ffuf_wordlist
install_subfinder
install_amass
install_subdomain_wordlist
install_httpx
install_hydra
install_metasploit
install_metasploit_wordlists
install_large_wordlists
install_playwright
install_bubblewrap
install_radare2
install_r2ghidra
install_gdb
install_strace
install_wine
install_heimdall
install_upx
install_osv_scanner
install_trufflehog
install_apktool
install_jadx
install_binwalk
install_afl
install_scanmem
install_tshark
install_dotnet_ilspycmd
install_foundry
install_qiling

log ""
log "${BOLD}Summary${RESET} — this is exactly what ASRA's own tool registry health-check will see:"
missing=0
for name in nmap nuclei dalfox msfconsole sqlmap nikto interactsh-client whatweb wpscan ffuf subfinder amass httpx hydra radare2 gdb strace wine heimdall upx osv-scanner trufflehog apktool jadx binwalk radiff2 afl-fuzz scanmem tshark ilspycmd forge cast anvil; do
    if [ "$name" = "httpx" ]; then
        # httpx alone isn't a safe presence check here -- see install_httpx's own comment for why
        # (a broken, identically-named Python package can shadow the real one on PATH).
        if have httpx && httpx -version >/dev/null 2>&1; then
            ok "httpx -> $(command -v httpx)"
        else
            fail "httpx -> not on PATH, or a broken/non-ProjectDiscovery binary is shadowing it"
            missing=$((missing + 1))
        fi
    elif have "$name"; then
        ok "$name -> $(command -v "$name")"
    else
        fail "$name -> not on PATH"
        missing=$((missing + 1))
    fi
done
# Not a binary on PATH -- install_playwright already ran the real check (the exact
# _chromium_installed() agent/tools/runner.py's tool_is_installed() calls at real runtime) using
# its own temp venv before deleting it; that venv no longer exists by this point in the script, so
# this reads the result install_playwright recorded instead of re-deriving it with nothing left to
# check with.
if [ "${PLAYWRIGHT_CHROMIUM_INSTALLED:-0}" = "1" ]; then
    ok "chromium (playwright) -> installed"
else
    fail "chromium (playwright) -> not installed (see install_playwright's own output above)"
    missing=$((missing + 1))
fi

# qiling is a venv Python package (agent/tools/builders/qiling.py), not a PATH binary -- the same
# `import qiling` check its own tool availability uses, so this summary line matches the app's view.
if [ -x "$SCRIPT_DIR/venv/bin/python" ] && "$SCRIPT_DIR/venv/bin/python" -c "import qiling" >/dev/null 2>&1; then
    ok "qiling -> importable in ASRA's venv"
else
    fail "qiling -> not importable in ASRA's venv (see install_qiling's own output above)"
    missing=$((missing + 1))
fi
# Not counted in $missing -- unlike the tools above, custom_exploit_run works fine without it
# (agent/tools/sandbox.py falls back to running unsandboxed, same behavior as before this existed),
# just with less isolation. A real hardening improvement, not a required core tool.
if have bwrap; then
    ok "bwrap -> $(command -v bwrap) (custom_exploit_run's scripts run sandboxed)"
else
    warn "bwrap -> not on PATH — custom_exploit_run will run its own scripts unsandboxed (see install_bubblewrap's own output above)"
fi
# Same "hardening improvement, not a required core tool" treatment as bwrap above -- without this,
# a GUI-capable program a sandboxed script spawns (wine, confirmed) shows a real window on the
# operator's own desktop via WSLg instead of running offscreen (agent/tools/sandbox.py's own
# run_sandboxed degrades gracefully either way, just with less isolation).
if have Xvfb; then
    ok "Xvfb -> $(command -v Xvfb) (wine and other GUI-capable sandboxed programs run offscreen)"
else
    warn "Xvfb -> not on PATH — wine (and any other GUI-capable program a sandboxed script spawns) will show a real window on the desktop (see install_wine's own output above)"
fi
# Not counted in $missing -- same reasoning as bwrap/r2ghidra: radare2 itself (checked in the main
# loop above) already covers most of agent/tools/builders/radare2.py's own analysis surface;
# decompile_function specifically needs this plugin on top, everything else works without it.
# Checked the SAME way install_r2ghidra() itself does (the system plugin dir, not `r2pm -l`, which
# only ever reflects THIS invoking user's own per-user install -- see that function's own comment
# for the real, confirmed-live gap this closes).
_r2ghidra_summary_version="$(have radare2 && r2 -v 2>/dev/null | head -1 | awk '{print $2}')"
if [ -n "$_r2ghidra_summary_version" ] && [ -f "/usr/local/lib/radare2/${_r2ghidra_summary_version}/core_ghidra.so" ]; then
    ok "r2ghidra -> installed system-wide (radare2's decompile_function analysis is available)"
else
    warn "r2ghidra -> not installed — radare2's decompile_function analysis will fail until this is retried (see install_r2ghidra's own output above)"
fi
# Not counted in $missing -- forge itself (checked in the main loop above) is the real required
# binary; the vendored scaffold is forge_poc_run's own dependency on top, checked separately since
# it's a file on disk, not a PATH binary (agent/tools/native.py's _foundry_scaffold_dir).
if [ -f "$HOME/.foundry-asra-scaffold/lib/forge-std/src/Test.sol" ]; then
    ok "forge-std -> vendored at $HOME/.foundry-asra-scaffold (forge_poc_run can compile real PoCs)"
else
    warn "forge-std -> not vendored — forge_poc_run will fail until this is retried (see install_foundry's own output above)"
fi
# Not counted in $missing -- same reasoning as bwrap above: custom_exploit_run scripts fall back to
# dnspython/DNS-over-HTTPS just fine without dig/nslookup/host, just with a slower, more roundabout
# path to get there (see install_dnsutils's own comment for the real incident this avoids).
if have dig; then
    ok "dig/nslookup/host -> $(command -v dig) (custom_exploit_run scripts can shell out for DNS lookups directly)"
else
    warn "dig/nslookup/host -> not on PATH — custom_exploit_run scripts will need dnspython or DNS-over-HTTPS for DNS lookups instead (see install_dnsutils's own output above)"
fi

# python3 IS counted in $missing -- unlike perl/ruby below, ./run.sh itself cannot even start
# without it (install_python_prereqs above already tried to fix this; this is just the final,
# visible confirmation it actually worked). perl/ruby are each only needed by a couple of tools
# above (nikto, whatweb/wpscan) which already warn loudly on their own if their own interpreter
# turned out to be missing -- these two lines exist purely so a human scanning this final summary
# doesn't have to scroll back up to find those warnings, not because anything new is being checked.
if have python3; then
    ok "python3 -> $(command -v python3) (required by ./run.sh itself)"
else
    fail "python3 -> not on PATH — ./run.sh cannot start without it"
    missing=$((missing + 1))
fi
if have perl; then
    ok "perl -> $(command -v perl) (needed by nikto)"
else
    warn "perl -> not on PATH — nikto will fail to run until it's installed (see install_nikto's own output above)"
fi
if have ruby; then
    ok "ruby -> $(command -v ruby) (needed by whatweb, wpscan)"
else
    warn "ruby -> not on PATH — whatweb/wpscan will fail to run until it's installed (see install_whatweb's own output above)"
fi

log ""
if [ "$missing" -eq 0 ]; then
    log "All core tools are ready. Next: ./run.sh (or run.bat from Windows) to start ASRA — it auto-discovers whatever is on PATH now, no config changes needed."
    exit 0
else
    warn "$missing core tool(s) still missing — see the [FAIL]/[WARN] lines above for why, then re-run this script (already-installed tools are skipped, so re-running is cheap)."
    exit 1
fi
