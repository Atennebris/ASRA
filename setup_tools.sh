#!/bin/bash
# Installs the five core binaries ASRA's tool registry expects on PATH: nmap, nuclei, msfconsole
# (Metasploit), sqlmap, nikto. Health-checking in agent/tools/runner.py is just shutil.which — so
# "installed" here means exactly "installed", nothing project-specific needed after this runs.
#
# Safe to re-run: every install_* function checks whether its binary already exists before
# touching anything, so running this again on an already-provisioned machine is just a status
# report, not a reinstall.
#
# Works on any Debian/Ubuntu (apt), Fedora/RHEL (dnf), or Arch (pacman) based distro, inside
# WSL2 or on native Linux — detects the package manager instead of assuming one, same reasoning
# README already applies to the WSL2 distro choice itself. Not for macOS (see README's Homebrew
# section for that — different package manager, different install story entirely).
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

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
elif have sudo; then
    SUDO="sudo"
else
    fail "Not root and no sudo on PATH — re-run this script as root, or install sudo first."
    exit 1
fi

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

# --- nuclei -------------------------------------------------------------------------------------
install_nuclei() {
    have nuclei && { ok "nuclei already installed ($(command -v nuclei))"; return 0; }
    log "Installing nuclei (no distro packages this one — always from the official GitHub release)..."
    case "$(uname -m)" in
        x86_64)        arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *)             fail "Unsupported CPU architecture for nuclei: $(uname -m) — install manually from https://github.com/projectdiscovery/nuclei/releases"; return 1 ;;
    esac
    version="$(curl -fsSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep -oP '"tag_name": "v\K[^"]+')"
    if [ -z "$version" ]; then
        fail "Could not resolve the latest nuclei release (GitHub API unreachable or rate-limited) — install manually."
        return 1
    fi
    tmp_dir="$(mktemp -d)"
    if ! curl -fsSL -o "$tmp_dir/nuclei.zip" "https://github.com/projectdiscovery/nuclei/releases/download/v${version}/nuclei_${version}_linux_${arch}.zip"; then
        fail "Could not download nuclei v${version} for linux_${arch} — install manually."
        rm -rf "$tmp_dir"
        return 1
    fi
    unzip -oq "$tmp_dir/nuclei.zip" -d "$tmp_dir" nuclei
    $SUDO install -m 0755 "$tmp_dir/nuclei" /usr/local/bin/nuclei
    rm -rf "$tmp_dir"
}

# --- metasploit ---------------------------------------------------------------------------------
install_metasploit() {
    have msfconsole && { ok "msfconsole already installed ($(command -v msfconsole))"; return 0; }
    case "$PKG_MANAGER" in
        apt|dnf)
            log "Installing Metasploit Framework via the official Rapid7 installer (large download, be patient)..."
            tmp_installer="$(mktemp)"
            if ! curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb -o "$tmp_installer"; then
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

log ""
log "${BOLD}ASRA — installing the core tool arsenal (nmap, nuclei, msfconsole, sqlmap, nikto)${RESET}"
log "Package manager detected: ${PKG_MANAGER:-none}"
log ""

install_nmap
install_sqlmap
install_nikto
install_nuclei
install_metasploit

log ""
log "${BOLD}Summary${RESET} — this is exactly what ASRA's own tool registry health-check will see:"
missing=0
for name in nmap nuclei msfconsole sqlmap nikto; do
    if have "$name"; then
        ok "$name -> $(command -v "$name")"
    else
        fail "$name -> not on PATH"
        missing=$((missing + 1))
    fi
done

log ""
if [ "$missing" -eq 0 ]; then
    log "All 5 core tools are ready. Next: ./run.sh (or run.bat from Windows) to start ASRA — it auto-discovers whatever is on PATH now, no config changes needed."
    exit 0
else
    warn "$missing core tool(s) still missing — see the [FAIL]/[WARN] lines above for why, then re-run this script (already-installed tools are skipped, so re-running is cheap)."
    exit 1
fi
