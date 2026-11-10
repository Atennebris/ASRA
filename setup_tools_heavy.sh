#!/bin/bash
# Installs the "heavy"/extended arsenal -- substantially larger or slower-to-build tools
# deliberately kept OUT of setup_tools.sh's fast base install: headless Ghidra (+ the JDK it
# needs), pwntools/pwndbg/pyelftools/unicorn (crash/exploit triage, cheap pip packages but grouped
# here since they belong with the rest of this "heavier RE arsenal" story), sigrok-cli (logic-signal
# capture -- ASRA has nothing like it today), unblob (modern firmware extractor, complements
# binwalk rather than replacing it), and adb/platform-tools (Android emulator/live-device access) +
# WABT (WebAssembly toolkit, wat2wasm/wasm2c/wasm-objdump -- needed once ASRA has a real WASM
# analysis tool).
#
# What this deliberately does NOT install, and why: IDA Pro / JEB / Hopper (all proprietary,
# require a purchased license to unlock full functionality -- a time/feature-limited demo isn't a
# real substitute for one). This arsenal already has free, fully open-source tools covering the
# exact same disassembly/decompilation job at equal or greater capability: Ghidra below (NSA,
# genuinely open source, includes a full decompiler Hopper doesn't have at all) and radare2
# (agent/tools/builders/radare2.py, already a registered tool) -- so a paid tool's demo build adds
# no real capability ASRA doesn't already have, unlike Ghidra/pwndbg/sigrok-cli/unblob/adb/WABT
# below, each of which fills a genuine gap.
#
# Same conventions as setup_tools.sh (duplicated here, not sourced from it -- these are two
# independent, independently-invokable entry points; sourcing one from the other would also run
# its own full install sequence unless carefully guarded, more fragile than ~30 duplicated lines of
# shell idiom): safe to re-run (every install_* checks first), detects the package manager rather
# than assuming one. Covers macOS too (Homebrew branches on install_jdk_for_ghidra/
# install_sigrok_cli/install_adb/install_wabt, same "explicit Darwin branch, not folded into the
# shared apt/dnf/pacman machinery" pattern setup_tools.sh's own install_radare2/install_gdb/
# install_wine already use) -- install_pwntools_stack/install_unblob are already plain pip installs
# into ASRA's own venv, no package-manager branch needed on any OS; install_pwndbg only needs gdb
# (already covered) plus git/pwndbg's own setup.sh, neither PKG_MANAGER-gated either.
#
# Everything that writes outside a /tmp scratch dir goes to a FIXED, ASRA-controlled absolute path
# (/opt/<tool>), never a bare $HOME-relative one, because $HOME resolves differently depending on
# whether the operator's last launch had ASRA_RUN_AS_ROOT on (root's $HOME, /root) or off (the
# normal WSL user's $HOME) -- a real,
# previously-confirmed bug (agent/tools/nuclei_template_packs.py) when state landed at a bare
# $HOME-relative path instead. The one unavoidable exception is pwndbg's OWN installer appending a
# source line to ~/.gdbinit (a per-user GDB config file by GDB's own design, not something this
# script controls) -- see install_pwndbg's own comment for the resulting caveat.
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

CURL_RETRY_OPTS="--retry 3 --retry-delay 2 --retry-connrefused"

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
elif have sudo; then
    SUDO="sudo"
else
    fail "Not root and no sudo on PATH — re-run this script as root, or install sudo first."
    exit 1
fi

# This script's own directory == the repo root -- used to reach ASRA's ./venv for the pip-only
# installs below (pwntools/pyelftools/unicorn/unblob), same reasoning setup_tools.sh's own
# install_qiling already relies on.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if have apt-get; then
    PKG_MANAGER="apt"
elif have dnf; then
    PKG_MANAGER="dnf"
elif have pacman; then
    PKG_MANAGER="pacman"
else
    warn "No supported package manager found (apt-get/dnf/pacman) — package-based installs below will be skipped; GitHub-release based ones (Ghidra) will still work."
    PKG_MANAGER=""
fi

_pkg_index_updated=0
pkg_update_once() {
    [ "$_pkg_index_updated" -eq 1 ] && return 0
    case "$PKG_MANAGER" in
        apt)    $SUDO apt-get update -y ;;
        pacman) $SUDO pacman -Sy --noconfirm ;;
        *)      : ;;
    esac
    _pkg_index_updated=1
}

pkg_install() {
    [ -z "$PKG_MANAGER" ] && return 1
    pkg_update_once
    case "$PKG_MANAGER" in
        apt)    $SUDO apt-get install -y "$@" ;;
        dnf)    $SUDO dnf install -y "$@" ;;
        pacman) $SUDO pacman -S --noconfirm --needed "$@" ;;
    esac
}

venv_py() {
    local candidate="$SCRIPT_DIR/venv/bin/python"
    [ -x "$candidate" ] && { printf '%s' "$candidate"; return 0; }
    return 1
}

# --- Ghidra (headless decompiler, for a future agent/tools/builders/ghidra.py) + the JDK it
# requires ----------------------------------------------------------------------------------------
# A fixed, ASRA-controlled path, not $HOME-relative (see this file's own header comment) --
# overridable (e.g. an operator-chosen drive with more room) without editing this script.
GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-/opt/ghidra}"
# Ghidra's own minimum JDK requirement has moved with its own release line (JDK 17 for 11.0.x, 21
# for 11.3.x/12.1.x, reportedly 25 for some 12.2.x builds per third-party reports at the time this
# was written) -- rather than hardcode a specific JDK version that the CURRENTLY-latest Ghidra
# release may already have outgrown by the time this runs, this installs the distro's own current
# default JDK meta-package and verifies compatibility by actually trying analyzeHeadless afterward
# (see install_ghidra). Override if that default turns out to be insufficient for whatever Ghidra
# version is latest when this runs.
GHIDRA_JDK_PACKAGE="${GHIDRA_JDK_PACKAGE:-}"
install_jdk_for_ghidra() {
    # Deliberately checks for javac, not just java -- setup_tools.sh's own install_jre (apktool/
    # jadx's prerequisite) installs a JRE-only package (default-jre-headless et al) that provides
    # `java` but no compiler at all. A bare `have java` here would treat that JRE as "already have
    # a JDK" and skip this step entirely -- Ghidra's Script Manager needs a real javac to compile
    # scripts at runtime, so a JRE-only `java` on PATH is not the same thing as what this function
    # promises to install, even though both scripts can genuinely run on the same machine.
    if have javac; then
        ok "A JDK (with javac) is already on PATH ($(command -v javac)) -- trying it as-is; install_ghidra will say clearly if it turns out too old."
        return 0
    fi
    if have java; then
        warn "java is on PATH ($(command -v java)) but javac is not -- that's a JRE-only install (e.g. from setup_tools.sh's own install_jre for apktool/jadx), not sufficient for Ghidra's Script Manager. Installing a real JDK..."
    else
        log "No Java on PATH -- installing a JDK for Ghidra..."
    fi
    if [ "$(uname -s)" = "Darwin" ]; then
        have brew || { fail "Homebrew not found -- install it first (https://brew.sh), then re-run this script."; return 1; }
        local formula="${GHIDRA_JDK_PACKAGE:-openjdk}"
        brew install "$formula" || { fail "brew install $formula failed -- see output above."; return 1; }
        # Homebrew's openjdk formula doesn't symlink itself onto PATH by default (keg-only, to
        # avoid clobbering the system Java) -- confirmed Homebrew's own standard behavior, not
        # guessed. have javac below catches it if this guess at the keg path is wrong for the
        # installed version; GHIDRA_JDK_PACKAGE lets the operator override the formula entirely.
        local brew_prefix
        brew_prefix="$(brew --prefix "$formula" 2>/dev/null)"
        [ -n "$brew_prefix" ] && export PATH="$brew_prefix/bin:$PATH"
        have javac || { fail "brew install $formula reported success but javac still isn't on PATH (checked $brew_prefix/bin) -- set GHIDRA_JDK_PACKAGE to a specific formula (e.g. openjdk@21) and re-run."; return 1; }
        return 0
    fi
    local package="$GHIDRA_JDK_PACKAGE"
    if [ -z "$package" ]; then
        case "$PKG_MANAGER" in
            # default-jdk-headless (confirmed live, Ubuntu 24.04) depends only on
            # default-jre-headless + openjdk-*-jdk-headless -- unlike plain `default-jdk`, which
            # additionally pulls in the full, non-headless `default-jre` (X11/AWT/Swing libs) even
            # though analyzeHeadless never touches a GUI. Builds cleanly on top of whatever JRE
            # setup_tools.sh's own install_jre already installed for apktool/jadx, instead of
            # adding a second, heavier JRE flavor alongside it.
            apt)    package="default-jdk-headless" ;;
            dnf)    package="java-latest-openjdk-devel" ;;
            pacman) package="jdk-openjdk" ;;
        esac
    fi
    [ -z "$package" ] && { fail "No supported package manager detected and no javac on PATH -- install a JDK 21+ manually, then re-run this script."; return 1; }
    pkg_install "$package" || { fail "Installing $package failed -- install a JDK 21+ manually, then re-run this script."; return 1; }
    # Checks javac specifically, not java -- in the exact scenario this function exists for (a
    # JRE-only `java` already on PATH from install_jre), `java` was already true before this
    # install ran, so checking it here would report success even if the package somehow didn't
    # actually bring a compiler (e.g. a distro renames/splits its JDK package unexpectedly).
    have javac || { fail "JDK install ($package) reported success but javac still isn't on PATH."; return 1; }
}

install_ghidra() {
    if [ -x "$GHIDRA_INSTALL_DIR/ghidraRun" ]; then
        ok "Ghidra already installed at $GHIDRA_INSTALL_DIR"
        return 0
    fi
    install_jdk_for_ghidra || { warn "Skipping Ghidra -- no usable JDK."; return 1; }
    log "Installing Ghidra (headless decompiler -- agent/tools/builders/ghidra.py) to $GHIDRA_INSTALL_DIR..."
    local download_url
    download_url="$(curl -fsSL $CURL_RETRY_OPTS https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest | grep -oP '"browser_download_url":\s*"\K[^"]+\.zip' | head -1)"
    if [ -z "$download_url" ]; then
        fail "Could not resolve the latest Ghidra release asset (GitHub API unreachable or rate-limited) — install manually from https://github.com/NationalSecurityAgency/ghidra/releases."
        return 1
    fi
    local tmp_dir
    tmp_dir="$(mktemp -d)"
    if ! curl -fsSL $CURL_RETRY_OPTS -o "$tmp_dir/ghidra.zip" "$download_url"; then
        fail "Could not download Ghidra from $download_url — install manually."
        rm -rf "$tmp_dir"
        return 1
    fi
    unzip -oq "$tmp_dir/ghidra.zip" -d "$tmp_dir"
    local extracted_dir
    extracted_dir="$(find "$tmp_dir" -maxdepth 1 -mindepth 1 -type d -name 'ghidra_*' | head -1)"
    if [ -z "$extracted_dir" ]; then
        fail "Ghidra zip didn't contain the expected ghidra_* directory -- install manually."
        rm -rf "$tmp_dir"
        return 1
    fi
    $SUDO rm -rf "$GHIDRA_INSTALL_DIR"
    $SUDO mkdir -p "$(dirname "$GHIDRA_INSTALL_DIR")"
    $SUDO mv "$extracted_dir" "$GHIDRA_INSTALL_DIR"
    $SUDO chmod +x "$GHIDRA_INSTALL_DIR/ghidraRun" "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
    # Symlinked onto PATH under its real tool name -- same convention install_jadx/install_heimdall
    # already use, so a future ToolSpec for it can register executable="analyzeHeadless" and be
    # found exactly like every other external tool (shutil.which), no Ghidra-specific lookup.
    $SUDO ln -sf "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" /usr/local/bin/analyzeHeadless
    rm -rf "$tmp_dir"
    _verify_analyze_headless
}

# Confirmed live (2026-11-09): the current latest Ghidra release (12.2) outright REJECTS JDK 21
# ("WARNING: JAVA_HOME environment specifies unsupported java version") even though 21 is a
# current LTS and is exactly what install_jdk_for_ghidra's own apt default (default-jdk-headless)
# installs -- it needs JDK 25 specifically. This isn't a one-off fluke to shrug off: this file's
# own GHIDRA_JDK_PACKAGE comment already flagged version drift as likely (17 for 11.0.x, 21 for
# 11.3.x/12.1.x, "reportedly 25 for some 12.2.x builds") before this confirmed it directly. Rather
# than hardcode "25" as install_jdk_for_ghidra's own upfront choice (right today, certain to go
# stale again the next time Ghidra bumps its own requirement), this one retry closes exactly the
# gap just found live -- a genuinely newer Ghidra needing something newer still falls through to
# the manual GHIDRA_JDK_PACKAGE override below, same as before; this isn't a general JDK-version
# solver, just a fix for the one real, confirmed mismatch.
_verify_analyze_headless() {
    if ! have analyzeHeadless; then
        fail "analyzeHeadless not found on PATH after install."
        return 1
    fi
    local output
    output="$(analyzeHeadless 2>&1)"
    if printf '%s' "$output" | grep -qi "usage"; then
        ok "Ghidra installed at $GHIDRA_INSTALL_DIR, analyzeHeadless on PATH"
        return 0
    fi
    # Deliberately not gated on a specific error-message substring (e.g. "unsupported java
    # version") -- confirmed live that the exact wording differs depending on whether JAVA_HOME
    # happens to be set ("WARNING: JAVA_HOME environment specifies unsupported java version") or
    # not (falls straight to "ERROR: Unable to prompt user for JDK path, no TTY detected" with no
    # version-specific text at all) -- any failure here, with the platform's own default JDK choice
    # and no explicit override, is worth one retry with a confirmed-newer candidate.
    if [ -z "${GHIDRA_JDK_PACKAGE:-}" ]; then
        if [ "$PKG_MANAGER" = "apt" ]; then
            warn "analyzeHeadless rejected the installed JDK as unsupported -- retrying with openjdk-25-jdk-headless (confirmed needed by the current Ghidra release)..."
            if pkg_install openjdk-25-jdk-headless; then
                output="$(analyzeHeadless 2>&1)"
                if printf '%s' "$output" | grep -qi "usage"; then
                    ok "Ghidra installed at $GHIDRA_INSTALL_DIR, analyzeHeadless on PATH (needed JDK 25, not the distro default)"
                    return 0
                fi
            fi
        elif [ "$(uname -s)" = "Darwin" ] && have brew; then
            warn "analyzeHeadless rejected the installed JDK as unsupported -- retrying with openjdk@25 (confirmed needed by the current Ghidra release)..."
            if brew install openjdk@25; then
                local brew_prefix
                brew_prefix="$(brew --prefix openjdk@25 2>/dev/null)"
                [ -n "$brew_prefix" ] && export PATH="$brew_prefix/bin:$PATH"
                output="$(analyzeHeadless 2>&1)"
                if printf '%s' "$output" | grep -qi "usage"; then
                    ok "Ghidra installed at $GHIDRA_INSTALL_DIR, analyzeHeadless on PATH (needed openjdk@25, not the default openjdk formula)"
                    return 0
                fi
            fi
        fi
    fi
    warn "Ghidra installed at $GHIDRA_INSTALL_DIR, but analyzeHeadless still didn't run cleanly -- set GHIDRA_JDK_PACKAGE to a newer JDK package and re-run. Raw output:"
    log "$output"
    return 1
}

# --- pwntools / pyelftools / unicorn (crash/exploit-primitive scripting + ELF parsing + CPU
# emulation) -- pure pip packages into ASRA's own venv, same pattern as setup_tools.sh's own
# install_qiling. ----------------------------------------------------------------------------------
install_pwntools_stack() {
    local py
    py="$(venv_py)" || { warn "pwntools/pyelftools/unicorn: ASRA venv not found at $SCRIPT_DIR/venv — run ./run.sh once to create it, then re-run this script."; return 1; }
    local missing=()
    "$py" -c "import pwn" >/dev/null 2>&1 || missing+=("pwntools")
    "$py" -c "import elftools" >/dev/null 2>&1 || missing+=("pyelftools")
    "$py" -c "import unicorn" >/dev/null 2>&1 || missing+=("unicorn")
    if [ "${#missing[@]}" -eq 0 ]; then
        ok "pwntools, pyelftools, unicorn already installed in ASRA's venv"
        return 0
    fi
    log "Installing ${missing[*]} into ASRA's venv (crash/exploit-primitive triage -- agent/tools/builders/pwndbg.py)..."
    "$py" -m pip install "${missing[@]}" || { fail "pip install ${missing[*]} failed."; return 1; }
}

# --- pwndbg (GDB plugin -- structured crash/replay triage, same crash-triage story as pwntools
# above). Installed to a fixed /opt path (not $HOME/pwndbg) for the code itself -- but pwndbg's own
# setup.sh additionally appends a `source` line to the CURRENT invoking user's ~/.gdbinit, which is
# unavoidably $HOME-relative (that's how GDB itself discovers per-user config, not a choice this
# script makes).
# Known, documented limitation this leaves: run this once as root (ASRA_RUN_AS_ROOT=true) and once
# as the normal WSL user if you switch between launch modes and need pwndbg active in both --
# running this script again is cheap and idempotent either way (see the gdbinit grep check below).
PWNDBG_INSTALL_DIR="${PWNDBG_INSTALL_DIR:-/opt/pwndbg}"
install_pwndbg() {
    if grep -q "pwndbg" "$HOME/.gdbinit" 2>/dev/null; then
        ok "pwndbg already wired into $HOME/.gdbinit"
        return 0
    fi
    have gdb || { warn "pwndbg needs gdb (setup_tools.sh's own install_gdb) -- install that first, then re-run this script."; return 1; }
    log "Installing pwndbg (structured GDB crash/replay triage -- agent/tools/builders/pwndbg.py) to $PWNDBG_INSTALL_DIR..."
    if [ ! -d "$PWNDBG_INSTALL_DIR" ]; then
        $SUDO mkdir -p "$(dirname "$PWNDBG_INSTALL_DIR")"
        $SUDO git clone --depth 1 https://github.com/pwndbg/pwndbg "$PWNDBG_INSTALL_DIR" || { fail "git clone pwndbg failed."; return 1; }
        $SUDO chown -R "$(id -u):$(id -g)" "$PWNDBG_INSTALL_DIR"
    fi
    ( cd "$PWNDBG_INSTALL_DIR" && ./setup.sh ) || { fail "pwndbg's own setup.sh failed -- see its output above."; return 1; }
    grep -q "pwndbg" "$HOME/.gdbinit" 2>/dev/null || { warn "pwndbg's setup.sh ran but didn't register in $HOME/.gdbinit -- check its own output above."; return 1; }
    ok "pwndbg installed and wired into $HOME/.gdbinit"
}

# --- sigrok-cli (logic-signal capture/analysis -- ASRA has no equivalent today) -----------------
install_sigrok_cli() {
    have sigrok-cli && { ok "sigrok-cli already installed ($(command -v sigrok-cli))"; return 0; }
    log "Installing sigrok-cli (logic-signal capture/analysis)..."
    if [ "$(uname -s)" = "Darwin" ]; then
        have brew || { fail "Homebrew not found -- install it first (https://brew.sh), then re-run this script."; return 1; }
        brew install sigrok-cli || { fail "brew install sigrok-cli failed -- see output above."; return 1; }
        return 0
    fi
    pkg_install sigrok-cli || { warn "sigrok-cli not available via $PKG_MANAGER -- install manually from https://sigrok.org/wiki/Downloads."; return 1; }
}

# --- unblob (modern firmware extractor, complements -- doesn't replace -- binwalk) --------------
install_unblob() {
    local py
    py="$(venv_py)" || { warn "unblob: ASRA venv not found at $SCRIPT_DIR/venv — run ./run.sh once to create it, then re-run this script."; return 1; }
    "$py" -c "import unblob" >/dev/null 2>&1 && { ok "unblob already installed in ASRA's venv"; return 0; }
    log "Installing unblob (modern firmware extractor -- complements binwalk, agent/tools/builders/binwalk.py)..."
    "$py" -m pip install unblob || { fail "pip install unblob failed."; return 1; }
    # SquashFS extraction additionally needs the sasquatch binary (unblob's own PyPI page points
    # at a GitHub-release .deb for it) -- best-effort, never fails the whole step: every OTHER
    # format unblob handles still works without it.
    if ! have sasquatch; then
        warn "unblob installed, but sasquatch (needed for SquashFS extraction specifically) is not -- see https://github.com/onekey-sec/sasquatch/releases for a manual .deb install if you need that one format."
    fi
}

# --- adb / Android platform-tools (live device/emulator access) --------------------------------
install_adb() {
    have adb && { ok "adb already installed ($(command -v adb))"; return 0; }
    log "Installing adb (Android platform-tools -- live device/emulator access)..."
    if [ "$(uname -s)" = "Darwin" ]; then
        have brew || { fail "Homebrew not found -- install it first (https://brew.sh), then re-run this script."; return 1; }
        brew install --cask android-platform-tools || { fail "brew install --cask android-platform-tools failed -- see output above."; return 1; }
    else
        case "$PKG_MANAGER" in
            apt)    pkg_install adb ;;
            dnf)    pkg_install android-tools ;;
            pacman) pkg_install android-tools ;;
        esac
    fi
    have adb || { warn "adb not available via this platform's package manager -- install manually from https://developer.android.com/tools/releases/platform-tools."; return 1; }
}

# --- WABT (WebAssembly Binary Toolkit: wat2wasm/wasm2c/wasm-objdump) ----------------------------
install_wabt() {
    have wasm2c && { ok "WABT already installed ($(command -v wasm2c))"; return 0; }
    log "Installing WABT (WebAssembly Binary Toolkit)..."
    if [ "$(uname -s)" = "Darwin" ]; then
        have brew || { fail "Homebrew not found -- install it first (https://brew.sh), then re-run this script."; return 1; }
        brew install wabt || { fail "brew install wabt failed -- see output above."; return 1; }
        return 0
    fi
    pkg_install wabt || { warn "wabt not available via $PKG_MANAGER -- install manually from https://github.com/WebAssembly/wabt/releases."; return 1; }
}

log ""
log "${BOLD}ASRA — installing the \"heavy\"/extended arsenal: Ghidra, pwntools/pwndbg/pyelftools/unicorn, sigrok-cli, unblob, adb, WABT${RESET}"
log "Package manager detected: ${PKG_MANAGER:-none}"
log ""

install_ghidra
install_pwntools_stack
install_pwndbg
install_sigrok_cli
install_unblob
install_adb
install_wabt

log ""
log "${BOLD}Summary${RESET} — this is exactly what ASRA's own tool registry health-check will see:"
missing=0
for name in analyzeHeadless sigrok-cli adb wasm2c; do
    if have "$name"; then
        ok "$name -> $(command -v "$name")"
    else
        fail "$name -> not on PATH"
        missing=$((missing + 1))
    fi
done
if [ -x "$SCRIPT_DIR/venv/bin/python" ] && "$SCRIPT_DIR/venv/bin/python" -c "import pwn, elftools, unicorn" >/dev/null 2>&1; then
    ok "pwntools/pyelftools/unicorn -> importable in ASRA's venv"
else
    fail "pwntools/pyelftools/unicorn -> not fully importable in ASRA's venv (see install_pwntools_stack's own output above)"
    missing=$((missing + 1))
fi
if [ -x "$SCRIPT_DIR/venv/bin/python" ] && "$SCRIPT_DIR/venv/bin/python" -c "import unblob" >/dev/null 2>&1; then
    ok "unblob -> importable in ASRA's venv"
else
    fail "unblob -> not importable in ASRA's venv (see install_unblob's own output above)"
    missing=$((missing + 1))
fi
if grep -q "pwndbg" "$HOME/.gdbinit" 2>/dev/null; then
    ok "pwndbg -> wired into $HOME/.gdbinit"
else
    fail "pwndbg -> not wired into $HOME/.gdbinit (see install_pwndbg's own output above)"
    missing=$((missing + 1))
fi

log ""
if [ "$missing" -eq 0 ]; then
    log "Heavy arsenal ready. Restart the agent so the new tools are picked up."
    exit 0
else
    warn "$missing heavy tool(s) still missing — see the [FAIL]/[WARN] lines above for why, then re-run this script (already-installed tools are skipped, so re-running is cheap)."
    exit 1
fi
