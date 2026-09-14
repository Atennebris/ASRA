#!/bin/bash
# Starts ASRA locally in WSL2. Never touches the system Python or any global package set — all
# dependencies live in the project-local ./venv.
#
# First run (no venv yet, or an incomplete one): creates it and installs requirements.txt.
# Every later run: recognizes the venv + dependencies are already in place (a hash of
# requirements.txt, stored inside the venv, matches the current file) and skips straight to
# activating + starting — no redundant reinstall just because the script ran again. If
# requirements.txt actually changed since the last install, the hash mismatch catches that and
# reinstalls automatically.
set -e

cd "$(dirname "$0")"

VENV_DIR="venv"
INSTALLED_HASH_FILE="$VENV_DIR/.requirements.sha256"

# A directory can exist from an interrupted first run without a working interpreter in it —
# treat that the same as "no venv yet", not as "already set up".
if [ ! -x "$VENV_DIR/bin/python3" ]; then
  echo "No virtual environment found — creating ./venv ..."
  rm -rf "$VENV_DIR"
  python3 -m venv "$VENV_DIR"
fi

# sha256sum is GNU coreutils (Linux/WSL2 default); macOS ships shasum instead — try both so this
# doesn't silently break there, even though the project's tested/supported target is WSL2.
if command -v sha256sum >/dev/null 2>&1; then
  CURRENT_HASH="$(sha256sum requirements.txt | awk '{print $1}')"
else
  CURRENT_HASH="$(shasum -a 256 requirements.txt | awk '{print $1}')"
fi
INSTALLED_HASH="$(cat "$INSTALLED_HASH_FILE" 2>/dev/null || true)"

if [ "$CURRENT_HASH" != "$INSTALLED_HASH" ]; then
  # No -q here (real, confirmed incident this fixes): pip's own dependency resolver can spend
  # several CPU-bound minutes with ZERO output at all while backtracking through candidate
  # versions before it even starts downloading/building anything -- requirements.txt's own comments
  # next to mythril/slither-analyzer document why those two specifically are pinned to stop exactly
  # this backtracking -- and -q suppressed every sign of it, making a real, still-working install
  # indistinguishable from a genuinely hung one. Confirmed live: an operator watching a silent
  # terminal for minutes during exactly this pip resolve reasonably assumed it had frozen and hit
  # Ctrl+C, aborting a perfectly healthy install partway through. Plain pip output ("Collecting X",
  # "Building wheel for Y", ...) is verbose but at least proves forward progress the whole time.
  echo "Installing dependencies from requirements.txt -- this can take several minutes on a fresh"
  echo "install or after requirements.txt changes. Real progress prints below; let it finish rather"
  echo "than assuming it's stuck."
  "$VENV_DIR/bin/pip" install --upgrade pip
  "$VENV_DIR/bin/pip" install -r requirements.txt
  # The `httpx` PyPI package (an HTTP client library this project imports as `import httpx`) also
  # drops an unused console-script shim at venv/bin/httpx. With the venv on PATH that shim SHADOWS
  # ProjectDiscovery's real `httpx` recon scanner (/usr/local/bin/httpx) -- confirmed live: it made
  # setup_tools.sh's own httpx self-check falsely FAIL (exit 1) even though the real scanner was
  # installed. Nothing here uses the httpx CLI (only the library, and HTTPX_PATH already points the
  # tool at the real binary), so drop just the shim; the library package itself stays untouched.
  rm -f "$VENV_DIR/bin/httpx"
  # slither-analyzer AND mythril installed separately, --no-deps -- see requirements.txt's own
  # comments right above where each would otherwise be listed. Both declare transitive constraints
  # (slither-analyzer: eth-abi>=5.0.1; mythril: eth-abi<5.0.0, MarkupSafe<2.1.0, more likely exist)
  # that are genuinely irreconcilable with the rest of this file in one pip resolve (confirmed live:
  # ResolutionImpossible / old-version build failures), even though both tools' own actual runtime
  # code works fine against the newer package versions the rest of this file already needs.
  # Deliberately placed AFTER the main install, never inside requirements.txt itself -- requirements.txt
  # has no per-line way to express "resolve everything else normally, but --no-deps just this one".
  "$VENV_DIR/bin/pip" install --no-deps slither-analyzer==0.11.6
  "$VENV_DIR/bin/pip" install --no-deps mythril==0.24.8
  echo "$CURRENT_HASH" > "$INSTALLED_HASH_FILE"
else
  echo "Dependencies already installed and up to date — skipping install."
fi

if [ ! -f .env ]; then
  echo "No .env found — copying .env.example. Edit .env with your real API key(s) before scanning."
  cp .env.example .env
fi

set -a
source .env
set +a
export PORT="${PORT:-8000}"

# DEBUG=true in .env (agent/utils/debug.py's is_debug_enabled(), same env var/accepted values)
# also opens a second, separate terminal window here that tails the global debug log live — the
# actual server keeps running in this original terminal same as always, matching what run.bat
# already gives Windows users (a cmd window running scripts/debug_console.py). That log lives in
# ~/Documents/ASRA (projects/paths.py's resolve_global_app_dir(), same "real, user-visible folder"
# convention project folders already use), overridable via APP_DATA_DIR in .env exactly like
# PROJECTS_DIR already overrides where project folders go.
#
# Skipped entirely under WSL2: run.bat's own Windows-side cmd window already covers that case (it
# reads the same Windows-side log file directly, opened before this script ever runs) — opening a
# second one here too would be redundant, and a plain WSL2 shell normally has no GUI terminal
# emulator to open one in anyway.
_is_wsl() {
  [ -n "${WSL_DISTRO_NAME:-}" ] && return 0
  grep -qi microsoft /proc/version 2>/dev/null
}

if ! _is_wsl; then
  case "${DEBUG:-}" in
    [Tt][Rr][Uu][Ee] | 1 | [Yy][Ee][Ss])
      ASRA_APP_DIR="$("$VENV_DIR/bin/python" -c "from projects.paths import resolve_global_app_dir; print(resolve_global_app_dir())")"
      mkdir -p "$ASRA_APP_DIR"
      touch "$ASRA_APP_DIR/debug.log"
      # exec $SHELL at the end keeps the window open with a normal prompt after the tail script
      # exits (Ctrl+C, or the whole app shutting down) instead of the window just closing —
      # matches run.bat's "cmd /k" behavior on Windows. The $SHELL here is deliberately unexpanded
      # by this script (escaped \$) — it must be evaluated by the *new* terminal's own shell, not
      # this one, once it actually runs the command below.
      DEBUG_CMD="cd '$(pwd)' && '$VENV_DIR/bin/python' scripts/debug_console.py --log-path '$ASRA_APP_DIR/debug.log'; exec \$SHELL"
      case "$(uname -s)" in
        Darwin)
          if osascript -e "tell application \"Terminal\" to do script \"$DEBUG_CMD\"" >/dev/null 2>&1; then
            echo "Debug mode is on — opened a separate Terminal window tailing $ASRA_APP_DIR/debug.log"
          else
            echo "Debug mode is on, but could not open a separate Terminal window automatically —" \
                 "run this yourself in another terminal if you want it:"
            echo "  $VENV_DIR/bin/python scripts/debug_console.py --log-path \"$ASRA_APP_DIR/debug.log\""
          fi
          ;;
        Linux)
          # No single "the" Linux terminal emulator — tries the common ones in order and uses
          # whichever is actually installed. gnome-terminal gets its own case: its "-e <string>"
          # form is deprecated in favor of "-- <argv...>"; the rest accept the more universal
          # "-e <argv...>" convention. Best-effort across a genuinely wide variety of desktop
          # environments (same "written carefully, not verified on real hardware for every case"
          # honesty this project already applies to the whole native-macOS path).
          #
          # Window size (columns x rows), same DEBUG_CONSOLE_WIDTH/DEBUG_CONSOLE_HEIGHT knobs
          # run.bat reads for its own Windows console window, kept smaller by default here too.
          # Only wired up for the two emulators whose --geometry flag is reliably COLSxROWS
          # (gnome-terminal, xterm) — konsole/x-terminal-emulator/xfce4-terminal's own geometry
          # handling varies enough across versions that guessing a flag here risks a broken launch
          # instead of just an unsized window, so those fall back to their own default size.
          _console_geometry="${DEBUG_CONSOLE_WIDTH:-90}x${DEBUG_CONSOLE_HEIGHT:-25}"
          _opened=0
          for _term in x-terminal-emulator gnome-terminal konsole xfce4-terminal xterm; do
            if command -v "$_term" >/dev/null 2>&1; then
              case "$_term" in
                gnome-terminal)
                  "$_term" "--geometry=$_console_geometry" -- bash -c "$DEBUG_CMD" >/dev/null 2>&1 &
                  ;;
                xterm)
                  "$_term" -geometry "$_console_geometry" -e bash -c "$DEBUG_CMD" >/dev/null 2>&1 &
                  ;;
                *)
                  "$_term" -e bash -c "$DEBUG_CMD" >/dev/null 2>&1 &
                  ;;
              esac
              _opened=1
              break
            fi
          done
          if [ "$_opened" = "1" ]; then
            echo "Debug mode is on — opened a separate terminal window tailing $ASRA_APP_DIR/debug.log"
          else
            echo "Debug mode is on, but no terminal emulator was found to open a separate window" \
                 "(headless/server environment?) — run this yourself in another terminal if you want it:"
            echo "  $VENV_DIR/bin/python scripts/debug_console.py --log-path \"$ASRA_APP_DIR/debug.log\""
          fi
          ;;
      esac
      ;;
  esac
fi

# Real incident this fixes: arjun (agent/tools/builders/arjun.py) is the one tool in the registry
# installed via pip (requirements.txt) instead of setup_tools.sh's system-wide /usr/local/bin --
# every other external tool (nmap/nuclei/nikto/ffuf/...) is found via a plain shutil.which()
# against PATH, which works for them because they land in /usr/local/bin regardless of venv state.
# A console-script pip installs (venv/bin/arjun) is NOT on PATH unless the venv was actually
# activated first, and this script never does that -- it calls "$VENV_DIR/bin/python" by its full
# path, so the server process's own PATH never included venv/bin, and shutil.which("arjun") inside
# the running app would report it as not installed even right after a clean setup. Prepending it
# here (inherited by every subprocess run_tool spawns) is the one place this needs fixing, not a
# special case inside agent/tools/runner.py -- it keeps every tool discoverable the same, uniform
# PATH-based way, and covers any future pip-installed CLI tool for free too.
export PATH="$(pwd)/$VENV_DIR/bin:$PATH"

echo "Starting ASRA on http://127.0.0.1:${PORT}"
# The agent modules take a few seconds to import off WSL2's /mnt/c filesystem before uvicorn can
# print its own startup lines -- say so, so this gap reads as progress, not a frozen console.
echo "  Loading modules and recovering sessions (a few seconds)..."
# main.py's own "python main.py" entrypoint (not the bare "uvicorn main:app" CLI) specifically so
# a second Ctrl+C during graceful shutdown can be caught and reported as one clean line instead of
# uvicorn/uvloop's own raw traceback -- see main.py's __main__ block for the real reasoning.
exec "$VENV_DIR/bin/python" main.py
