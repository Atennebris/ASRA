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
  echo "Installing dependencies from requirements.txt ..."
  "$VENV_DIR/bin/pip" install -q --upgrade pip
  "$VENV_DIR/bin/pip" install -q -r requirements.txt
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
PORT="${PORT:-8000}"

echo "Starting ASRA on http://127.0.0.1:${PORT}"
exec "$VENV_DIR/bin/uvicorn" main:app --host 127.0.0.1 --port "$PORT"
