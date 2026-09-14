@echo off
setlocal enabledelayedexpansion
rem Windows launcher (double-click this) - ASRA itself runs inside WSL2, not natively on
rem Windows, because the security tools (nmap/nuclei/Metasploit/sqlmap) are Linux tools. This
rem script only bridges Windows to the already-set-up WSL2 side; run.sh does the real work.
rem If WSL2 isn't set up yet, see README.md's "Stage 1: prepare your machine" section.
rem
rem No distro name is hardcoded here: by default this uses whatever WSL marks as your default
rem distro (any Debian/Ubuntu-based one works, since run.sh itself only needs bash + python3).
rem To target a specific distro instead (e.g. you have several installed), set WSL_DISTRO, e.g.:
rem   set WSL_DISTRO=Ubuntu-24.04
rem   run.bat
rem
rem Default user is whatever that distro's own default is (normal, non-root -- the documented,
rem supported way to run ASRA; sys.geteuid() != 0 the whole time). To run the ENTIRE agent process
rem as root instead (skips sudo/SUDO_PASSWORD entirely for anything that would otherwise need it,
rem e.g. nmap's own -O -- see agent/tools/builders/nmap.py), set WSL_USER=root, e.g.:
rem   set WSL_USER=root
rem   run.bat
rem No setup needed for this -- root (UID 0) always exists on every Linux distro by definition, and
rem `wsl.exe --user root` switches to it directly with no password prompt at all (confirmed live:
rem `wsl.exe --user root -d <distro> -- whoami` returns "root" instantly, no auth step of any kind).

where wsl.exe >nul 2>nul
if errorlevel 1 (
  echo WSL is not installed or not on PATH.
  echo See README.md, section "Stage 1: prepare your machine", then run this again.
  pause
  exit /b 1
)

set "WSL_TARGET_ARGS="
if not "%WSL_DISTRO%"=="" set "WSL_TARGET_ARGS=-d %WSL_DISTRO%"
if not "%WSL_USER%"=="" set "WSL_TARGET_ARGS=%WSL_TARGET_ARGS% --user %WSL_USER%"

rem DEBUG=true in .env (agent/utils/debug.py's is_debug_enabled(), same env var, same accepted
rem values) also opens a second, separate console window here that tails the global debug log
rem live — the actual server keeps running in this original window same as always. That log lives
rem in Documents\ASRA (projects/paths.py's resolve_global_app_dir(), same "real, user-visible
rem folder" convention project folders already use — not this repo's own data\ directory, so
rem debug output never mixes into the app's install folder), overridable via APP_DATA_DIR in .env
rem exactly like PROJECTS_DIR already overrides where project folders go. This script runs
rem natively on Windows already (unlike the Python side, which needs a WSL2->Windows path bridge
rem for the same folder), so %USERPROFILE% is directly correct here with no interop needed.
rem
rem The window itself is plain cmd.exe (not PowerShell — that used to be the case here, changed on
rem request: PowerShell's own window/prompt chrome wasn't wanted). What actually RUNS inside that
rem window, though, is a native PowerShell script (scripts\debug_console.ps1) — not wsl.exe. An
rem earlier version ran scripts\debug_console.py through an interactive wsl.exe session kept
rem attached to the window for its whole life; that forces the window into ConPTY passthrough,
rem where Windows stops treating Ctrl+A/Ctrl+C as its own select-all/copy shortcuts and instead
rem forwards them as raw bytes into the Linux pty, which echoes them back as garbled control
rem characters (confirmed live: this is exactly what broke copying from that window). A plain
rem native PowerShell process has no such problem — the window stays in classic conhost mode, so
rem mouse selection, QuickEdit, and Ctrl+A/Ctrl+C all behave like any ordinary console window.
rem CATEGORY_COLORS itself still lives in exactly one place (agent/utils/debug.py) — fetched once
rem below via a short-lived, non-interactive wsl.exe call (stdout redirected straight to a file,
rem never attached to a console), not redeclared in PowerShell. The command line itself is written
rem to a small generated .cmd file first, then run via "cmd /k <that file>" (:start_debug_console
rem below), rather than inlined at the call site: confirmed by hand against real cmd.exe that
rem embedding this many literal quotes/&/^ characters inside a NESTED `if (...)` block corrupts
rem them (cmd pre-scans an entire parenthesized block's quote/paren balance together, not line by
rem line, so a quote used for one purpose on one line can collide with unrelated quoting on another
rem line in the same block) — a goto/call-based subroutine keeps this at the same "top level" the
rem parser handles correctly, and a real file a user could open and read is more robust than a
rem one-line command squeezed into `start ... cmd /k "..."` regardless.
if not exist .env goto :skip_debug_console
findstr /I /R /C:"^DEBUG=true" /C:"^DEBUG=1" /C:"^DEBUG=yes" .env >nul 2>nul
if errorlevel 1 goto :skip_debug_console
call :start_debug_console
:skip_debug_console

rem Invoked as "bash run.sh", not "./run.sh" - a fresh git checkout on the Windows side won't
rem necessarily carry the executable bit (NTFS has no real concept of it), and this way it
rem never matters.
wsl.exe %WSL_TARGET_ARGS% -- bash -lc "cd \"$(wslpath -a '%~dp0')\" && bash run.sh"
if errorlevel 1 (
  echo.
  echo ASRA exited with an error. If this is the first run, check that a WSL2 distro is installed
  echo and that the system tools ^(nmap/nuclei/etc.^) are installed inside it - see README.md.
  echo If you have more than one WSL distro installed, try: set WSL_DISTRO=^<name^> then run.bat again.
  pause
)
exit /b 0

:start_debug_console
set "ASRA_APP_DIR=%USERPROFILE%\Documents\ASRA"
for /f "usebackq tokens=1,* delims==" %%A in (`findstr /R /C:"^APP_DATA_DIR=" .env`) do if not "%%B"=="" set "ASRA_APP_DIR=%%B"
rem Ctrl+MouseWheel zoom is a native conhost feature (Windows 10 1809+): it's meant to change only
rem the font size and leave the window's own pixel dimensions alone. In this window it visibly
rem misbehaves -- the window itself jumps/resizes too -- and the most likely cause is conhost's
rem separate "wrap text output on resize" behavior reflowing the whole scrollback buffer (thousands
rem of already-printed log lines) every time the zoom changes the visible column count, which reads
rem as the window going haywire rather than a clean text-only zoom. conhost persists that setting
rem per console-title in the registry (the same place the Properties dialog writes to when you
rem click OK on a window not launched from a .lnk shortcut) -- pre-seeding it here, keyed to this
rem window's own fixed title, only affects windows titled exactly "ASRA Debug Log", never any other
rem console on this machine. Delete this key (reg delete "HKCU\Console\ASRA Debug Log" /f) to revert.
reg add "HKCU\Console\ASRA Debug Log" /v LineWrap /t REG_DWORD /d 0 /f >nul 2>nul

rem Font is set here, in the registry, instead of at runtime in debug_console.ps1 -- confirmed live
rem that SetCurrentConsoleFontEx is simply broken on this machine's Windows build: every call
rem "succeeds" but the console's real rendered size snaps to a tiny ~6x12px and gets stuck there for
rem the rest of the session no matter what's requested afterward, including the console's own
rem original working size. The registry is the same place the Properties dialog itself writes a
rem chosen font to, applied once at window-creation time, which measurably works where the runtime
rem call doesn't. Height overridable via DEBUG_CONSOLE_FONT_SIZE in .env (same convention as
rem APP_DATA_DIR above); width follows Consolas's own ~1:2 aspect ratio. FontSize is packed as
rem width + height*65536 -- see HKEY_CURRENT_USER\Console in the registry for the format.
set "ASRA_FONT_HEIGHT=28"
for /f "usebackq tokens=1,* delims==" %%A in (`findstr /R /C:"^DEBUG_CONSOLE_FONT_SIZE=" .env`) do if not "%%B"=="" set "ASRA_FONT_HEIGHT=%%B"
set /a "ASRA_FONT_WIDTH=ASRA_FONT_HEIGHT/2"
set /a "ASRA_FONT_PACKED=ASRA_FONT_WIDTH+(ASRA_FONT_HEIGHT*65536)"
reg add "HKCU\Console\ASRA Debug Log" /v FontSize /t REG_DWORD /d %ASRA_FONT_PACKED% /f >nul 2>nul
reg add "HKCU\Console\ASRA Debug Log" /v FaceName /t REG_SZ /d "Consolas" /f >nul 2>nul
reg add "HKCU\Console\ASRA Debug Log" /v FontFamily /t REG_DWORD /d 54 /f >nul 2>nul
reg add "HKCU\Console\ASRA Debug Log" /v FontWeight /t REG_DWORD /d 400 /f >nul 2>nul

rem Window grid size (columns x rows) -- kept small by default so the debug window doesn't dominate
rem the screen; overridable via DEBUG_CONSOLE_WIDTH/DEBUG_CONSOLE_HEIGHT in .env, same convention as
rem DEBUG_CONSOLE_FONT_SIZE above. debug_console.ps1 itself clamps whatever's requested here against
rem MaxPhysicalWindowSize, so a value too big for the current display/font combo still degrades
rem gracefully instead of failing.
set "ASRA_CONSOLE_WIDTH=90"
for /f "usebackq tokens=1,* delims==" %%A in (`findstr /R /C:"^DEBUG_CONSOLE_WIDTH=" .env`) do if not "%%B"=="" set "ASRA_CONSOLE_WIDTH=%%B"
set "ASRA_CONSOLE_HEIGHT=25"
for /f "usebackq tokens=1,* delims==" %%A in (`findstr /R /C:"^DEBUG_CONSOLE_HEIGHT=" .env`) do if not "%%B"=="" set "ASRA_CONSOLE_HEIGHT=%%B"

rem Same "pre-seed the registry before the window exists" trick as FontSize above, extended to the
rem window/buffer grid itself -- without this, the window is born at conhost's plain per-machine
rem default size (whatever WindowSize/ScreenBufferSize last happened to be under this title, or the
rem system default the very first time), and debug_console.ps1's own $rawUI.WindowSize assignment
rem (needed anyway as a fallback for a display too small to fit ASRA_CONSOLE_WIDTH/HEIGHT) only runs
rem a moment later once PowerShell actually starts executing -- confirmed live, that gap between
rem "window appears at the old size" and "script resizes it" is exactly the visible jump. Pre-seeding
rem here means the window is already the right size the instant it's created, so that later resize
rem becomes a no-op in the common case instead of a visible second resize.
set /a "ASRA_WINDOW_PACKED=ASRA_CONSOLE_WIDTH+(ASRA_CONSOLE_HEIGHT*65536)"
reg add "HKCU\Console\ASRA Debug Log" /v WindowSize /t REG_DWORD /d %ASRA_WINDOW_PACKED% /f >nul 2>nul
rem Buffer height (scrollback) intentionally stays large (3000, matching debug_console.ps1's own
rem BufferSize.Height floor) regardless of the visible window height; buffer width matches the window
rem width since there's no separate override for it.
set /a "ASRA_BUFFER_PACKED=ASRA_CONSOLE_WIDTH+(3000*65536)"
reg add "HKCU\Console\ASRA Debug Log" /v ScreenBufferSize /t REG_DWORD /d %ASRA_BUFFER_PACKED% /f >nul 2>nul

if not exist "!ASRA_APP_DIR!" mkdir "!ASRA_APP_DIR!"
if not exist "!ASRA_APP_DIR!\debug.log" type nul > "!ASRA_APP_DIR!\debug.log"
echo Debug mode is on — opening a separate window tailing "!ASRA_APP_DIR!\debug.log" ...

rem One short-lived, non-interactive wsl.exe call (stdout piped straight to a file, never attached
rem to a console window) to read CATEGORY_COLORS from its single source of truth
rem (agent/utils/debug.py) — the persistent tail window started below is plain PowerShell and never
rem touches WSL itself, see the comment above this subroutine for why that matters.
set "ASRA_CATEGORY_COLORS_FILE=%TEMP%\asra_category_colors.json"
wsl.exe %WSL_TARGET_ARGS% -- bash -lc "cd \"$(wslpath -a '%~dp0')\" && ./venv/bin/python -c \"import json,sys; sys.path.insert(0, '.'); from agent.utils.debug import CATEGORY_COLORS; print(json.dumps(CATEGORY_COLORS))\"" > "!ASRA_CATEGORY_COLORS_FILE!"

set "ASRA_DEBUG_LAUNCHER=%TEMP%\asra_debug_console.cmd"
echo @echo off> "!ASRA_DEBUG_LAUNCHER!"
rem cmd.exe /k running a .cmd file silently appends " - <that file's own path>" to whatever title
rem "start" gave the window the moment it starts executing the file -- confirmed live, that's
rem exactly why the LineWrap registry key above (keyed to the plain "ASRA Debug Log" string) never
rem actually applied: the real window title was "ASRA Debug Log - C:\...\asra_debug_console.cmd",
rem not "ASRA Debug Log". An explicit `title` command inside the script itself runs after that
rem auto-rename and resets it back to the fixed string, which is also what the registry key above
rem needs to actually match.
echo title ASRA Debug Log>> "!ASRA_DEBUG_LAUNCHER!"
rem chcp 65001 used to run here before starting powershell.exe -- confirmed live (instrumented the
rem PowerShell script to log its own window size at every step) that chcp itself silently shrinks
rem the registry-seeded font back down before powershell.exe even starts, undoing the whole fix
rem above. debug_console.ps1 already sets [Console]::OutputEncoding = UTF8 on its own, which is
rem sufficient for correct UTF-8 rendering (Cyrillic, box-drawing, etc.) without cmd's chcp at all.
echo powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\debug_console.ps1" -LogPath "!ASRA_APP_DIR!\debug.log" -ColorsFile "!ASRA_CATEGORY_COLORS_FILE!" -Width !ASRA_CONSOLE_WIDTH! -Height !ASRA_CONSOLE_HEIGHT!>> "!ASRA_DEBUG_LAUNCHER!"
start "ASRA Debug Log" cmd /k "!ASRA_DEBUG_LAUNCHER!"
goto :eof
