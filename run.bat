@echo off
setlocal
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

where wsl.exe >nul 2>nul
if errorlevel 1 (
  echo WSL is not installed or not on PATH.
  echo See README.md, section "Stage 1: prepare your machine", then run this again.
  pause
  exit /b 1
)

set "WSL_TARGET_ARGS="
if not "%WSL_DISTRO%"=="" set "WSL_TARGET_ARGS=-d %WSL_DISTRO%"

rem Invoked as "bash run.sh", not "./run.sh" - a fresh git checkout on the Windows side won't
rem necessarily carry the executable bit (NTFS has no real concept of it), and this way it
rem never matters.
wsl.exe %WSL_TARGET_ARGS% -- bash -lc "cd \"$(wslpath -a '%~dp0')\" && bash run.sh"
if errorlevel 1 (
  echo.
  echo ASRA exited with an error. If this is the first run, check that a WSL2 distro is installed
  echo and that the system tools (nmap/nuclei/etc.) are installed inside it - see README.md.
  echo If you have more than one WSL distro installed, try: set WSL_DISTRO=^<name^> then run.bat again.
  pause
)
