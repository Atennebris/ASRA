@echo off
rem Same as run.bat (double-click this instead) except the agent runs as WSL2's root user --
rem no sudo/SUDO_PASSWORD needed anywhere, ever (e.g. nmap's own -O works automatically). See
rem run.bat's own header comment / README.md's "Running as root" section for the full story.
set "WSL_USER=root"
call "%~dp0run.bat"
