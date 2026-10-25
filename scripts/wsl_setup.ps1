#Requires -Version 5.1
<#
Runs WSL's own install commands, elevated, for the desktop launcher's "Install WSL" / "Install
<distro>" buttons (desktop/src-tauri/src/main.rs's install_wsl command).

This script is launched via `Start-Process powershell.exe -Verb RunAs` from main.rs -- by the time
it starts, it is ALREADY the elevated process. PowerShell's own Start-Process cannot combine
`-Verb RunAs` with `-RedirectStandardOutput`/`-RedirectStandardError` on the OUTER elevate call, so
main.rs does none of that; this script instead redirects its own child (wsl.exe) into -LogPath
directly, which has no such restriction once already running elevated.

The launcher's get_wsl_setup_status command never parses this log for a pass/fail sentinel -- it
re-checks real WSL/distro state instead (see that command's own comment) -- so this script's log
output exists purely for the operator to read, not as a machine-readable contract. Keep it
human-readable, not structured.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$LogPath,
    # "install-wsl" (plain `wsl --install`, pulls in WSL's own current default distro) or
    # "install-distro" (`wsl --install -d <Distro>`, used when WSL itself is already present but
    # no distro is registered yet).
    [Parameter(Mandatory = $true)][ValidateSet('install-wsl', 'install-distro')][string]$Mode,
    [string]$Distro = 'Ubuntu'
)

function Write-Log([string]$Line) {
    Add-Content -LiteralPath $LogPath -Value $Line -Encoding utf8
}

Write-Log "Running elevated as $($env:USERNAME). Mode: $Mode. Distro: $Distro."
Write-Log "This window can take several minutes (first-time WSL/distro downloads) -- it is safe to leave it running."

if ($Mode -eq 'install-wsl') {
    # No -d: installs WSL itself plus whichever distro `wsl --install` currently defaults to
    # (Microsoft's own choice, Ubuntu today) -- matches ASRA_WSL_AUTO_INSTALL_DISTRO's own default.
    & wsl.exe --install *>> $LogPath
} else {
    & wsl.exe --install -d $Distro *>> $LogPath
}
$exitCode = $LASTEXITCODE

Write-Log "=== wsl.exe --install exited with code $exitCode ==="
if ($exitCode -ne 0) {
    Write-Log 'If Windows asked you to restart the machine, do that, then click the launcher''s install button again -- WSL finishes enabling itself on the next boot on some Windows builds.'
}

# A fresh WSL distro's very first boot prompts interactively for a UNIX username/password; that
# prompt has nowhere to go when launched this way (no attached console the operator can type
# into), so it is left to the operator to complete themselves the first time they actually open
# that distro -- this script only gets WSL + the distro registered, same scope main.rs's own
# install_wsl command comment documents.
Write-Log 'Done. If this is a brand-new distro, its very first launch will ask you to pick a UNIX username/password -- open it once from the Start menu (or click Start in ASRA again) to finish that one-time step.'
