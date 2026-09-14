#Requires -Version 5.1
<#
Native Windows tail of the ASRA global debug log for run.bat's debug console window.

Runs as a plain Win32 console process (no WSL/ConPTY in the loop) so the window stays in
classic conhost mode -- mouse selection, QuickEdit, and "Enable Ctrl key shortcuts" (Ctrl+A
select-all / Ctrl+C copy) all behave like any ordinary console window. The previous approach
ran scripts/debug_console.py through an interactive `wsl.exe` session attached to the same
window for its entire lifetime; that forces the window into ConPTY passthrough, where Windows
stops intercepting Ctrl+A/Ctrl+C itself and instead forwards them as raw bytes into the Linux
pty, which echoes them back as unreadable control characters -- run.sh's native macOS/Linux
terminals never had this problem (no WSL hop there), so debug_console.py is untouched and still
used as-is for those platforms.

Colors are NOT redeclared here -- CATEGORY_COLORS in agent/utils/debug.py stays the single
source of truth. run.bat fetches it once (non-interactively, before this script starts) via a
short-lived `wsl.exe -- python -c ...` call and writes it to -ColorsFile as JSON; this script
never talks to WSL itself.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$LogPath,
    [Parameter(Mandatory = $true)][string]$ColorsFile,
    # Window grid size (columns x rows) -- run.bat passes DEBUG_CONSOLE_WIDTH/DEBUG_CONSOLE_HEIGHT
    # from .env here, falling back to these same smaller-by-default values when unset.
    [int]$Width = 90,
    [int]$Height = 25
)

# run.bat's launcher .cmd sets the window title via the `title` command before starting this
# script -- but cmd.exe re-derives the title from "the command it's currently running" once a new
# foreground child process (this script) actually starts, silently overwriting that back to a
# path-based title (confirmed live: the window ends up titled after the launcher .cmd's own path,
# not "ASRA Debug Log"). This process is what's actually alive for the window's entire real
# lifetime, so setting the title here -- not in the batch wrapper -- is what actually sticks.
$Host.UI.RawUI.WindowTitle = "ASRA Debug Log"

# conhost only renders ANSI/VT color codes once a process explicitly asks for it -- same
# ENABLE_VIRTUAL_TERMINAL_PROCESSING dance debug_console.py's _enable_windows_ansi() does.
#
# Font (face + size) is deliberately NOT set here via SetCurrentConsoleFontEx -- confirmed live on
# this project's own dev machine that the API is simply broken on recent Windows builds: it returns
# success for every request, but the console's actual rendered size snaps to a tiny ~6x12px and
# stays stuck there for the rest of the session regardless of which face/size/index is requested
# afterward, including re-requesting the console's own original working default. run.bat instead
# pre-seeds HKCU\Console\<this window's title> (FaceName/FontSize/FontFamily/FontWeight) in the
# registry before the window is even created -- the same persistence mechanism the Properties
# dialog itself writes to -- which measurably works (confirmed live: real client-area pixel
# dimensions grew as expected) precisely because it never goes through the broken runtime call.
Add-Type @'
using System;
using System.Runtime.InteropServices;

namespace AsraNative {
    public class Kernel32 {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetStdHandle(int nStdHandle);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
    }
}
'@

$stdOutHandle = [AsraNative.Kernel32]::GetStdHandle(-11)  # STD_OUTPUT_HANDLE
$consoleMode = 0
if ([AsraNative.Kernel32]::GetConsoleMode($stdOutHandle, [ref]$consoleMode)) {
    [AsraNative.Kernel32]::SetConsoleMode($stdOutHandle, $consoleMode -bor 0x0004) | Out-Null  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
}

# run.bat now pre-seeds WindowSize/ScreenBufferSize in the registry too (same mechanism as the
# FontSize pre-seed above), so in the common case the window is already born at the right grid size
# and the assignment below is a no-op -- no second, visible resize after the window appears. This
# still runs unconditionally as a safety net for a display too small to fit the requested grid
# (clamping against MaxPhysicalWindowSize here, since the registry-seeded font above changes how many
# columns/rows the same monitor can physically show, and this must be read after that font is already
# active) and for a first-ever run before run.bat has had a chance to write the registry keys.
$rawUI = $Host.UI.RawUI
$maxSize = $rawUI.MaxPhysicalWindowSize
$targetWidth = [Math]::Min($Width, $maxSize.Width)
$targetHeight = [Math]::Min($Height, $maxSize.Height)
# Buffer must never be smaller than the window in either dimension -- grow it first, then resize
# the window, matching the order the console host itself enforces.
$rawUI.BufferSize = New-Object System.Management.Automation.Host.Size(
    [Math]::Max($rawUI.BufferSize.Width, $targetWidth), [Math]::Max($rawUI.BufferSize.Height, 3000))
$rawUI.WindowSize = New-Object System.Management.Automation.Host.Size($targetWidth, $targetHeight)

# Belt-and-suspenders alongside run.bat's "chcp 65001": that sets the *console's* codepage, this
# makes sure .NET's own Console.Out (what Write-Host actually writes through) agrees with it too --
# same reasoning as debug_console.py's sys.stdout.reconfigure(encoding="utf-8").
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# [char]27, not the backtick-e escape ("`e") -- `e is only recognized by PowerShell 7+'s
# tokenizer; Windows PowerShell 5.1 (what run.bat launches via plain powershell.exe, and what this
# script's own #Requires -Version 5.1 targets) silently drops the backtick and leaves the literal
# text "e[36m" etc. sitting in the output -- confirmed live, that literal text is exactly what was
# showing up instead of color.
$esc = [char]27
$reset = "$esc[0m"
$headerColor = "$esc[36m"
$dim = "$esc[90m"

# category -> raw ANSI color prefix, exactly as CATEGORY_COLORS in agent/utils/debug.py defines it.
$categoryColors = Get-Content -Raw -Encoding UTF8 $ColorsFile | ConvertFrom-Json
# Matches logger.py's get_logger() naming (logging.getLogger(f"asra.{category}")) -- a real log
# line reads "... [asra.TOOLS] ..." not "... [TOOLS] ...".
$loggerNamePrefix = "asra."

function Get-LineColor([string]$line) {
    foreach ($category in $categoryColors.PSObject.Properties.Name) {
        if ($line.Contains("[$loggerNamePrefix$category]")) {
            return $categoryColors.$category
        }
    }
    return $null
}

# ASCII banner so the window is instantly recognizable at a glance (a wall of raw log lines gives
# no visual anchor for which of several open windows this one is) -- project name as ASCII art,
# "DEBUG CONSOLE" centered underneath, everything else (log path, logs) unchanged below it.
$banner = @(
    '    _     ____  ____      _    ',
    '   / \   / ___||  _ \    / \   ',
    '  / _ \  \___ \| |_) |  / _ \  ',
    ' / ___ \  ___) |  _ <  / ___ \ ',
    '/_/   \_\|____/|_| \_\/_/   \_\'
)
foreach ($bannerLine in $banner) {
    Write-Host "$headerColor$bannerLine$reset"
}
$debugLabel = "D E B U G   C O N S O L E"
$bannerWidth = $banner[0].Length
$labelPadding = [Math]::Max(0, [Math]::Floor(($bannerWidth - $debugLabel.Length) / 2))
Write-Host "$dim$(' ' * $labelPadding)$debugLabel$reset"
Write-Host ""
Write-Host "$headerColor ASRA debug log -- $LogPath$reset"
Write-Host "${dim}Normal console window -- select with the mouse, or Ctrl+A/Ctrl+C, like any other console.$reset"
Write-Host ""

while (-not (Test-Path -LiteralPath $LogPath)) {
    Start-Sleep -Milliseconds 200
}

function Open-TailReader([string]$Path) {
    # FileShare.ReadWrite: agent/utils/debug.py's FileHandler keeps this file open for appending
    # the entire time the server runs, so this reader must never take an exclusive lock on it.
    $fileStream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    $streamReader = New-Object System.IO.StreamReader($fileStream, [System.Text.Encoding]::UTF8)
    # Only what gets appended from this point on -- replaying old content from a previous run (or,
    # for the per-project reader below, everything already logged earlier in the same session) on
    # every open reads as live activity that isn't actually happening right now.
    $streamReader.BaseStream.Seek(0, [System.IO.SeekOrigin]::End) | Out-Null
    return $streamReader
}

$reader = Open-TailReader $LogPath

# Global log only shows server startup / UI-clicks-between-scans / native toolkit traffic by
# design (agent/utils/debug.py's own module docstring) -- an active scan's own AGENT/LLM/TOOLS
# activity is routed to that project's own debug.log instead, so this window additionally follows
# a small pointer file (agent/utils/debug.py's _update_active_session_log_pointer) that names
# whichever project log was written to most recently, switching over live the moment a new session
# starts logging. $null until a session has ever logged anything since this window opened.
$pointerPath = Join-Path (Split-Path -Parent $LogPath) "active_session_debug_log.txt"
$projectReader = $null
$projectLogPath = $null

function Update-ProjectReader {
    if (-not (Test-Path -LiteralPath $pointerPath)) {
        return
    }
    $target = (Get-Content -Raw -Encoding UTF8 -LiteralPath $pointerPath -ErrorAction SilentlyContinue)
    if ([string]::IsNullOrWhiteSpace($target)) {
        return
    }
    $target = $target.Trim()
    if ($target -eq $script:projectLogPath) {
        return  # already tailing this exact project log, nothing changed
    }
    if (-not (Test-Path -LiteralPath $target)) {
        return  # pointer written but the file itself isn't there yet -- try again next poll
    }
    if ($script:projectReader) {
        $script:projectReader.Dispose()
    }
    $script:projectReader = Open-TailReader $target
    $script:projectLogPath = $target
    Write-Host "$dim-- now also following the active project's own log: $target$reset"
}

try {
    while ($true) {
        $sawLine = $false

        $line = $reader.ReadLine()
        if ($null -ne $line) {
            $sawLine = $true
            $color = Get-LineColor $line
            if ($color) { Write-Host "$color$line$reset" } else { Write-Host $line }
        }

        Update-ProjectReader
        if ($projectReader) {
            $projectLine = $projectReader.ReadLine()
            if ($null -ne $projectLine) {
                $sawLine = $true
                $color = Get-LineColor $projectLine
                if ($color) { Write-Host "$color$projectLine$reset" } else { Write-Host $projectLine }
            }
        }

        if (-not $sawLine) {
            Start-Sleep -Milliseconds 200
        }
    }
}
finally {
    $reader.Dispose()
    if ($projectReader) {
        $projectReader.Dispose()
    }
}
