# UI Automation helpers for driving the real asra-desktop.exe window (the native Tauri/WebView2
# shell) without a vision-based computer-use tool -- WebView2 exposes its rendered HTML to Windows'
# own accessibility tree, so a button's visible text (e.g. "Start") is reachable as a proper named
# UIA element and can be invoked deterministically, instead of guessing screen coordinates from a
# screenshot. Dot-source this file, then call its functions.
#
# Why this exists: computer-use (vision-based desktop control) is not available in every
# environment this project's own tooling runs in -- confirmed absent in at least one real session
# that needed to click the start screen's "Start" button to test the backend-watchdog feature live.
# UI Automation needs no such capability at all: it's a standard part of Windows, reachable from
# plain PowerShell.

Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

function Get-AsraDesktopWindow {
    <#
    .SYNOPSIS
    Returns the AutomationElement for the running asra-desktop.exe's main window, or $null if it
    isn't running. Retries briefly -- right after Start-Process, the window may not be registered
    with the UIA tree yet even though the process object already exists.
    #>
    param([int]$TimeoutSeconds = 15)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $proc = Get-Process -Name "asra-desktop" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($proc -and $proc.MainWindowHandle -ne 0) {
            try {
                $elem = [System.Windows.Automation.AutomationElement]::FromHandle($proc.MainWindowHandle)
                if ($elem) { return $elem }
            } catch {}
        }
        Start-Sleep -Milliseconds 300
    }
    return $null
}

function Find-AsraButton {
    <#
    .SYNOPSIS
    Finds a button inside the asra-desktop window by its visible text (WebView2 exposes an HTML
    <button>'s text content as the UIA element's Name, so this matches exactly what an operator
    reads on screen -- "Start", "Force restart ASRA (stuck backend?)", etc).
    .PARAMETER Name
    Exact visible button text.
    .PARAMETER TimeoutSeconds
    How long to keep retrying -- the start screen's own JS can swap which buttons exist/are
    visible (e.g. after a click changes state), so a button appearing a moment later is normal,
    not a failure.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [int]$TimeoutSeconds = 15
    )

    $window = Get-AsraDesktopWindow -TimeoutSeconds $TimeoutSeconds
    if (-not $window) {
        throw "asra-desktop.exe window not found -- is it running? (Start-Process 'E:\ASRA\desktop\bin\asra-desktop.exe')"
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $condition = New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::NameProperty, $Name
        )
        $found = $window.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
        if ($found) { return $found }
        Start-Sleep -Milliseconds 300
    }
    throw "Button with name '$Name' not found in the asra-desktop window after ${TimeoutSeconds}s -- take a screenshot-free dump with Get-AsraElementTree to see what IS there."
}

function Invoke-AsraButton {
    <#
    .SYNOPSIS
    Clicks a button in the asra-desktop window by its visible text. Prefers UIA's InvokePattern
    (a real synthetic activation, same as what a screen reader or test framework would do); falls
    back to a genuine synthetic mouse click at the element's own bounding-rect center (via Win32
    SendInput) when InvokePattern isn't supported -- some WebView2-rendered controls only expose
    LegacyIAccessible, not Invoke.
    #>
    param([Parameter(Mandatory)][string]$Name)

    $element = Find-AsraButton -Name $Name
    $invokePattern = $null
    if ($element.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$invokePattern)) {
        $invokePattern.Invoke()
        return
    }

    # Fallback: real mouse click via Win32 SendInput, at the element's actual screen position --
    # not a guessed coordinate, the UIA tree's own BoundingRectangle for this exact element.
    $rect = $element.Current.BoundingRectangle
    $x = [int]($rect.X + $rect.Width / 2)
    $y = [int]($rect.Y + $rect.Height / 2)
    Add-Type -Namespace AsraWin32 -Name Mouse -MemberDefinition @'
        [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
        [DllImport("user32.dll")] public static extern void mouse_event(uint dwFlags, uint dx, uint dy, uint dwData, int dwExtraInfo);
'@ -ErrorAction SilentlyContinue
    [AsraWin32.Mouse]::SetCursorPos($x, $y)
    Start-Sleep -Milliseconds 100
    [AsraWin32.Mouse]::mouse_event(0x0002, 0, 0, 0, 0)  # MOUSEEVENTF_LEFTDOWN
    Start-Sleep -Milliseconds 50
    [AsraWin32.Mouse]::mouse_event(0x0004, 0, 0, 0, 0)  # MOUSEEVENTF_LEFTUP
}

function Get-AsraElementTree {
    <#
    .SYNOPSIS
    Debug helper: dumps every named element's ControlType/Name currently in the asra-desktop
    window, for when Find-AsraButton can't find what you expected -- WebView2's accessibility tree
    only includes what's actually rendered right now (hidden/not-yet-swapped-in elements never
    appear), so this shows the ground truth instead of guessing from the HTML source.
    #>
    param([int]$TimeoutSeconds = 15)

    $window = Get-AsraDesktopWindow -TimeoutSeconds $TimeoutSeconds
    if (-not $window) { throw "asra-desktop.exe window not found." }
    $all = $window.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
    foreach ($el in $all) {
        if ($el.Current.Name) {
            "{0,-20} {1}" -f $el.Current.ControlType.ProgrammaticName.Replace("ControlType.", ""), $el.Current.Name
        }
    }
}
