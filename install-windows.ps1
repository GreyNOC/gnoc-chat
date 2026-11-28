# gnoc chat installer for Windows 10 (2004+) and Windows 11.
#
# gnoc chat is a terminal program built for Linux and macOS. On Windows it runs inside WSL, Microsoft's
# built-in Linux layer, which is the supported way to run it. This script:
#   1. turns on WSL with Ubuntu if you do not have it yet (needs one restart),
#   2. copies gnoc chat into ~/.local/share/gnoc-chat/app inside Ubuntu and runs the normal installer there,
#   3. adds a "gnoc" command to Windows and a "gnoc chat" shortcut to your Start menu.
# Run it again at any time: it picks up where it left off and never removes your settings.

$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path

function Say($msg)  { Write-Host $msg }
function Step($msg) { Write-Host ""; Write-Host ">> $msg" -ForegroundColor Cyan }

Say "gnoc chat installer for Windows (version 2026.11.28)"

# --- 1. WSL and a Linux distribution ---------------------------------------------------------------
Step "Checking for WSL (Windows Subsystem for Linux)"
$wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
$distros = @()
if ($wsl) {
    try {
        $raw = & wsl.exe -l -q 2>$null
        $distros = @($raw | ForEach-Object { ($_ -replace "`0", '').Trim() } |
                     Where-Object { $_ -and $_ -notmatch '^docker-desktop' })
    } catch { $distros = @() }
}

if ($distros.Count -eq 0) {
    Say "WSL with a Linux distribution is not set up yet. Installing Ubuntu now."
    Say "Windows will ask for administrator permission. When it finishes, RESTART your computer,"
    Say "open 'Ubuntu' from the Start menu once to choose a Linux username and password,"
    Say "then run install-windows.cmd again to finish."
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        & wsl.exe --install -d Ubuntu
    } else {
        Start-Process -FilePath wsl.exe -ArgumentList '--install','-d','Ubuntu' -Verb RunAs -Wait
    }
    exit 0
}

$Distro = if ($distros -contains 'Ubuntu') { 'Ubuntu' } else { $distros[0] }
Say "  using the '$Distro' Linux distribution"

# --- 2. Copy into Linux and run the normal installer ------------------------------------------------
# gnoc's own folder (~/.local/share/gnoc-chat/app): replacing it on an update can never touch a folder of yours.
$App = '~/.local/share/gnoc-chat/app'
Step "Copying gnoc chat into $Distro ($App)"
$linuxSrc = (& wsl.exe -d $Distro -e wslpath -a "$Here").Trim()
if ($linuxSrc -match "'") { throw "Move the gnoc chat folder to a path without an apostrophe and run this again." }
& wsl.exe -d $Distro -e bash -c "set -e; mkdir -p ~/.local/share/gnoc-chat; rm -rf ${App}.new; mkdir -p ${App}.new; cp -r '$linuxSrc'/. ${App}.new/; rm -rf $App; mv ${App}.new $App"
if ($LASTEXITCODE -ne 0) { throw "Copying into WSL failed." }

Step "Installing Python tools inside $Distro (Linux may ask for the password you chose for Ubuntu)"
& wsl.exe -d $Distro -e bash -c "command -v python3 >/dev/null && python3 -c 'import venv, ensurepip' 2>/dev/null || (sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip)"
if ($LASTEXITCODE -ne 0) { throw "Installing Python inside WSL failed. Open Ubuntu and run: sudo apt install python3 python3-venv" }

Step "Running the gnoc chat installer inside $Distro"
& wsl.exe -d $Distro -e bash -lc "cd $App && bash install.sh"
if ($LASTEXITCODE -ne 0) { throw "The installer inside WSL failed. Open Ubuntu and run: cd ~/.local/share/gnoc-chat/app && bash install.sh" }

# --- 3. Windows command and Start menu shortcut ----------------------------------------------------
Step "Adding the gnoc command to Windows"
$binDir = Join-Path $env:LOCALAPPDATA 'gnoc-chat\bin'
New-Item -ItemType Directory -Force -Path $binDir | Out-Null
$cmd = "@echo off`r`nwsl.exe -d $Distro --cd ~ -e bash -lc ""exec ~/.local/bin/gnoc \""`$@\"""" gnoc %*`r`n"
Set-Content -Path (Join-Path $binDir 'gnoc.cmd') -Value $cmd -Encoding ASCII -NoNewline
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not $userPath) { $userPath = '' }
if (($userPath -split ';') -notcontains $binDir) {
    [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ';' + $binDir).TrimStart(';'), 'User')
    Say "  added $binDir to your PATH (open a NEW terminal window to use it)"
}

$startMenu = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
$shell = New-Object -ComObject WScript.Shell
$lnk = $shell.CreateShortcut((Join-Path $startMenu 'gnoc chat.lnk'))
$lnk.TargetPath = (Get-Command wsl.exe).Source
$lnk.Arguments = "-d $Distro --cd ~ -e bash -lc ""~/.local/bin/gnoc chat"""
$lnk.Description = 'gnoc chat - terminal AI agent'
$lnk.Save()
Say "  added 'gnoc chat' to your Start menu"

Write-Host ""
Write-Host "Installed." -ForegroundColor Green
Say "Start it from the Start menu ('gnoc chat'), or type  gnoc chat  in a new terminal window."
Say "Before the first chat, give it a model: see 'Pick a model' in README.md, or run  gnoc help"
