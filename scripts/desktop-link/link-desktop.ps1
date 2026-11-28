# link-desktop.ps1 - make this Windows desktop a model server for the GreyNOC rig (run once, as your normal user).
#
# What it does:
#   1. installs Ollama for Windows if missing (winget), and configures it to listen on THIS PC's localhost only
#   2. prints the GPU, VRAM and RAM so the rig can pick models that fit
#   3. starts (and adds to your Startup folder) a hidden loop that keeps a reverse SSH tunnel up: this PC's Ollama (127.0.0.1:11434) appears on the
#      laptop at 127.0.0.1:11436. Nothing is opened on the network; only the laptop can reach it, over your existing key.
#
# With -Engine, step 1 runs gnoc's own model server (gnoc engine, llama.cpp) on 127.0.0.1:11434 instead of Ollama:
#   it installs the engine's llama.cpp build, adopts Ollama's downloaded models by hard link (no re-download), stops
#   Ollama and takes it out of Startup so the port is free, sets GNOC_ENGINE_ADDR=127.0.0.1:11434 for your user,
#   starts the engine and adds "GreyNOC-Engine.cmd" to your Startup folder. The tunnel is unchanged: it forwards
#   whatever listens on 11434.
#
# Usage (PowerShell):   powershell -ExecutionPolicy Bypass -File .\link-desktop.ps1 -Laptop <this-laptop-ip> [-Engine]
# Undo:                 delete "GreyNOC-Ollama-Link.cmd" from shell:startup and end the hidden powershell
#                       running greynoc-link-loop.ps1 (Task Manager > Details)
# Undo -Engine:         gnoc engine stop; delete "GreyNOC-Engine.cmd" from shell:startup;
#                       [Environment]::SetEnvironmentVariable("GNOC_ENGINE_ADDR", $null, "User"); then start Ollama
#                       again (Start menu) - reinstalling it puts it back in Startup. Adopted models stay in both stores.
param(
    [Parameter(Mandatory = $true)][string]$Laptop,
    [string]$User = "gn",
    [int]$RemotePort = 11436,
    [switch]$Engine
)
$ErrorActionPreference = "Stop"

Write-Host "== hardware"
# Win32_VideoController.AdapterRAM caps at 4 GB, so read the real size from the display-class registry keys
Get-ItemProperty "HKLM:\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0*" -ErrorAction SilentlyContinue |
    Where-Object { $_."HardwareInformation.qwMemorySize" } |
    ForEach-Object { "{0}  VRAM {1:N1} GB" -f $_.DriverDesc, ($_."HardwareInformation.qwMemorySize" / 1GB) }
"RAM {0:N1} GB" -f ((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
"CPU " + (Get-CimInstance Win32_Processor | Select-Object -First 1).Name

if ($Engine) {
    Write-Host "== gnoc engine"
    $gnoc = Get-Command gnoc -ErrorAction SilentlyContinue
    if (-not $gnoc) {
        Write-Host "gnoc is not on PATH. Install the Windows edition first: unzip gnoc-chat-<version>-windows.zip,"
        Write-Host "double-click install-windows.cmd (no administrator rights), then open a NEW PowerShell window"
        Write-Host "and run this script again with -Engine."
        exit 1
    }
    $gnoc = $gnoc.Source
    & $gnoc engine install
    if ($LASTEXITCODE -ne 0) { throw "gnoc engine install failed (exit $LASTEXITCODE)" }
    # Ollama's downloaded models, adopted by hard link: no second download, no second copy on disk
    & $gnoc engine import-ollama
    if ($LASTEXITCODE -ne 0) { throw "gnoc engine import-ollama failed (exit $LASTEXITCODE)" }
    # free 127.0.0.1:11434: the tray app restarts the server, so stop it first, then the server
    Get-Process -Name "ollama app", "ollama" -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 2   # let the port close before the engine binds it
    $startupDir = [Environment]::GetFolderPath("Startup")
    Get-ChildItem -LiteralPath $startupDir -Filter "Ollama*.lnk" -ErrorAction SilentlyContinue |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force; Write-Host "removed from Startup: $($_.Name)" }
    [Environment]::SetEnvironmentVariable("GNOC_ENGINE_ADDR", "127.0.0.1:11434", "User")
    $env:GNOC_ENGINE_ADDR = "127.0.0.1:11434"
    & $gnoc engine start
    if ($LASTEXITCODE -ne 0) { throw "gnoc engine start failed (exit $LASTEXITCODE)" }
    # started at logon from the Startup folder, like the tunnel below (no admin rights needed)
    $engineLauncher = Join-Path $startupDir "GreyNOC-Engine.cmd"
    "@start `"`" /min powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command `"& '$gnoc' engine start`"" |
        Set-Content -Encoding ASCII $engineLauncher
    Write-Host "  auto-start: $engineLauncher   (delete that file to stop it starting at logon)"
} else {
    Write-Host "== ollama"
    if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) {
        winget install --id Ollama.Ollama -e --accept-source-agreements --accept-package-agreements
        $env:Path += ";$env:LOCALAPPDATA\Programs\Ollama"
    }
    # localhost only, one 16k slot like the laptop, flash attention, quantised KV cache to fit bigger models
    [Environment]::SetEnvironmentVariable("OLLAMA_HOST", "127.0.0.1:11434", "User")
    [Environment]::SetEnvironmentVariable("OLLAMA_CONTEXT_LENGTH", "16384", "User")
    [Environment]::SetEnvironmentVariable("OLLAMA_FLASH_ATTENTION", "1", "User")
    [Environment]::SetEnvironmentVariable("OLLAMA_KV_CACHE_TYPE", "q8_0", "User")
    [Environment]::SetEnvironmentVariable("OLLAMA_KEEP_ALIVE", "30m", "User")
    Write-Host "Ollama env set. Quit Ollama from the tray and start it again so it picks these up."
}

Write-Host "== tunnel"
$ssh = (Get-Command ssh).Source
# BatchMode + ConnectTimeout: a rejected key or a changed host key otherwise waits for an answer in a HIDDEN window,
# and the link never comes back (QAQC 2026-11-19)
$sshArgs = "-N -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes " +
           "-R 127.0.0.1:${RemotePort}:127.0.0.1:11434 $User@$Laptop"
# one-shot test: open the same forward, print OK on the laptop side, exit (no Ctrl+C needed)
# 2026-10-28: capture stderr. ssh reports a BUSY REMOTE PORT as "remote port forwarding failed for
# listen port N", which is a completely different problem from a key failure, and the old message blamed
# the key either way. A half-open sshd session on the laptop keeps the port bound after the desktop goes
# away (the laptop has no ClientAliveInterval set), so this is the COMMON failure, not the rare one, and
# it cost a confusing round-trip when it was read as an auth problem.
$out = & $ssh -o BatchMode=yes -o ExitOnForwardFailure=yes -R "127.0.0.1:${RemotePort}:127.0.0.1:11434" "$User@$Laptop" "echo TUNNEL-OK" 2>&1
$out | Where-Object { $_ -notmatch "TUNNEL-OK" } | ForEach-Object { Write-Host $_ }
if ($LASTEXITCODE -ne 0) {
    if ("$out" -match "remote port forwarding failed") {
        throw @"
port $RemotePort on the laptop is ALREADY BOUND by a stale tunnel, so this one refused to start.
Your key login is fine - that is not the problem.

FIX IT ON THE LAPTOP (not here), in a terminal:
    sudo ss -ltnp 'sport = :$RemotePort' | grep -oP 'pid=\K[0-9]+' | xargs -r sudo kill
    ss -ltn | grep $RemotePort        # expect NO output

then run this script again. The stale listener is an orphaned sshd child from a previous desktop
session; the laptop never reaps it because ClientAliveInterval is unset in its sshd_config.
"@
    }
    throw "tunnel test failed (exit $LASTEXITCODE): check the key login to $User@$Laptop"
}

# keep-alive loop script in the user profile, started hidden from the Startup folder (no admin rights needed)
$loop = Join-Path $HOME "greynoc-link-loop.ps1"
@"
while (`$true) {
    & '$ssh' $sshArgs
    Start-Sleep 15
}
"@ | Set-Content -Encoding ASCII $loop
$startup = [Environment]::GetFolderPath("Startup")
$launcher = Join-Path $startup "GreyNOC-Ollama-Link.cmd"
"@start `"`" /min powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$loop`"" |
    Set-Content -Encoding ASCII $launcher
# stop an older copy, then start one now
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
    Where-Object { $_.CommandLine -like "*greynoc-link-loop.ps1*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Start-Process powershell.exe -WindowStyle Hidden -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$loop`""
Write-Host ("linked: the laptop now reaches this PC's " + $(if ($Engine) { "gnoc engine" } else { "Ollama" }) +
            " at 127.0.0.1:$RemotePort")
Write-Host "  auto-start: $launcher   (delete that file to stop it starting at logon)"
