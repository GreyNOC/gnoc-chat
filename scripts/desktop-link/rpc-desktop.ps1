# rpc-desktop.ps1 - lend this desktop's GPU to the laptop so ONE big model runs across both GPUs (run once).
#
# The laptop runs llama.cpp's llama-server; this PC runs llama.cpp's ggml-rpc-server, which exposes this GPU to
# it. The model's layers are split across the two cards (about 16 GB here + 8 GB on the laptop), so a ~35B model
# runs fully on GPUs. Both ends must run the SAME llama.cpp build (the RPC protocol is version-locked): b11476.
#
# What it does:
#   1. downloads llama.cpp b11476 for this GPU (CUDA for NVIDIA, Vulkan otherwise) into %LOCALAPPDATA%\greynoc-llama
#   2. starts ggml-rpc-server on 127.0.0.1:50052 (localhost only, with a local tensor cache so the model is shipped
#      over the link once, not at every start)
#   3. keeps a reverse SSH tunnel up so the laptop reaches it at its own 127.0.0.1:50052 (same key as link-desktop.ps1)
#   4. adds itself to the Startup folder
# Nothing listens on the network. The RPC server has no authentication, which is why it stays on localhost and
# only the laptop reaches it through your SSH key.
#
# Usage (PowerShell):   powershell -ExecutionPolicy Bypass -File .\rpc-desktop.ps1 -Laptop <this-laptop-ip>
# Then on the laptop:   gnoc split up
# Undo:                 delete "GreyNOC-RPC-Link.cmd" from shell:startup, end the hidden powershell running
#                       greynoc-rpc-loop.ps1 and ggml-rpc-server.exe (Task Manager > Details)
param(
    [Parameter(Mandatory = $true)][string]$Laptop,
    [string]$User = "gn",
    [int]$Port = 50052,
    [string]$Build = "b11476"
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"   # Invoke-WebRequest is 10x slower with the progress bar

Write-Host "== gpu"
$gpus = (Get-CimInstance Win32_VideoController).Name
$gpus | ForEach-Object { "  $_" }
$nvidia = [bool]($gpus | Where-Object { $_ -match "NVIDIA" })
# CUDA 13 build: the only one that certainly carries kernels for RTX 50xx (Blackwell, sm_120); fine for older cards
$cuda = "cuda-13.4"
$flavor = if ($nvidia) { $cuda } else { "vulkan" }
Write-Host "  using the $flavor build"

Write-Host "== llama.cpp $Build"
$dir = Join-Path $env:LOCALAPPDATA "greynoc-llama\$Build-$flavor"
New-Item -ItemType Directory -Force $dir | Out-Null
$base = "https://github.com/ggml-org/llama.cpp/releases/download/$Build"
$zips = @("llama-$Build-bin-win-$flavor-x64.zip")
if ($nvidia) { $zips += "cudart-llama-bin-win-$cuda-x64.zip" }
# download to .part and rename only when complete, and unzip whenever the server is missing: an interrupted download
# used to leave a truncated zip that every later run skipped, failing with "no ggml-rpc-server.exe" for good
foreach ($z in $zips) {
    $dst = Join-Path $dir $z
    if (-not (Test-Path $dst)) {
        Write-Host "  downloading $z"
        Invoke-WebRequest "$base/$z" -OutFile "$dst.part"
        Move-Item -Force "$dst.part" $dst
    }
}
if (-not (Get-ChildItem $dir -Recurse -Include "ggml-rpc-server.exe", "rpc-server.exe" -ErrorAction SilentlyContinue)) {
    foreach ($z in $zips) {
        $dst = Join-Path $dir $z
        try { Expand-Archive -Force $dst $dir } catch { Remove-Item -Force $dst; throw "bad download $z (deleted; run again): $_" }
    }
}
$rpc = Get-ChildItem $dir -Recurse -Include "ggml-rpc-server.exe", "rpc-server.exe" | Select-Object -First 1
if (-not $rpc) { throw "no ggml-rpc-server.exe in the $Build $flavor package" }
Write-Host "  $($rpc.FullName)"

Write-Host "== free the GPU"
# Ollama on this PC keeps models in VRAM; unload them so the RPC server gets the card. (The rig's orch-bot brain
# may load one again later; gnoc split up warns when the desktop Ollama is holding VRAM.)
try {
    $ps = Invoke-RestMethod "http://127.0.0.1:11434/api/ps" -TimeoutSec 3
    foreach ($m in $ps.models) {
        Invoke-RestMethod "http://127.0.0.1:11434/api/generate" -Method Post -TimeoutSec 30 `
            -Body (@{ model = $m.name; keep_alive = 0 } | ConvertTo-Json) | Out-Null
        Write-Host "  unloaded $($m.name)"
    }
} catch { Write-Host "  (Ollama not running here, nothing to unload)" }

Write-Host "== stop the previous link"
# The old keep-alive loop's ssh still holds 127.0.0.1:50052 on the LAPTOP, and sshd refuses a second forward on
# a bound port ("remote port forwarding failed for listen port 50052"). This cleanup used to run at the END of
# the script, i.e. after the tunnel test had already thrown. It must run FIRST.
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
    Where-Object { $_.CommandLine -like "*greynoc-rpc-loop.ps1*" } |
    ForEach-Object { Write-Host "  stopping old loop (pid $($_.ProcessId))"; Stop-Process -Id $_.ProcessId -Force }
Get-CimInstance Win32_Process -Filter "Name='ssh.exe'" |
    Where-Object { $_.CommandLine -like "*:${Port}:*" } |
    ForEach-Object { Write-Host "  stopping old tunnel (pid $($_.ProcessId))"; Stop-Process -Id $_.ProcessId -Force }
Get-Process -Name "ggml-rpc-server", "rpc-server" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 3   # let the laptop's sshd release the listen port

Write-Host "== tunnel test"
$ssh = (Get-Command ssh).Source
for ($try = 1; $try -le 5; $try++) {
    & $ssh -o BatchMode=yes -o ExitOnForwardFailure=yes -R "127.0.0.1:${Port}:127.0.0.1:$Port" "$User@$Laptop" "echo TUNNEL-OK"
    if ($LASTEXITCODE -eq 0) { break }
    Write-Host "  attempt $try failed, the laptop may still be releasing the port; retrying"
    Start-Sleep 5
}
if ($LASTEXITCODE -ne 0) {
    throw ("tunnel test failed (exit $LASTEXITCODE). If it says 'remote port forwarding failed for listen port " +
           "$Port', something on the LAPTOP still holds it: there, run  pkill -f '${Port}:127.0.0.1:${Port}'  or " +
           "just reconnect this PC's link. Otherwise check the key login to $User@$Laptop.")
}

# keep-alive supervisor: the RPC server and the reverse tunnel are watched INDEPENDENTLY every 10s. The old loop
# held the tunnel with a blocking 'ssh -N', so an RPC server that died behind a healthy tunnel was never restarted
# (measured 2026-10-22: port 50052 open, nothing serving). The tunnel now runs as a tracked background process.
# Its output goes to rpc-server.log; after a crash the log is copied to the laptop (~/.cache/greynoc-rpc-desktop.log)
# so the rig can read why it died.
$cache = Join-Path $dir "cache"
$log = Join-Path $dir "rpc-server.log"
$loop = Join-Path $HOME "greynoc-rpc-loop.ps1"
@"
`$env:LLAMA_CACHE = '$cache'
`$rpcName = '$($rpc.BaseName)'
`$tun = `$null
`$lastShip = `$null
`$nextPoll = Get-Date
while (`$true) {
    # ship the log to the laptop whenever it CHANGES, not only after a crash: an RPC server that dies and is
    # restarted inside one 10s cycle otherwise leaves the laptop with no explanation at all (measured 2026-10-22).
    if (Test-Path '$log.err') {
        `$wt = (Get-Item '$log.err').LastWriteTime
        if (`$wt -ne `$lastShip) {
            `$lastShip = `$wt
            (Get-Content '$log.prev', '$log' -Tail 50 -ErrorAction SilentlyContinue) + (Get-Content '$log.err.prev', '$log.err' -Tail 200 -ErrorAction SilentlyContinue) | & '$ssh' -o BatchMode=yes $User@$Laptop 'mkdir -p ~/.cache; cat > ~/.cache/greynoc-rpc-desktop.log'
        }
    }
    # Control channel. A hung RPC server is still a RUNNING PROCESS, so presence is not health: after a client
    # is killed mid-session the server can answer TCP and nothing else, and this loop would never restart it
    # (measured 2026-10-22). The laptop, which CAN test health, asks for a restart by dropping a flag file;
    # we poll for it over the same key we already hold. Laptop side: gnoc split restart-remote.
    if ((Get-Date) -gt `$nextPoll) {
        `$nextPoll = (Get-Date).AddSeconds(20)
        `$want = & '$ssh' -o BatchMode=yes -o ConnectTimeout=10 $User@$Laptop 'if [ -f ~/.cache/greynoc-rpc-restart ]; then rm -f ~/.cache/greynoc-rpc-restart; echo RESTART; fi' 2>`$null
        if (`$want -match 'RESTART') {
            Write-Output "$(Get-Date -Format s) restart requested by the laptop"
            Get-Process -Name `$rpcName -ErrorAction SilentlyContinue | Stop-Process -Force
            Start-Sleep 2
        }
    }
    if (-not (Get-Process -Name `$rpcName -ErrorAction SilentlyContinue)) {
        # keep the DEAD run's log: the restart's redirect truncates it, and that is the only record of why it died
        if (Test-Path '$log.err') { Move-Item -Force '$log.err' '$log.err.prev' }
        if (Test-Path '$log') { Move-Item -Force '$log' '$log.prev' }
        Start-Process -WindowStyle Hidden -FilePath '$($rpc.FullName)' -WorkingDirectory '$($rpc.DirectoryName)' -ArgumentList '-H 127.0.0.1 -p $Port -c' -RedirectStandardOutput '$log' -RedirectStandardError '$log.err'
        Start-Sleep 3
    }
    if ((-not `$tun) -or `$tun.HasExited) {
        `$tun = Start-Process -PassThru -WindowStyle Hidden -FilePath '$ssh' -ArgumentList '-N', '-o', 'ServerAliveInterval=30', '-o', 'ServerAliveCountMax=3', '-o', 'ExitOnForwardFailure=yes', '-R', '127.0.0.1:${Port}:127.0.0.1:$Port', '$User@$Laptop'
    }
    Start-Sleep 10
}
"@ | Set-Content -Encoding ASCII $loop
$startup = [Environment]::GetFolderPath("Startup")
$launcher = Join-Path $startup "GreyNOC-RPC-Link.cmd"
"@start `"`" /min powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$loop`"" |
    Set-Content -Encoding ASCII $launcher
# (the old loop and RPC server were already stopped above, before the tunnel test)
Start-Process powershell.exe -WindowStyle Hidden -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$loop`""
Write-Host "linked: the laptop now reaches this GPU's RPC server at 127.0.0.1:$Port"
Write-Host "  next, on the laptop: gnoc split up"
Write-Host "  auto-start: $launcher   (delete that file to stop it starting at logon)"
