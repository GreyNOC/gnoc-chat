# comfyui-desktop.ps1 - local image generation on this Windows desktop's GPU for gnoc chat (run once, normal user).
#
# What it does:
#   1. installs 7-Zip if missing (winget) and unpacks the official ComfyUI portable build for NVIDIA GPUs into
#      %USERPROFILE%\ComfyUI_windows_portable (self-contained Python + CUDA PyTorch, nothing else installed)
#   2. downloads one SDXL checkpoint (about 6.9 GB) into its models\checkpoints folder
#   3. starts ComfyUI on THIS PC's localhost only (127.0.0.1:8188) at logon, hidden
#   4. keeps a reverse SSH tunnel up so the laptop reaches it at 127.0.0.1:18188 (same key as the Ollama link;
#      nothing is opened on the network)
# gnoc chat unloads the desktop's Ollama model before each image and frees ComfyUI's VRAM after, so the two share
# the 16 GB card.
#
# Usage (PowerShell):   powershell -ExecutionPolicy Bypass -File .\comfyui-desktop.ps1 -Laptop <this-laptop-ip>
# Undo:                 delete "GreyNOC-ComfyUI.cmd" from shell:startup, end the hidden powershell running
#                       greynoc-comfy-loop.ps1, and delete %USERPROFILE%\ComfyUI_windows_portable
param(
    [Parameter(Mandatory = $true)][string]$Laptop,
    [string]$User = "gn",
    [int]$RemotePort = 18188,
    [string]$CkptUrl = "https://huggingface.co/stabilityai/stable-diffusion-xl-base-1.0/resolve/main/sd_xl_base_1.0.safetensors"
)
$ErrorActionPreference = "Stop"
$root = Join-Path $HOME "ComfyUI_windows_portable"

Write-Host "== ComfyUI portable"
if (-not (Test-Path (Join-Path $root "run_nvidia_gpu.bat"))) {
    $7z = "C:\Program Files\7-Zip\7z.exe"
    if (-not (Test-Path $7z)) { winget install --id 7zip.7zip -e --accept-source-agreements --accept-package-agreements }
    $arch = Join-Path $env:TEMP "ComfyUI_windows_portable_nvidia.7z"
    curl.exe -L --fail -o $arch "https://github.com/comfyanonymous/ComfyUI/releases/latest/download/ComfyUI_windows_portable_nvidia.7z"
    if ($LASTEXITCODE -ne 0) { throw "download failed: get ComfyUI_windows_portable_nvidia.7z from the ComfyUI GitHub releases page by hand, unpack it to $root, and re-run" }
    & $7z x $arch "-o$HOME" -y | Out-Null
    Remove-Item $arch
}
Write-Host "ComfyUI at $root"

Write-Host "== SDXL checkpoint"
$ckptDir = Join-Path $root "ComfyUI\models\checkpoints"
$ckpt = Join-Path $ckptDir ([IO.Path]::GetFileName($CkptUrl))
if (-not (Test-Path $ckpt)) {
    curl.exe -L --fail -C - -o $ckpt $CkptUrl
    if ($LASTEXITCODE -ne 0) { throw "checkpoint download failed (re-run to resume)" }
}
Write-Host "checkpoint $ckpt"

Write-Host "== start at logon + tunnel"
$ssh = (Get-Command ssh).Source
$py = Join-Path $root "python_embeded\python.exe"
$main = Join-Path $root "ComfyUI\main.py"
& $ssh -o BatchMode=yes -o ExitOnForwardFailure=yes -R "127.0.0.1:${RemotePort}:127.0.0.1:8188" "$User@$Laptop" "echo TUNNEL-OK"
if ($LASTEXITCODE -ne 0) { throw "tunnel test failed (exit $LASTEXITCODE): run link-desktop.ps1 first so the key login works" }
$loop = Join-Path $HOME "greynoc-comfy-loop.ps1"
@"
Start-Process -WindowStyle Hidden -FilePath '$py' -ArgumentList '-s','$main','--listen','127.0.0.1','--port','8188','--disable-auto-launch' -WorkingDirectory '$root'
while (`$true) {
    & '$ssh' -N -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes -R 127.0.0.1:${RemotePort}:127.0.0.1:8188 $User@$Laptop
    Start-Sleep 15
}
"@ | Set-Content -Encoding ASCII $loop
$launcher = Join-Path ([Environment]::GetFolderPath("Startup")) "GreyNOC-ComfyUI.cmd"
"@start `"`" /min powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$loop`"" |
    Set-Content -Encoding ASCII $launcher
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
    Where-Object { $_.CommandLine -like "*greynoc-comfy-loop.ps1*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Start-Process powershell.exe -WindowStyle Hidden -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$loop`""
Write-Host "ready: the laptop reaches ComfyUI at 127.0.0.1:$RemotePort (first start takes a minute)"
Write-Host "  auto-start: $launcher"
