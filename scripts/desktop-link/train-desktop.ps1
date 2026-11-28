# train-desktop.ps1 - distil our Opus transcripts into the local model on THIS PC's GPU (run once, it takes hours).
#
# The laptop builds the training set (scripts/gnoc_distill.py build + sft). This script:
#   1. makes a Python venv in %LOCALAPPDATA%\greynoc-train with PyTorch (CUDA 12.8 wheels, which carry RTX 50xx
#      Blackwell kernels) and Unsloth
#   2. copies train-sft.jsonl and gnoc_train_qlora.py from the laptop over the same SSH key link-desktop.ps1 uses
#   3. runs the QLoRA training (Huihui-Qwen3.5-9B-abliterated, 4-bit, LoRA rank 32, loss on assistant turns only)
#   4. registers the result in this PC's Ollama as huihui-qwen3.5-9b-abliterated-gnocdistill, reusing the chat
#      template and parameters of the current lead (huihui-qwen3.5-9b-abliterated-oc)
# Stop the gnoc chat lead first if it is busy: training needs the whole 16 GB.
#
# Usage (PowerShell):   powershell -ExecutionPolicy Bypass -File .\train-desktop.ps1 -Laptop <this-laptop-ip> [-Samples 4000]
# Then on the laptop:   python3 scripts/gnoc_opus_eval.py run huihui-qwen3.5-9b-abliterated-gnocdistill@desktop --n 60
#                       python3 scripts/gnoc_bench.py huihui-qwen3.5-9b-abliterated-gnocdistill@desktop
# If Unsloth will not install natively on Windows, run the same python command inside WSL2 (Ubuntu) instead.
param(
    [Parameter(Mandatory = $true)][string]$Laptop,
    [string]$User = "gn",
    [int]$Samples = 4000,
    [int]$MaxSeq = 8192,
    [string]$Name = "huihui-qwen3.5-9b-abliterated-gnocdistill"
)
$ErrorActionPreference = "Stop"
$root = Join-Path $env:LOCALAPPDATA "greynoc-train"
New-Item -ItemType Directory -Force $root | Out-Null
Set-Location $root

Write-Host "== python"
$py = (Get-Command py -ErrorAction SilentlyContinue)
if (-not $py) { winget install -e --id Python.Python.3.12 --silent; $py = Get-Command py }
if (-not (Test-Path "$root\venv")) { & py -3.12 -m venv "$root\venv" }
$vpy = "$root\venv\Scripts\python.exe"
& $vpy -m pip install --upgrade pip
& $vpy -m pip install torch --index-url https://download.pytorch.org/whl/cu128
& $vpy -m pip install "unsloth" "triton-windows" datasets trl
& $vpy -c "import torch; assert torch.cuda.is_available(), 'CUDA not visible'; print(torch.cuda.get_device_name(0))"

Write-Host "== data from the laptop"
$ws = "~/.gnoc"
scp "${User}@${Laptop}:$ws/.claude/state/orch/distill/train-sft.jsonl" "$root\train-sft.jsonl"
scp "${User}@${Laptop}:$ws/scripts/gnoc_train_qlora.py" "$root\gnoc_train_qlora.py"

Write-Host "== train ($Samples samples, max-seq $MaxSeq)"
& $vpy "$root\gnoc_train_qlora.py" --data "$root\train-sft.jsonl" --out "$root\gnoc-distill" --samples $Samples --max-seq $MaxSeq
if ($LASTEXITCODE -ne 0) { throw "training failed (exit $LASTEXITCODE)" }

Write-Host "== ollama create $Name"
$gguf = Get-ChildItem -Recurse "$root\gnoc-distill*" -Filter *.gguf | Where-Object { $_.Name -notmatch "mmproj" } |
        Sort-Object Length -Descending | Select-Object -First 1
$mf = (& ollama show huihui-qwen3.5-9b-abliterated-oc --modelfile) -split "`n" |
      Where-Object { $_ -notmatch '^FROM ' -and $_ -notmatch '^#' }
Set-Content -Encoding ascii "$root\Modelfile" (@("FROM $($gguf.FullName)") + $mf)
& ollama create $Name -f "$root\Modelfile"
Write-Host "done: $Name is in this PC's Ollama. Evaluate it from the laptop (see the header)."
