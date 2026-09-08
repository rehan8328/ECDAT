$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Get-Content "$root\.env" | ForEach-Object { if ($_ -match '^([^#=]+)=(.*)$') { Set-Item -Path "Env:$($matches[1].Trim())" -Value $matches[2].Trim() } }
Set-Location "$root\backend"
& .\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port $env:API_PORT
