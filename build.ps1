$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$versionPath = Join-Path $root "VERSION"
$projectPath = Join-Path $root "netmonitor-gui"
$outputPath = Join-Path $root "proxy-for-windows-app.exe"
$cachePath = Join-Path $projectPath ".cache\go-build"

try {
    Invoke-WebRequest -Uri "http://127.0.0.1:8006/exit" -UseBasicParsing -TimeoutSec 2 | Out-Null
} catch {
}

for ($i = 0; $i -lt 20; $i++) {
    try {
        Invoke-WebRequest -Uri "http://127.0.0.1:8006/ping" -UseBasicParsing -TimeoutSec 1 | Out-Null
        Start-Sleep -Milliseconds 250
    } catch {
        break
    }
}

if (!(Test-Path -LiteralPath $versionPath)) {
    "0.8.0" | Set-Content -LiteralPath $versionPath -Encoding ASCII
}

$current = (Get-Content -LiteralPath $versionPath -Raw).Trim()
if ($current -notmatch '^(\d+)\.(\d+)\.(\d+)$') {
    throw "VERSION must use MAJOR.MINOR.PATCH, got '$current'"
}

$next = "{0}.{1}.{2}" -f $Matches[1], $Matches[2], ([int]$Matches[3] + 1)
$next | Set-Content -LiteralPath $versionPath -Encoding ASCII

Push-Location $projectPath
try {
    New-Item -ItemType Directory -Force -Path $cachePath | Out-Null
    $env:GOCACHE = (Resolve-Path -LiteralPath $cachePath).Path
    go build -ldflags "-X main.appVersion=$next" -o $outputPath .
    if ($LASTEXITCODE -ne 0) {
        throw "go build failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}

Write-Host "Built proxy-for-windows-app.exe version $next"
