# MaunPrekshak Windows Installer
# Usage: irm https://raw.githubusercontent.com/PramanKasliwal/maunprekshak/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

Write-Host "📡 Installing/Updating MaunPrekshak..." -ForegroundColor Cyan

# 1. Ensure Python is installed
$pythonCmd = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonCmd = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonCmd = "py"
} else {
    Write-Host "❌ Error: Python is not installed or not in PATH." -ForegroundColor Red
    Write-Host "Please install Python from https://www.python.org/downloads/ and check 'Add python.exe to PATH'." -ForegroundColor Yellow
    exit 1
}

# 2. Install or upgrade maunprekshak
& $pythonCmd -m pip install --upgrade maunprekshak

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Installation via pip failed." -ForegroundColor Red
    exit $LASTEXITCODE
}

# 3. Locate Python Scripts directory
$scriptsDir = (& $pythonCmd -c "import sysconfig; print(sysconfig.get_path('scripts'))").Trim()

# 4. Check if scriptsDir is in PATH
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
$machinePath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
$combinedPath = "$userPath;$machinePath"

if ($combinedPath -split ";" -notcontains $scriptsDir -and $env:PATH -split ";" -notcontains $scriptsDir) {
    Write-Host "⚙️ Adding Python Scripts directory to User PATH: $scriptsDir" -ForegroundColor Yellow
    $newPath = if ([string]::IsNullOrWhiteSpace($userPath)) { $scriptsDir } else { "$userPath;$scriptsDir" }
    [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
    $env:PATH = "$env:PATH;$scriptsDir"
    Write-Host "✅ Added $scriptsDir to your User PATH." -ForegroundColor Green
    Write-Host "ℹ️ Please restart open terminal windows for the PATH changes to take full effect." -ForegroundColor Cyan
}

Write-Host ""
Write-Host "🎉 MaunPrekshak installed successfully!" -ForegroundColor Green
Write-Host "Try running:" -ForegroundColor Cyan
Write-Host "  mp --help" -ForegroundColor White
Write-Host "Or via Python module:" -ForegroundColor Cyan
Write-Host "  $pythonCmd -m maunprekshak --help" -ForegroundColor White
