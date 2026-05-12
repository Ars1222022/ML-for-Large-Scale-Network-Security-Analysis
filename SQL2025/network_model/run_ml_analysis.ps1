# run_ml_analysis.ps1
# Använder requirements.txt för att installera specifika versioner

$SCRIPT_PATH = Split-Path -Parent $MyInvocation.MyCommand.Path
$MAIN_SCRIPT = Join-Path $SCRIPT_PATH "analyze_network_traffic.py"
$REQ_FILE = Join-Path $SCRIPT_PATH "requirements.txt"

# ------------------------------------------------------------
# FUNKTIONER
# ------------------------------------------------------------
function Write-Color {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

function Test-CommandExists {
    param([string]$Command)
    return [bool](Get-Command $Command -ErrorAction SilentlyContinue)
}

# ------------------------------------------------------------
# 1. KONTROLLERA PYTHON
# ------------------------------------------------------------
Clear-Host
Write-Color "============================================================" -Color Cyan
Write-Color "ML ANALYS - MILJOKONTROLL" -Color Cyan
Write-Color "============================================================" -Color Cyan
Write-Color "Mapp: $SCRIPT_PATH" -Color White
Write-Color ""

Write-Color "[1/6] Kontrollerar Python..." -Color Yellow

$pythonCmd = $null
foreach ($cmd in @("python", "py", "python3")) {
    if (Test-CommandExists $cmd) {
        $pythonCmd = $cmd
        break
    }
}

if (-not $pythonCmd) {
    Write-Color "   FEL: Python ar inte installerat!" -Color Red
    pause
    exit 1
}

$version = & $pythonCmd --version
Write-Color "   OK - $version" -Color Green

# ------------------------------------------------------------
# 2. SKAPA REQUIREMENTS.TXT MED DINA SPECIFIKA VERSIONER
# ------------------------------------------------------------
Write-Color ""
Write-Color "[2/6] Skapar requirements.txt med specifika versioner..." -Color Yellow

$requirements = @"
pandas==2.2.3
numpy==1.26.4
scikit-learn==1.5.2
joblib==1.4.2
sqlalchemy==2.0.36
pyodbc==5.2.0
"@

Set-Content -Path $REQ_FILE -Value $requirements -Encoding ASCII
Write-Color "   OK - requirements.txt skapad" -Color Green
Write-Color "   Versioner:" -Color White
Get-Content $REQ_FILE | ForEach-Object { Write-Color "     $_" -Color Gray }

# ------------------------------------------------------------
# 3. UPPGRADERA PIP OCH INSTALLERA PAKET FRÅN REQUIREMENTS.TXT
# ------------------------------------------------------------
Write-Color ""
Write-Color "[3/6] Uppgraderar pip och installerar paket..." -Color Yellow

Write-Color "   Uppgraderar pip..." -NoNewline
& $pythonCmd -m pip install --upgrade pip --quiet 2>$null
Write-Color " OK" -Color Green

Write-Color "   Installerar paket från requirements.txt..." -NoNewline
& $pythonCmd -m pip install -r $REQ_FILE --quiet 2>$null

if ($LASTEXITCODE -eq 0) {
    Write-Color " OK" -Color Green
} else {
    Write-Color " FEL - försöker installera ett i taget..." -Color Yellow
    foreach ($pkg in @("pandas","numpy","scikit-learn","joblib","sqlalchemy","pyodbc")) {
        Write-Color "   Installerar $pkg..." -NoNewline
        & $pythonCmd -m pip install $pkg --quiet 2>$null
        if ($LASTEXITCODE -eq 0) { Write-Color " OK" -Color Green } else { Write-Color " FEL" -Color Red }
    }
}

# ------------------------------------------------------------
# 4. KONTROLLERA ANALYS-SKRIPTET
# ------------------------------------------------------------
Write-Color ""
Write-Color "[4/6] Kontrollerar analyze_network_traffic.py..." -Color Yellow

if (-not (Test-Path $MAIN_SCRIPT)) {
    Write-Color "   FEL: analyze_network_traffic.py finns inte!" -Color Red
    exit 1
} else {
    Write-Color "   OK - analyze_network_traffic.py finns" -Color Green
}

# ------------------------------------------------------------
# 5. KONTROLLERA MODELLFILER
# ------------------------------------------------------------
Write-Color ""
Write-Color "[5/6] Kontrollerar modellfiler..." -Color Yellow

$modelFile = Join-Path $SCRIPT_PATH "network_intrusion_model.pkl"
$featuresFile = Join-Path $SCRIPT_PATH "feature_columns.pkl"

if (Test-Path $modelFile) {
    $modelSize = [math]::Round((Get-Item $modelFile).Length / 1KB, 1)
    Write-Color "   OK - Modellfil: $modelSize KB" -Color Green
} else {
    Write-Color "   VARNING: network_intrusion_model.pkl saknas!" -Color Yellow
}

if (Test-Path $featuresFile) {
    Write-Color "   OK - Feature-fil finns" -Color Green
} else {
    Write-Color "   VARNING: feature_columns.pkl saknas!" -Color Yellow
}

# ------------------------------------------------------------
# 6. FRÅGA OM SERVERNAMN OCH KÖR
# ------------------------------------------------------------
Write-Color ""
Write-Color "[6/6] Konfiguration..." -Color Yellow

# Läs nuvarande servernamn
$currentServer = "localhost"
if (Test-Path $MAIN_SCRIPT) {
    $content = Get-Content $MAIN_SCRIPT -Raw
    if ($content -match 'SERVER_NAME\s*=\s*"([^"]+)"') {
        $currentServer = $matches[1]
    }
}

Write-Color "   Nuvarande servernamn: $currentServer" -Color White
$changeServer = Read-Host "   Vill du andra servernamnet? (j/N)"

if ($changeServer -eq "j" -or $changeServer -eq "J") {
    $newServer = Read-Host "   Ange ditt servernamn"
    if ($newServer) {
        (Get-Content $MAIN_SCRIPT) -replace 'SERVER_NAME\s*=\s*"[^"]*"', "SERVER_NAME = `"$newServer`"" | Set-Content $MAIN_SCRIPT
        Write-Color "   OK - Servernamn uppdaterat" -Color Green
    }
}

# Kör analysen
Write-Color ""
$runAnalysis = Read-Host "Vill du kora ML-analysen nu? (j/N)"

if ($runAnalysis -eq "j" -or $runAnalysis -eq "J") {
    Write-Color ""
    Write-Color "============================================================" -Color Cyan
    Write-Color "STARTAR ML-ANALYS..." -Color Cyan
    Write-Color "============================================================" -Color Cyan
    Write-Color ""
    
    & $pythonCmd $MAIN_SCRIPT
    
    Write-Color ""
    Write-Color "============================================================" -Color Green
    Write-Color "ANALYS KLAR!" -Color Green
    Write-Color "============================================================" -Color Green
}

Write-Color ""
pause