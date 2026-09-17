# ==============================================================================
# Phylax (φύλαξ) — Sovereign Edge Defense Windows PowerShell Installer
# ==============================================================================
[CmdletBinding()]
param (
    [string]$InstallDir = "$HOME\.cargo\bin"
)

$ErrorActionPreference = "Stop"

Write-Host "
  ██████╗ ██╗  ██╗██╗   ██╗██╗      █████╗ ██╗  ██╗
  ██╔══██╗██║  ██║╚██╗ ██╔╝██║     ██╔══██╗╚██╗██╔╝
  ██████╔╝███████║ ╚████╔╝ ██║     ███████║ ╚███╔╝ 
  ██╔═══╝ ██╔══██║  ╚██╔╝  ██║     ██╔══██║ ██╔██╗ 
  ██║     ██║  ██║   ██║   ███████╗██║  ██║██╔╝ ██╗
  ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
  Sovereign Zero-Telemetry WAF & Edge Defense Daemon
" -ForegroundColor Cyan

# Check if Rust/Cargo is installed
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Error "Rust/Cargo is required to install Phylax on Windows. Please install from https://rustup.rs"
    exit 1
}

# Create installation directory if missing
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

Write-Host "📦 Installing Phylax binary with CLI features..." -ForegroundColor Green

if (Test-Path "Cargo.toml") {
    cargo build --release --features cli
    Copy-Item "target\release\phylax.exe" "$InstallDir\phylax.exe" -Force
} else {
    cargo install --git https://github.com/xuoxod/phylax.git --features cli
}

Write-Host "✅ Installed: $InstallDir\phylax.exe" -ForegroundColor Green

# Generate default configuration if missing
$ConfigFile = "$HOME\.config\phylax\phylax.toml"
$ConfigDir = Split-Path -Parent $ConfigFile
if (-not (Test-Path $ConfigDir)) {
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
}

if (-not (Test-Path $ConfigFile)) {
    & "$InstallDir\phylax.exe" init --output $ConfigFile
    Write-Host "⚙️  Generated default configuration: $ConfigFile" -ForegroundColor Cyan
}

Write-Host "`n🎉 Phylax installation complete!" -ForegroundColor Green
Write-Host "Quick Start:"
Write-Host "  1. Test CLI:             phylax --help"
Write-Host "  2. Run Microbenchmarks:  phylax bench"
Write-Host "  3. Start WAF Proxy:      phylax serve --upstream http://127.0.0.1:8080 --listen 127.0.0.1:3000"
