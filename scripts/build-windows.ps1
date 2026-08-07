# Build open-gpki PKCS#11 module on native Windows → build/open-gpki-pkcs11-windows-x86_64.dll
#
# Prerequisites (either toolchain is fine):
#   A) MSVC:  rustup default stable-x86_64-pc-windows-msvc
#             + Visual Studio Build Tools (C++ / link.exe)
#   B) GNU:   rustup toolchain install stable-x86_64-pc-windows-gnu
#             rustup target add x86_64-pc-windows-gnu
#             + MinGW-w64 (provides libwinscard.a), e.g. under C:\open-gpki-mingw
#
# Usage (from repo root):
#   powershell -ExecutionPolicy Bypass -File scripts\build-windows.ps1
#   powershell -File scripts\build-windows.ps1 -MingwRoot D:\mingw64

[CmdletBinding()]
param(
    [string]$MingwRoot = "",
    [ValidateSet("auto", "msvc", "gnu")]
    [string]$Toolchain = "auto",
    [string]$OutDir = "build"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot

function Test-LinkExe {
    $cmd = Get-Command link.exe -ErrorAction SilentlyContinue
    return $null -ne $cmd
}

function Find-MingwRoot([string]$Hint) {
    $candidates = @()
    if ($Hint) { $candidates += $Hint }
    if ($env:OPEN_GPKI_MINGW) { $candidates += $env:OPEN_GPKI_MINGW }
    $candidates += @(
        "C:\open-gpki-mingw",
        "C:\mingw64",
        "C:\msys64\mingw64",
        "C:\ProgramData\mingw64",
        "$env:USERPROFILE\mingw64"
    )
    foreach ($root in $candidates) {
        if (-not $root) { continue }
        $lib = Join-Path $root "x86_64-w64-mingw32\lib\libwinscard.a"
        $bin = Join-Path $root "bin"
        if ((Test-Path $lib) -and (Test-Path $bin)) {
            return (Resolve-Path $root).Path
        }
    }
    return $null
}

function Ensure-Rustup {
    if (-not (Get-Command rustup -ErrorAction SilentlyContinue)) {
        throw "rustup not found. Install from https://rustup.rs/"
    }
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw "cargo not found. Ensure Rust is on PATH."
    }
}

Ensure-Rustup
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$useMsvc = $false
if ($Toolchain -eq "msvc") {
    $useMsvc = $true
} elseif ($Toolchain -eq "gnu") {
    $useMsvc = $false
} else {
    # auto: prefer MSVC when link.exe is available
    $useMsvc = Test-LinkExe
}

$dllSrc = $null

if ($useMsvc) {
    Write-Host "==> toolchain: windows-msvc"
    if (-not (Test-LinkExe)) {
        throw "link.exe not found. Install Visual Studio Build Tools with the C++ workload, or re-run with -Toolchain gnu"
    }
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    rustup target add x86_64-pc-windows-msvc | Out-Null
    $ErrorActionPreference = $prevEap
    $env:CARGO_TARGET_DIR = Join-Path $RepoRoot "target"
    cargo build --release --target x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed (msvc)" }
    $dllSrc = Join-Path $RepoRoot "target\x86_64-pc-windows-msvc\release\open_gpki_pkcs11.dll"
    if (-not (Test-Path $dllSrc)) {
        # host may already be msvc; artifact can land in target\release
        $dllSrc = Join-Path $RepoRoot "target\release\open_gpki_pkcs11.dll"
    }
} else {
    Write-Host "==> toolchain: windows-gnu"
    $mingw = Find-MingwRoot $MingwRoot
    if (-not $mingw) {
        throw @"
MinGW-w64 not found (need x86_64-w64-mingw32\lib\libwinscard.a).
Install a MinGW-w64 toolchain and pass -MingwRoot <path>, or set OPEN_GPKI_MINGW.
Example layout: C:\open-gpki-mingw\x86_64-w64-mingw32\lib\libwinscard.a
"@
    }
    Write-Host "    mingw: $mingw"
    $env:PATH = "$(Join-Path $mingw 'bin');$env:PATH"

    # rustup prints progress on stderr; don't treat that as terminating.
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    rustup toolchain install stable-x86_64-pc-windows-gnu | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "rustup toolchain install failed" }
    rustup target add x86_64-pc-windows-gnu --toolchain stable-x86_64-pc-windows-gnu | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "rustup target add failed" }
    $ErrorActionPreference = $prevEap

    $winscardLib = Join-Path $mingw "x86_64-w64-mingw32\lib"
    $env:CARGO_TARGET_DIR = Join-Path $RepoRoot "target"
    $env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = "rust-lld"
    $env:RUSTFLAGS = "-L native=$winscardLib"

    rustup run stable-x86_64-pc-windows-gnu cargo build --release --target x86_64-pc-windows-gnu
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed (gnu)" }
    $dllSrc = Join-Path $RepoRoot "target\x86_64-pc-windows-gnu\release\open_gpki_pkcs11.dll"
}

if (-not (Test-Path $dllSrc)) {
    throw "built DLL not found: $dllSrc"
}

$dllDst = Join-Path $OutDir "open-gpki-pkcs11-windows-x86_64.dll"
Copy-Item -Force $dllSrc $dllDst
$item = Get-Item $dllDst
Write-Host "built $($item.FullName) ($($item.Length) bytes)"
