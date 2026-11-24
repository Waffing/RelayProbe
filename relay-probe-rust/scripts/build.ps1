$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$previousRustFlags = $env:RUSTFLAGS
Push-Location $projectRoot
try {
    $targetInfo = cargo -vV
    if ($LASTEXITCODE -ne 0) { throw 'Rust toolchain not found' }
    if ($targetInfo -match 'host: x86_64-pc-windows-gnu') {
        $env:RUSTFLAGS = ($env:RUSTFLAGS + ' -C link-self-contained=yes -C target-feature=+crt-static').Trim()
    }
    cargo build --release --locked
    if ($LASTEXITCODE -ne 0) { throw 'Rust build failed' }
    Write-Output (Join-Path $projectRoot 'target\release\relay-probe.exe')
} finally {
    $env:RUSTFLAGS = $previousRustFlags
    Pop-Location
}
