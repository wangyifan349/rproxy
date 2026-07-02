$ErrorActionPreference = "Stop"

function Invoke-CheckedCommand {
    param(
        [string]$StepName,
        [scriptblock]$CommandBlock
    )

    Write-Host $StepName
    & $CommandBlock

    if ($LASTEXITCODE -ne 0) {
        Write-Error "$StepName failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }
}

Invoke-CheckedCommand "[1/4] checking source formatting" { cargo fmt --check }
Invoke-CheckedCommand "[2/4] running release-mode semantic check with verbose output" { cargo check --release --verbose }
Invoke-CheckedCommand "[3/4] running clippy with warnings denied" { cargo clippy --release --all-targets --all-features --verbose -- -D warnings }
Invoke-CheckedCommand "[4/4] building optimized release binary without MSVC PDB output" { cargo build --release --verbose }

Write-Host "[done] build completed. Start the server with: .\target\release\rproxy.exe"
