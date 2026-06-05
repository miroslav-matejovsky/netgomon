Write-Host "Cleaning first..."
task clean QUIET=1

# Run integration tests with gotestsum, tee output to .test-results/integration-<timestamp>.log
$ts = (Get-Date -Format "yyyyMMdd-HHmmss")
$outDir = ".test-results"
$outFile = Join-Path $outDir "integration-$ts.log"

if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir | Out-Null
}

Write-Host "Running integration tests ..."
Write-Host "saving output to $outFile"

gotestsum --format pkgname -- ./internal/etw/goetw/ ./internal/etw/rawsec/ ./internal/iphelper/ -v -run Integration 2>&1 | Tee-Object -FilePath $outFile

exit $LASTEXITCODE
