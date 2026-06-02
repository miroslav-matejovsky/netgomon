# Run integration tests with gotestsum, tee output to .test-results/integration-<timestamp>.log
$ts = (Get-Date -Format "yyyyMMdd-HHmmss")
$outDir = ".test-results"
$outFile = Join-Path $outDir "integration-$ts.log"

if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir | Out-Null
}

Write-Host "saving output to $outFile"

gotestsum --format pkgname -- -tags integration ./... 2>&1 | Tee-Object -FilePath $outFile

exit $LASTEXITCODE
