# Run unit and integration tests with coverage profiling.
# Enforces a minimum total statement coverage threshold.
# When below threshold, prints packages with uncovered functions inline.

$threshold = 50.0
$coverProfile = "coverage.out"

# Define folders/packages here
$testTargets = @(
    "./todo/..."
)

go test -count=1 -tags=integration "-coverprofile=$coverProfile" -covermode=atomic @testTargets 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    go test -count=1 -tags=integration "-coverprofile=$coverProfile" -covermode=atomic @testTargets
    Write-Host "go test failed" -ForegroundColor Red
    exit 1
}

$coverLines = go tool cover "-func=$coverProfile" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "go tool cover failed" -ForegroundColor Red
    exit 1
}

# parse total and per-function coverage
$total = 0.0
$functions = [System.Collections.Generic.List[PSObject]]::new()

foreach ($line in $coverLines) {
    if ($line -match "^total:") {
        if ($line -match "([\d.]+)%") {
            $total = [double]$Matches[1]
        }
        continue
    }

    # format: <module/pkg/file.go>:<line>:   <FuncName>   <pct>%
    $fields = ($line -split '\s+').Where({ $_ -ne '' })
    if ($fields.Count -lt 3) {
        continue 
    }

    $fileRef = $fields[0]   # e.g. github.com/.../foo.go:12:
    $funcName = $fields[1]
    $pctStr = $fields[-1] -replace '%', ''
    $pct = 0.0
    if (-not [double]::TryParse($pctStr, [ref]$pct)) {
        continue 
    }

    # extract package path: everything before the last /filename.go
    $pkg = ''
    if ($fileRef -match '^(.+)/[^/]+\.go:\d+:') {
        $pkg = $Matches[1]
    }
    else {
        continue
    }

    $functions.Add([PSCustomObject]@{
            Package  = $pkg
            Func     = $funcName
            Coverage = $pct
        })
}

if ($total -ge $threshold) {
    Write-Host ("coverage: {0:F1}% -- ok" -f $total)
    exit 0
}

# --- below threshold: propose candidates ---

Write-Host ("coverage: {0:F1}% < {1:F0}% threshold" -f $total, $threshold) -ForegroundColor Yellow
Write-Host ""

# group by package, compute average coverage, sort ascending
$byPackage = $functions | Group-Object -Property Package | ForEach-Object {
    $funcs = $_.Group
    $avg = ($funcs | Measure-Object -Property Coverage -Average).Average
    [PSCustomObject]@{
        Package   = $_.Name
        AvgPct    = [Math]::Round($avg, 1)
        Functions = $funcs | Sort-Object Coverage
    }
} | Sort-Object AvgPct | Select-Object -First 15

foreach ($pkg in $byPackage) {
    # short package name: strip module prefix, keep last two segments
    $shortPkg = $pkg.Package -replace '^.+/', ''
    $parent = $pkg.Package -replace '/[^/]+$', '' -replace '^.+/', ''
    $label = "$parent/$shortPkg"

    $zeroCov = @($pkg.Functions | Where-Object { $_.Coverage -eq 0.0 } | Select-Object -First 8 | ForEach-Object { $_.Func })
    $partial = @($pkg.Functions | Where-Object { $_.Coverage -gt 0.0 -and $_.Coverage -lt $threshold } | Select-Object -First 5 | ForEach-Object { "$($_.Func)($($_.Coverage)%)" })

    $parts = @()
    if ($zeroCov) {
        $parts += "uncovered: " + ($zeroCov -join ', ') 
    }
    if ($partial) {
        $parts += "partial: " + ($partial -join ', ') 
    }
    $detail = if ($parts) {
        "  -- " + ($parts -join '  |  ') 
    }
    else {
        "" 
    }

    Write-Host ("  {0,-35} {1,5:F1}%{2}" -f $label, $pkg.AvgPct, $detail)
}

Write-Host ""
Write-Host ("coverage {0:F1}% is below threshold {1:F0}%" -f $total, $threshold) -ForegroundColor Red
exit 1
