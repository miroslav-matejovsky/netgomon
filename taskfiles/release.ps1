param(
    [Parameter(Mandatory = $true, HelpMessage = "Version to release (e.g., 1.0.0 or v1.0.0)")]
    [string]$Version
)

# Ensure we're in the root directory
$root = git rev-parse --show-toplevel 2>$null
if (-not $root) {
    Write-Error "Not in a git repository"
    exit 1
}
Set-Location $root

# --- validation checks ---

# Validate semver format first (fail fast)
if ($Version -notmatch '^v?\d+\.\d+\.\d+(-[a-zA-Z0-9]+)?(\+[a-zA-Z0-9]+)?$') {
    Write-Error "Invalid semver version: '$Version'. Expected format: X.Y.Z or vX.Y.Z (e.g., 1.0.0 or v1.0.0)"
    exit 1
}

# Normalize version: prepend 'v' if not present
if (-not $Version.StartsWith("v")) {
    $Version = "v$Version"
}

# Check working directory is clean
$status = git status --porcelain
if ($status) {
    Write-Error "Working directory is not clean. Commit or stash changes before releasing."
    exit 1
}

# Check we're on main branch
$branch = git rev-parse --abbrev-ref HEAD
if ($branch -ne "main") {
    Write-Error "Must be on 'main' branch to release. Currently on '$branch'."
    exit 1
}

# Check release tag doesn't already exist
git rev-parse --verify --quiet "$Version" 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Error "Release tag '$Version' already exists."
    exit 1
}

Write-Host "Releasing version: $Version" -ForegroundColor Green

# --- build binaries ---

Write-Host "Building binaries..." -ForegroundColor Cyan

# Detect OS and build accordingly
$binDir = "bin"
if (Test-Path $binDir) {
    Remove-Item -Recurse -Force $binDir
}
New-Item -ItemType Directory -Path $binDir | Out-Null

$buildFailed = $false

# Build for Windows
Write-Host "  Building for Windows (AMD64)..."
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -o "$binDir/crawler-$Version.exe" cmd/crawler/main.go
if ($LASTEXITCODE -ne 0) {
    $buildFailed = $true
}

# Reset environment
$env:GOOS = ""
$env:GOARCH = ""

if ($buildFailed) {
    Write-Error "Build failed for one or more targets"
    exit 1
}

Write-Host "Build complete" -ForegroundColor Green

# --- create GitHub release ---

Write-Host "Creating GitHub release..." -ForegroundColor Cyan

# Create the tag and release
git tag $Version
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to create git tag '$Version'"
    exit 1
}

git push origin $Version
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to push tag to origin"
    git tag -d $Version
    exit 1
}

# Get list of binaries
$binaries = Get-ChildItem -Path $binDir -File | Where-Object { $_.Name -like "*$Version*" }

# Build gh release create command with all binaries
$ghArgs = @("release", "create", $Version, "--title", $Version, "--notes", "", "--prerelease=false")
foreach ($bin in $binaries) {
    $ghArgs += $bin.FullName
}

Write-Host "Uploading release with binaries..."
& gh @ghArgs

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to create GitHub release"
    # Optionally clean up tag if release creation failed
    git push --delete origin $Version
    git tag -d $Version
    exit 1
}

Write-Host "Release $Version created successfully!" -ForegroundColor Green
