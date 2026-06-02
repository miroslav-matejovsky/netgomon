# Remove build artifacts, test results, and .exe files from repo
$foldersToRemove = @(".test-results", ".cache", "site", "bin")
foreach ($folder in $foldersToRemove) {
  Write-Host "removing folder: $folder"
  if (Test-Path $folder) {
    Remove-Item -Recurse -Force $folder
  }
}

$foldersToIgnore = @(".venv")

Write-Host "removing *.exe files (ignoring: $($foldersToIgnore -join ', '))..."
Get-ChildItem -Recurse -Filter "*.exe" -File | ForEach-Object {
  $parts = $_.FullName -split [regex]::Escape([System.IO.Path]::DirectorySeparatorChar)
  $ignored = $parts | Where-Object { $foldersToIgnore -contains $_ }
  if ($ignored) {
    Write-Host "ignoring $($_.FullName) (in excluded folder: $($ignored -join ', '))"
  }
  else {
    Write-Host "removing $($_.FullName)"
    Remove-Item -Force $_.FullName
  }
}
# this script is called from Taskfile, so the final message is printed by Taskfile, not here
# Write-Host "clean done"
