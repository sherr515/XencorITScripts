# Example Script
# This is a sample script to demonstrate the GitHub sync functionality

param(
    [Parameter(Mandatory=$false)]
    [string]$Name = "World"
)

Write-Host "Hello, $Name!" -ForegroundColor Green
Write-Host "This is an example script in your GitHub sync folder." -ForegroundColor Cyan
Write-Host "Any changes to scripts in this folder can be synced to GitHub using Sync-ToGitHub.ps1" -ForegroundColor Yellow

# Example function
function Get-CurrentTime {
    return Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}

Write-Host "Current time: $(Get-CurrentTime)" -ForegroundColor Magenta 