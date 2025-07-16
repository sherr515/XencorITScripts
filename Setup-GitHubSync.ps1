# Setup GitHub Sync
# This script automates the initial setup process for GitHub syncing

param(
    [Parameter(Mandatory=$true)]
    [string]$RepositoryName,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipAuth
)

# Colors for output
$Green = "Green"
$Yellow = "Yellow"
$Red = "Red"
$Cyan = "Cyan"

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Test-GitInstalled {
    try {
        $null = git --version
        return $true
    }
    catch {
        return $false
    }
}

function Test-GitHubCLIInstalled {
    try {
        $null = gh --version
        return $true
    }
    catch {
        return $false
    }
}

# Main setup process
Write-ColorOutput "GitHub Sync Setup" $Cyan
Write-ColorOutput "==================" $Cyan

# Check prerequisites
Write-ColorOutput "Checking prerequisites..." $Cyan

if (-not (Test-GitInstalled)) {
    Write-ColorOutput "Git is not installed. Please install Git from: https://git-scm.com/" $Red
    Write-ColorOutput "After installing Git, run this script again." $Yellow
    exit 1
}

if (-not (Test-GitHubCLIInstalled)) {
    Write-ColorOutput "GitHub CLI is not installed. Please install it from: https://cli.github.com/" $Red
    Write-ColorOutput "After installing GitHub CLI, run this script again." $Yellow
    exit 1
}

Write-ColorOutput "✓ Git is installed" $Green
Write-ColorOutput "✓ GitHub CLI is installed" $Green

# Authentication check
if (-not $SkipAuth) {
    Write-ColorOutput "`nChecking GitHub authentication..." $Cyan
    try {
        $null = gh auth status
        Write-ColorOutput "✓ GitHub authentication is configured" $Green
    }
    catch {
        Write-ColorOutput "GitHub authentication required." $Yellow
        Write-ColorOutput "Please run: gh auth login" $Yellow
        Write-ColorOutput "Then run this script again." $Yellow
        exit 1
    }
}

# Initialize git repository
Write-ColorOutput "`nInitializing Git repository..." $Cyan
.\Sync-ToGitHub.ps1 -Initialize

# Setup GitHub repository
Write-ColorOutput "`nSetting up GitHub repository..." $Cyan
.\Sync-ToGitHub.ps1 -Setup -RepositoryName $RepositoryName

Write-ColorOutput "`nSetup completed successfully!" $Green
Write-ColorOutput "You can now use .\Sync-ToGitHub.ps1 to sync changes to your repository." $Cyan 