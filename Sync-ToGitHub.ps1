# GitHub Sync Script
# This script syncs changes from the local GitHub folder to a GitHub repository

param(
    [Parameter(Mandatory=$false)]
    [string]$CommitMessage = "Auto-sync: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
    
    [Parameter(Mandatory=$false)]
    [string]$RepositoryName = "",
    
    [Parameter(Mandatory=$false)]
    [switch]$Initialize,
    
    [Parameter(Mandatory=$false)]
    [switch]$Setup
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

function Initialize-GitRepository {
    param([string]$RepoName)
    
    Write-ColorOutput "Initializing Git repository..." $Cyan
    
    # Initialize git repository
    git init
    
    # Create .gitignore file
    $gitignoreContent = @"
# Windows
Thumbs.db
ehthumbs.db
Desktop.ini

# PowerShell
*.ps1.log

# Temporary files
*.tmp
*.temp

# IDE files
.vscode/
.idea/

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db
"@
    
    $gitignoreContent | Out-File -FilePath ".gitignore" -Encoding UTF8
    
    Write-ColorOutput "Git repository initialized successfully!" $Green
}

function Setup-GitHubRepository {
    param([string]$RepoName)
    
    if (-not (Test-GitHubCLIInstalled)) {
        Write-ColorOutput "GitHub CLI is not installed. Please install it from: https://cli.github.com/" $Red
        Write-ColorOutput "After installation, run: gh auth login" $Yellow
        return $false
    }
    
    Write-ColorOutput "Setting up GitHub repository..." $Cyan
    
    # Check if user is authenticated
    try {
        $null = gh auth status
    }
    catch {
        Write-ColorOutput "Please authenticate with GitHub first by running: gh auth login" $Red
        return $false
    }
    
    # Create repository on GitHub
    if ($RepoName) {
        gh repo create $RepoName --public --source=. --remote=origin --push
        Write-ColorOutput "GitHub repository '$RepoName' created and connected!" $Green
    } else {
        Write-ColorOutput "Please provide a repository name using -RepositoryName parameter" $Yellow
        return $false
    }
    
    return $true
}

function Sync-ToGitHub {
    Write-ColorOutput "Starting GitHub sync process..." $Cyan
    
    # Check if git is installed
    if (-not (Test-GitInstalled)) {
        Write-ColorOutput "Git is not installed. Please install Git from: https://git-scm.com/" $Red
        return
    }
    
    # Check if we're in a git repository
    if (-not (Test-Path ".git")) {
        Write-ColorOutput "Not in a git repository. Use -Initialize to create one." $Yellow
        return
    }
    
    # Check for changes
    $status = git status --porcelain
    if (-not $status) {
        Write-ColorOutput "No changes to commit." $Yellow
        return
    }
    
    # Add all changes
    Write-ColorOutput "Adding changes to staging area..." $Cyan
    git add .
    
    # Commit changes
    Write-ColorOutput "Committing changes with message: $CommitMessage" $Cyan
    git commit -m $CommitMessage
    
    # Check if remote exists
    $remote = git remote get-url origin 2>$null
    if (-not $remote) {
        Write-ColorOutput "No remote repository configured. Use -Setup to create one." $Yellow
        return
    }
    
    # Push to GitHub
    Write-ColorOutput "Pushing changes to GitHub..." $Cyan
    git push origin main
    
    Write-ColorOutput "Sync completed successfully!" $Green
}

# Main execution
try {
    # Change to the script directory
    $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
    Set-Location $scriptPath
    
    Write-ColorOutput "GitHub Sync Script" $Cyan
    Write-ColorOutput "==================" $Cyan
    
    if ($Initialize) {
        Initialize-GitRepository -RepoName $RepositoryName
    }
    elseif ($Setup) {
        Setup-GitHubRepository -RepoName $RepositoryName
    }
    else {
        Sync-ToGitHub
    }
}
catch {
    Write-ColorOutput "An error occurred: $($_.Exception.Message)" $Red
}
finally {
    Write-ColorOutput "`nScript completed." $Cyan
} 