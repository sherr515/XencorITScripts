# GitHub Sync Script

This folder contains scripts and tools that you want to sync to your GitHub repository. The `Sync-ToGitHub.ps1` script automates the process of uploading changes to your GitHub repository.

## Prerequisites

1. **Git** - Install from https://git-scm.com/
2. **GitHub CLI** - Install from https://cli.github.com/
3. **PowerShell** - Should already be installed on Windows

## Setup Instructions

### 1. Initial Setup (First Time Only)

1. **Authenticate with GitHub:**
   ```powershell
   gh auth login
   ```

2. **Initialize the Git repository:**
   ```powershell
   .\Sync-ToGitHub.ps1 -Initialize
   ```

3. **Create and connect to GitHub repository:**
   ```powershell
   .\Sync-ToGitHub.ps1 -Setup -RepositoryName "your-repo-name"
   ```

### 2. Regular Usage

After the initial setup, simply run:
```powershell
.\Sync-ToGitHub.ps1
```

This will:
- Check for changes in the folder
- Add all changes to staging
- Commit with a timestamp
- Push to your GitHub repository

### 3. Custom Commit Messages

You can specify a custom commit message:
```powershell
.\Sync-ToGitHub.ps1 -CommitMessage "Your custom commit message"
```

## Script Features

- **Automatic change detection** - Only commits when there are actual changes
- **Colored output** - Easy to read status messages
- **Error handling** - Graceful error messages and suggestions
- **Automatic .gitignore** - Excludes common unwanted files
- **Timestamp commits** - Default commit messages include timestamps

## Folder Structure

```
GitHub/
├── Sync-ToGitHub.ps1    # Main sync script
├── README.md            # This file
└── [Your scripts here]  # Add your final scripts here
```

## Adding Your Scripts

Simply copy your final scripts into this `GitHub` folder. The sync script will automatically detect and upload any changes when you run it.

## Troubleshooting

### "Git is not installed"
- Download and install Git from https://git-scm.com/

### "GitHub CLI is not installed"
- Download and install GitHub CLI from https://cli.github.com/
- Run `gh auth login` after installation

### "Not in a git repository"
- Run `.\Sync-ToGitHub.ps1 -Initialize` to create a git repository

### "No remote repository configured"
- Run `.\Sync-ToGitHub.ps1 -Setup -RepositoryName "your-repo-name"` to create and connect to a GitHub repository

### Authentication Issues
- Run `gh auth login` to authenticate with GitHub
- Follow the prompts to complete authentication

## Notes

- The script automatically creates a `.gitignore` file to exclude common unwanted files
- All commits include timestamps by default
- The script runs from the directory where it's located
- Changes are pushed to the `main` branch by default 