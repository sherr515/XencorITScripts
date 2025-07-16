# Work Scripts Repository

This repository contains all scripts used at work, organized by type and purpose. The `Sync-ToGitHub.ps1` script automates the process of uploading changes to this GitHub repository.

## 📁 Folder Structure

```
GitHub/
├── PowerShell/
│   ├── ActiveDirectory/
│   ├── Azure/
│   ├── Exchange/
│   ├── SharePoint/
│   ├── SystemAdmin/
│   └── Utilities/
├── Python/
│   ├── AWS/
│   ├── DataProcessing/
│   ├── API/
│   ├── Automation/
│   └── Utilities/
├── AWS/
│   ├── EC2/
│   ├── S3/
│   ├── IAM/
│   ├── Lambda/
│   └── CloudFormation/
├── Bash/
│   ├── Linux/
│   ├── Docker/
│   ├── Monitoring/
│   └── Utilities/
├── Config/
│   ├── Templates/
│   ├── Settings/
│   └── Documentation/
└── Sync-ToGitHub.ps1
```

## 🚀 Quick Start

### Prerequisites
1. **Git** - Install from https://git-scm.com/
2. **GitHub CLI** - Install from https://cli.github.com/

### Initial Setup
1. **Authenticate with GitHub:**
   ```powershell
   gh auth login
   ```

2. **Run the automated setup:**
   ```powershell
   cd C:\Dev\GitHub
   .\Setup-GitHubSync.ps1 -RepositoryName "your-repo-name"
   ```

### Regular Usage
After setup, simply run:
```powershell
.\Sync-ToGitHub.ps1
```

## 📝 Script Categories

### PowerShell Scripts
- **ActiveDirectory/** - User management, group operations, OU management
- **Azure/** - Azure resource management, automation
- **Exchange/** - Mailbox management, distribution lists, rules
- **SharePoint/** - Site management, permissions, content operations
- **SystemAdmin/** - System monitoring, maintenance, troubleshooting
- **Utilities/** - Helper functions, common operations

### Python Scripts
- **AWS/** - AWS SDK operations, automation
- **DataProcessing/** - Data analysis, transformation, reporting
- **API/** - REST API interactions, web services
- **Automation/** - Task automation, scheduling
- **Utilities/** - Helper modules, common functions

### AWS Scripts
- **EC2/** - Instance management, monitoring, automation
- **S3/** - Bucket operations, file management
- **IAM/** - User and role management
- **Lambda/** - Serverless function scripts
- **CloudFormation/** - Infrastructure as code templates

### Bash Scripts
- **Linux/** - System administration, monitoring
- **Docker/** - Container management, deployment
- **Monitoring/** - System monitoring, alerting
- **Utilities/** - Helper scripts, common operations

## 🔧 Adding New Scripts

1. **Choose the appropriate category** based on script type and purpose
2. **Add your script** to the relevant folder
3. **Update documentation** if needed
4. **Run the sync script** to upload changes:
   ```powershell
   .\Sync-ToGitHub.ps1
   ```

## 📋 Best Practices

### Script Documentation
- Include a header comment with description, author, and date
- Document parameters and usage examples
- Add error handling and logging

### File Naming
- Use descriptive names (e.g., `Get-UserGroupMemberships.ps1`)
- Include version numbers for major changes
- Use consistent naming conventions

### Security
- Never include passwords or sensitive data in scripts
- Use environment variables or secure credential storage
- Follow least privilege principles

## 🔄 Sync Features

- **Automatic change detection** - Only commits when there are actual changes
- **Colored output** - Easy to read status messages
- **Error handling** - Graceful error messages and suggestions
- **Automatic .gitignore** - Excludes common unwanted files
- **Timestamp commits** - Default commit messages include timestamps

## 🛠️ Troubleshooting

### "Git is not installed"
- Download and install Git from https://git-scm.com/

### "GitHub CLI is not installed"
- Download and install GitHub CLI from https://cli.github.com/
- Run `gh auth login` after installation

### Authentication Issues
- Run `gh auth login` to authenticate with GitHub
- Follow the prompts to complete authentication

## 📚 Script Templates

Each folder contains template files to help you get started with new scripts. These templates include:
- Standard header structure
- Parameter handling
- Error handling
- Logging setup
- Usage examples

## 🔍 Finding Scripts

Use the folder structure to quickly locate scripts by:
- **Type**: PowerShell, Python, AWS, Bash
- **Purpose**: ActiveDirectory, Azure, EC2, etc.
- **Function**: Management, Monitoring, Utilities, etc.

## 📈 Version Control

- Each script change is automatically committed with timestamps
- Custom commit messages can be specified
- All changes are tracked and versioned
- Easy rollback to previous versions if needed 