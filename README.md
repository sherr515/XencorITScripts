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
│   ├── CloudFormation/
│   ├── EC2/
│   ├── IAM/
│   ├── Lambda/
│   ├── Reporting/
│   └── S3/
├── Bash/
│   ├── Linux/
│   ├── Docker/
│   ├── Monitoring/
│   └── Utilities/
├── Config/
│   ├── Documentation/
│   ├── Settings/
│   └── Templates/
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

### 🎯 Key Features by Category

**PowerShell Scripts** - Windows administration and automation
- **Active Directory**: User reporting, bulk operations, security management
- **Azure**: Resource inventory, cost analysis, security assessment  
- **Exchange/SharePoint**: Mailbox and site management (to be populated)
- **System Admin**: Monitoring, maintenance, troubleshooting (to be populated)

**Python Scripts** - Cross-platform automation and data processing
- **API**: REST server with authentication, database integration, monitoring
- **Automation**: Backup/recovery with cloud storage (AWS S3, Google Cloud)
- **AWS**: Comprehensive resource management (EC2, S3, IAM, Lambda, CloudFormation)
- **Data Processing**: ETL, analysis, visualization, statistical reporting
- **Utilities**: System monitoring, health checks, alerting

**AWS Scripts** - Infrastructure and resource management
- **CloudFormation**: Infrastructure as code templates (EC2, S3, VPC)
- **EC2**: Instance lifecycle, monitoring, backup, security, tagging
- **IAM**: User/role management, policy administration
- **Lambda**: Serverless deployment and monitoring
- **S3**: Bucket operations, security audit, object management
- **Reporting**: Cost analysis, resource inventory, automation

**Bash Scripts** - Linux system administration
- **Docker**: Container management, deployment, monitoring, backup
- **Linux**: Security auditing, system assessment, compliance
- **Monitoring**: System monitoring, health checks, alerting
- **Utilities**: System info, backup management, user management

**Configuration Files** - Security and deployment templates
- **Settings**: SSH, firewall, nginx, apache configurations
- **Templates**: Docker Compose, Kubernetes deployment templates
- **Documentation**: Security guidelines and best practices

### PowerShell Scripts
- **ActiveDirectory/** - User reporting, bulk operations, group management
- **Azure/** - Resource inventory, cost analysis, security assessment
- **Exchange/** - Mailbox management, distribution lists, rules
- **SharePoint/** - Site management, permissions, content operations
- **SystemAdmin/** - System monitoring, maintenance, troubleshooting
- **Utilities/** - Helper functions, common operations

### Python Scripts
- **API/** - REST API server framework with authentication and database integration
- **Automation/** - Backup and recovery system with cloud storage integration
- **AWS/** - Comprehensive AWS resource management (EC2, S3, IAM, Lambda, CloudFormation)
- **DataProcessing/** - Data processing, analysis, and visualization with statistical reporting
- **Utilities/** - System monitoring and health checks with alerting capabilities

### AWS Scripts
- **CloudFormation/** - Infrastructure as code templates (EC2, S3, VPC)
- **EC2/** - Instance management, monitoring, backup, security, tagging
- **IAM/** - User and role management with policy administration
- **Lambda/** - Serverless function deployment and monitoring
- **Reporting/** - Cost analysis, resource inventory, reporting automation
- **S3/** - Bucket operations, security audit, object management

### Bash Scripts
- **Docker/** - Container management, deployment, monitoring, backup
- **Linux/** - System security auditing and assessment
- **Monitoring/** - System monitoring, health checks, alerting
- **Utilities/** - System information, backup management, user management

### Configuration Files
- **Settings/** - SSH, firewall, nginx, apache configurations
- **Templates/** - Docker Compose, Kubernetes deployment templates
- **Documentation/** - Security guidelines and best practices

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