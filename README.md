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

### 📂 Clickable Folder Links

**Main Categories:**
- [PowerShell](#powershell-scripts)
- [Python](#python-scripts)
- [AWS](#aws-scripts)
- [Bash](#bash-scripts)
- [Configuration Files](#configuration-files)

**PowerShell**
- [ActiveDirectory](#active-directory-scripts)
- [Azure](#azure-scripts)
- [Exchange](#exchange-scripts)
- [SharePoint](#sharepoint-scripts)
- [SystemAdmin](#system-administration-scripts)
- [Utilities](#utility-scripts)

**Python**
- [API](#api-scripts)
- [Automation](#automation-scripts)
- [AWS](#aws-python-scripts)
- [DataProcessing](#data-processing-scripts)
- [Utilities](#python-utilities)

**AWS**
- [CloudFormation](#cloudformation-scripts)
- [EC2](#ec2-scripts)
- [IAM](#iam-scripts)
- [Lambda](#lambda-scripts)
- [Reporting](#reporting-scripts)
- [S3](#s3-scripts)

**Bash**
- [Linux](#linux-scripts)
- [Docker](#docker-scripts)
- [Monitoring](#monitoring-scripts)
- [Utilities](#bash-utilities)

**Configuration**
- [Documentation](#documentation)
- [Settings](#settings)
- [Templates](#templates)

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
- **Exchange**: Mailbox reporting, storage analysis, security assessment
- **SharePoint**: Site inventory, permissions analysis, customization tracking
- **System Admin**: System health monitoring, performance analysis, remote management
- **Utilities**: System inventory, asset management, hardware tracking

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

## 📂 Detailed Script Descriptions

### PowerShell Scripts

#### Active Directory Scripts
- **Get-ADUserReport.ps1**: Comprehensive user reporting with security analysis
- **Set-ADUserBulkOperations.ps1**: Bulk user management and operations

#### Azure Scripts
- **Get-AzureResourceInventory.ps1**: Complete Azure resource inventory and cost analysis

#### Exchange Scripts
- **Get-ExchangeMailboxReport.ps1**: Mailbox reporting, storage analysis, security assessment

#### SharePoint Scripts
- **Get-SharePointSiteInventory.ps1**: Site inventory, permissions analysis, customization tracking

#### System Administration Scripts
- **Get-SystemHealthReport.ps1**: System health monitoring, performance analysis, remote management

#### Utility Scripts
- **Get-SystemInventory.ps1**: System inventory, asset management, hardware tracking

### Python Scripts

#### API Scripts
- **rest_api_server.py**: REST API server with authentication and database integration

#### Automation Scripts
- **backup_manager.py**: Backup and recovery system with cloud storage integration

#### AWS Python Scripts
- **aws_manager.py**: Comprehensive AWS resource management (EC2, S3, IAM, Lambda, CloudFormation)

#### Data Processing Scripts
- **data_processor.py**: Data processing, analysis, and visualization with statistical reporting

#### Python Utilities
- **system_monitor.py**: System monitoring and health checks with alerting capabilities

### AWS Scripts

#### CloudFormation Scripts
- **ec2-instance.yaml**: EC2 instance templates with security groups and monitoring
- **s3-bucket.yaml**: S3 bucket templates with encryption and lifecycle policies
- **vpc-basic.yaml**: VPC templates with subnets and routing

#### EC2 Scripts
- **Build-EC2Instances.ps1**: EC2 instance creation and configuration
- **Manage-EC2Instances.ps1**: Instance lifecycle management and monitoring
- **Backup-Resources.ps1**: Automated backup and recovery procedures

#### IAM Scripts
- **Build-IAMAccounts.ps1**: IAM user and role creation
- **Manage-IAMUsers.ps1**: User management and policy administration

#### Lambda Scripts
- **Manage-Lambda.ps1**: Serverless function deployment and monitoring

#### Reporting Scripts
- **Analyze-Costs.ps1**: Cost analysis and optimization reporting
- **resource-inventory.ps1**: Resource inventory and compliance reporting

#### S3 Scripts
- **Build-S3Buckets.ps1**: S3 bucket creation and configuration
- **Get-S3BucketInfo.ps1**: Bucket information and security audit

### Bash Scripts

#### Linux Scripts
- **security-audit.sh**: System security auditing and compliance checking

#### Docker Scripts
- **container-manager.sh**: Container management, deployment, and monitoring

#### Monitoring Scripts
- **system-monitor.sh**: System monitoring, health checks, and alerting

#### Bash Utilities
- **system-info.sh**: System information and hardware inventory
- **backup-manager.sh**: Backup management and recovery procedures
- **user-management.sh**: User account management and administration

### Configuration Files

#### Settings
- **ssh-config.conf**: SSH server configuration with security best practices
- **firewall-rules.conf**: Firewall configuration templates
- **nginx-config.conf**: Nginx web server configuration
- **apache-config.conf**: Apache web server configuration

#### Templates
- **docker-compose.yml**: Docker Compose service templates
- **kubernetes-deployment.yml**: Kubernetes deployment templates

#### Documentation
- **security-guidelines.md**: Security best practices and guidelines

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