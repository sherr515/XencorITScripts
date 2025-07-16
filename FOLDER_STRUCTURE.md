# Folder Structure Overview

This document provides a detailed overview of the folder structure for organizing work scripts by type and purpose.

## 📁 Main Structure

```
GitHub/
├── PowerShell/           # PowerShell scripts for Windows administration
├── Python/              # Python scripts for automation and data processing
├── AWS/                 # AWS CLI and SDK scripts
├── Bash/                # Bash scripts for Linux/Unix systems
├── Config/              # Configuration files and templates
├── Sync-ToGitHub.ps1    # Main sync script
├── Setup-GitHubSync.ps1 # Setup automation script
├── README.md            # Main documentation
└── FOLDER_STRUCTURE.md  # This file
```

## 🔧 PowerShell Scripts

### ActiveDirectory/
- User management scripts
- Group operations
- OU management
- Password policies
- Account provisioning

**Example files:**
- `Get-UserGroupMemberships.ps1`
- `New-ADUser-Bulk.ps1`
- `Set-ADPasswordPolicy.ps1`
- `Move-ADUsers.ps1`

### Azure/
- Azure resource management
- VM operations
- Storage account management
- Azure AD operations
- Resource group management

**Example files:**
- `Get-AzureVMStatus.ps1`
- `New-AzureResourceGroup.ps1`
- `Set-AzureTags.ps1`
- `Backup-AzureResources.ps1`

### Exchange/
- Mailbox management
- Distribution list operations
- Mail flow rules
- Calendar permissions
- Email routing

**Example files:**
- `Get-MailboxPermissions.ps1`
- `New-DistributionGroup.ps1`
- `Set-MailboxQuota.ps1`
- `Export-MailboxData.ps1`

### SharePoint/
- Site management
- Permission management
- Content operations
- List management
- Site collection administration

**Example files:**
- `Get-SPUserPermissions.ps1`
- `New-SPSite.ps1`
- `Set-SPListPermissions.ps1`
- `Export-SPContent.ps1`

### SystemAdmin/
- System monitoring
- Maintenance tasks
- Troubleshooting scripts
- Performance monitoring
- Backup operations

**Example files:**
- `Get-SystemHealth.ps1`
- `Start-SystemMaintenance.ps1`
- `Test-NetworkConnectivity.ps1`
- `Backup-SystemConfig.ps1`

### Utilities/
- Helper functions
- Common operations
- Reusable modules
- Configuration scripts

**Example files:**
- `Write-Log.ps1`
- `Send-Notification.ps1`
- `Test-Connectivity.ps1`
- `Get-SystemInfo.ps1`

## 🐍 Python Scripts

### AWS/
- AWS SDK operations
- Boto3 automation
- CloudWatch monitoring
- Lambda functions
- S3 operations

**Example files:**
- `aws_ec2_manager.py`
- `s3_backup_automation.py`
- `cloudwatch_monitor.py`
- `lambda_deployer.py`

### DataProcessing/
- Data analysis
- CSV/Excel processing
- Database operations
- Reporting scripts
- Data transformation

**Example files:**
- `process_user_data.py`
- `generate_reports.py`
- `data_validation.py`
- `csv_processor.py`

### API/
- REST API interactions
- Web service automation
- API testing
- Data extraction
- Service integration

**Example files:**
- `api_client.py`
- `webhook_handler.py`
- `service_monitor.py`
- `data_sync.py`

### Automation/
- Task automation
- Scheduled operations
- Workflow automation
- Process automation
- Integration scripts

**Example files:**
- `daily_backup.py`
- `user_provisioning.py`
- `system_monitor.py`
- `report_generator.py`

### Utilities/
- Helper modules
- Common functions
- Configuration management
- Logging utilities

**Example files:**
- `logger.py`
- `config_manager.py`
- `email_sender.py`
- `file_utils.py`

## ☁️ AWS Scripts

### EC2/
- Instance management
- Auto scaling
- Monitoring
- Backup operations
- Security groups

**Example files:**
- `create_ec2_instance.sh`
- `monitor_instances.py`
- `backup_volumes.sh`
- `update_security_groups.py`

### S3/
- Bucket operations
- File management
- Lifecycle policies
- Access control
- Data migration

**Example files:**
- `s3_backup.sh`
- `bucket_policy_manager.py`
- `file_sync.py`
- `s3_cleanup.py`

### IAM/
- User management
- Role management
- Policy management
- Access control
- Security auditing

**Example files:**
- `create_iam_user.py`
- `manage_roles.sh`
- `audit_permissions.py`
- `rotate_access_keys.py`

### Lambda/
- Serverless functions
- Event processing
- API handlers
- Scheduled tasks
- Integration functions

**Example files:**
- `lambda_function.py`
- `event_processor.py`
- `api_handler.py`
- `scheduled_task.py`

### CloudFormation/
- Infrastructure templates
- Stack management
- Resource provisioning
- Template validation
- Deployment automation

**Example files:**
- `vpc_template.yaml`
- `deploy_stack.py`
- `validate_template.sh`
- `update_stack.py`

## 🐧 Bash Scripts

### Linux/
- System administration
- Package management
- Service management
- User management
- System monitoring

**Example files:**
- `system_update.sh`
- `service_monitor.sh`
- `user_management.sh`
- `disk_cleanup.sh`

### Docker/
- Container management
- Image operations
- Deployment scripts
- Container monitoring
- Registry operations

**Example files:**
- `build_image.sh`
- `deploy_container.sh`
- `container_monitor.sh`
- `cleanup_containers.sh`

### Monitoring/
- System monitoring
- Alert management
- Performance tracking
- Log analysis
- Health checks

**Example files:**
- `system_monitor.sh`
- `alert_manager.py`
- `log_analyzer.sh`
- `health_check.sh`

### Utilities/
- Helper scripts
- Common operations
- File management
- Network utilities

**Example files:**
- `backup_files.sh`
- `network_test.sh`
- `file_organizer.sh`
- `system_info.sh`

## ⚙️ Config Folder

### Templates/
- Script templates
- Configuration templates
- Documentation templates
- Standard formats

**Example files:**
- `script_template.ps1`
- `config_template.yaml`
- `readme_template.md`
- `documentation_template.md`

### Settings/
- Configuration files
- Environment settings
- Default parameters
- Global settings

**Example files:**
- `config.yaml`
- `settings.json`
- `environment.conf`
- `defaults.ini`

### Documentation/
- Script documentation
- Usage guides
- API documentation
- Best practices

**Example files:**
- `script_guide.md`
- `api_documentation.md`
- `best_practices.md`
- `troubleshooting.md`

## 📋 Naming Conventions

### PowerShell Scripts
- Use PascalCase: `Get-UserInfo.ps1`
- Include verb-noun format: `Set-Permissions.ps1`
- Add version numbers for major changes: `Backup-Data-v2.ps1`

### Python Scripts
- Use snake_case: `user_management.py`
- Include descriptive names: `aws_ec2_monitor.py`
- Add version suffixes: `data_processor_v2.py`

### Bash Scripts
- Use lowercase with underscores: `system_backup.sh`
- Include descriptive names: `docker_deploy.sh`
- Add version numbers: `monitor_services_v1.sh`

### AWS Scripts
- Use descriptive prefixes: `aws_ec2_create.sh`
- Include service names: `s3_backup.py`
- Add functionality: `lambda_deploy.py`

## 🔍 Finding Scripts

### By Type
- **PowerShell**: Windows administration, Active Directory, Exchange
- **Python**: Data processing, API integration, automation
- **AWS**: Cloud operations, infrastructure management
- **Bash**: Linux administration, system operations

### By Purpose
- **Management**: User, system, resource management
- **Monitoring**: Health checks, performance monitoring
- **Automation**: Scheduled tasks, workflow automation
- **Utilities**: Helper functions, common operations

### By Environment
- **Windows**: PowerShell scripts for Windows systems
- **Linux**: Bash scripts for Linux/Unix systems
- **Cloud**: AWS scripts for cloud operations
- **Cross-platform**: Python scripts for multiple environments

## 📚 Best Practices

### Script Organization
1. **Group by type**: PowerShell, Python, AWS, Bash
2. **Subgroup by purpose**: Management, Monitoring, Automation
3. **Use descriptive names**: Clear, meaningful script names
4. **Include documentation**: README files for each folder
5. **Version control**: Track changes and versions

### File Management
1. **Template usage**: Start with provided templates
2. **Consistent structure**: Follow standard script structure
3. **Error handling**: Include proper error handling
4. **Logging**: Add logging for debugging and monitoring
5. **Documentation**: Include usage examples and descriptions

### Security
1. **No hardcoded credentials**: Use environment variables
2. **Least privilege**: Follow security best practices
3. **Input validation**: Validate all user inputs
4. **Error messages**: Don't expose sensitive information
5. **Regular updates**: Keep scripts updated and secure 