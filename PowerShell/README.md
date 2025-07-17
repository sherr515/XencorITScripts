# PowerShell Administration Scripts

This directory contains comprehensive PowerShell scripts for various administrative tasks across different platforms and services. Each script is designed with security best practices, detailed documentation, and modern PowerShell practices.

## Directory Structure

```
PowerShell/
├── ActiveDirectory/
│   ├── Get-ADUserReport.ps1
│   └── Set-ADUserBulkOperations.ps1
├── Azure/
│   └── Get-AzureResourceInventory.ps1
├── Exchange/
│   └── (Exchange management scripts - to be populated)
├── SharePoint/
│   └── (SharePoint management scripts - to be populated)
├── SystemAdmin/
│   └── (System administration scripts - to be populated)
├── Utilities/
│   └── (Utility scripts - to be populated)
├── Template-Script.ps1
└── README.md
```

## Active Directory Scripts

### Get-ADUserReport.ps1
**Purpose**: Generate comprehensive Active Directory user reports with detailed information

**Key Features**:
- User account information and status
- Group memberships and permissions
- Last login and password information
- Account lockout and security status
- Organizational unit structure
- Custom attributes and properties

**Usage Examples**:
```powershell
# Generate detailed user report
.\Get-ADUserReport.ps1 -ReportType Detailed -ExportPath "C:\Reports\ADUsers.csv"

# Generate security-focused report
.\Get-ADUserReport.ps1 -Filter "Department -eq 'IT'" -ReportType Security

# Include disabled users
.\Get-ADUserReport.ps1 -SearchBase "OU=Users,DC=contoso,DC=com" -IncludeDisabled
```

### Set-ADUserBulkOperations.ps1
**Purpose**: Perform bulk operations on Active Directory users

**Key Features**:
- Bulk user creation from CSV files
- Bulk user updates and modifications
- Bulk group membership management
- Bulk password operations
- Bulk account enable/disable operations
- Bulk attribute updates
- Bulk user deletion and cleanup

**Usage Examples**:
```powershell
# Bulk user creation
.\Set-ADUserBulkOperations.ps1 -Operation Create -InputFile "users.csv" -WhatIf

# Add users to group
.\Set-ADUserBulkOperations.ps1 -Operation AddToGroup -GroupName "IT_Users" -Filter "Department -eq 'IT'"

# Bulk password reset
.\Set-ADUserBulkOperations.ps1 -Operation SetPassword -Filter "Enabled -eq `$true" -ForcePasswordChange
```

## Azure Scripts

### Get-AzureResourceInventory.ps1
**Purpose**: Comprehensive Azure resource inventory and management

**Key Features**:
- Virtual machines and their configurations
- Storage accounts and blob containers
- Network resources (VNETs, subnets, NSGs)
- Database resources (SQL, Cosmos DB, Redis)
- App Services and Function Apps
- Key Vaults and security resources
- Cost analysis and optimization recommendations
- Security assessment and compliance checks

**Usage Examples**:
```powershell
# Generate detailed inventory report
.\Get-AzureResourceInventory.ps1 -ReportType Detailed -ExportPath "C:\Reports\AzureInventory.csv"

# Include cost analysis
.\Get-AzureResourceInventory.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012" -IncludeCosts

# Security-focused report
.\Get-AzureResourceInventory.ps1 -ResourceGroup "Production-RG" -ReportType Security
```

## Common Features Across All Scripts

### Security Focus
- **Authentication**: Secure credential handling
- **Authorization**: Role-based access control
- **Audit Logging**: Comprehensive operation logging
- **Error Handling**: Secure error management
- **Input Validation**: Parameter validation and sanitization

### Performance Optimization
- **Parallel Processing**: Multi-threaded operations where appropriate
- **Batch Operations**: Efficient bulk processing
- **Resource Management**: Proper cleanup and disposal
- **Caching**: Intelligent data caching
- **Progress Reporting**: Real-time operation progress

### Monitoring and Logging
- **Structured Logging**: JSON-formatted log output
- **Log Levels**: INFO, WARNING, ERROR, SUCCESS
- **Performance Metrics**: Operation timing and statistics
- **Audit Trails**: Complete operation history
- **Export Capabilities**: Multiple output formats

### Modern PowerShell Practices
- **CmdletBinding**: Advanced parameter handling
- **Pipeline Support**: Efficient data processing
- **Error Handling**: Try-catch with proper cleanup
- **Progress Bars**: User-friendly progress indication
- **WhatIf Support**: Safe operation simulation

## Prerequisites

### System Requirements
- **PowerShell**: 5.1+ or PowerShell Core 6.0+
- **Windows**: Windows 10/11 or Windows Server 2016+
- **Memory**: 4GB+ for large operations
- **Storage**: SSD recommended for performance

### Module Dependencies
- **Active Directory**: `Import-Module ActiveDirectory`
- **Azure**: `Import-Module Az`
- **Exchange**: `Import-Module ExchangeOnlineManagement`
- **SharePoint**: `Import-Module Microsoft.Online.SharePoint.PowerShell`

### Permissions Required
- **Active Directory**: Domain User with appropriate permissions
- **Azure**: Contributor or Reader role
- **Exchange**: Exchange Administrator role
- **SharePoint**: SharePoint Administrator role

## Installation and Setup

### Quick Start
```powershell
# Clone the repository
git clone https://github.com/your-org/powershell-scripts.git
cd powershell-scripts

# Install required modules
Install-Module -Name Az -Force -AllowClobber
Install-Module -Name ExchangeOnlineManagement -Force
Install-Module -Name Microsoft.Online.SharePoint.PowerShell -Force

# Set execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Test script execution
.\ActiveDirectory\Get-ADUserReport.ps1 -WhatIf
```

### Environment Configuration
```powershell
# Create configuration file
$config = @{
    LogPath = "C:\Logs\PowerShell"
    ExportPath = "C:\Exports"
    DefaultFilter = "Enabled -eq `$true"
    VerboseLogging = $true
}

$config | ConvertTo-Json | Out-File -FilePath ".\config.json"

# Load configuration in scripts
$config = Get-Content -Path ".\config.json" | ConvertFrom-Json
```

## Usage Guidelines

### Best Practices
1. **Test First**: Always use `-WhatIf` parameter for testing
2. **Backup Data**: Create backups before bulk operations
3. **Monitor Resources**: Watch system resources during large operations
4. **Log Everything**: Enable verbose logging for troubleshooting
5. **Validate Input**: Verify CSV files and parameters before execution

### Error Handling
```powershell
# Example error handling pattern
try {
    # Operation code
    Write-Log "Operation completed successfully" -Level "SUCCESS"
} catch {
    Write-Log "Operation failed: $($_.Exception.Message)" -Level "ERROR"
    # Cleanup code
} finally {
    # Always execute cleanup
}
```

### Performance Optimization
```powershell
# Use parallel processing for large datasets
$jobs = $items | ForEach-Object -ThrottleLimit 10 -Parallel {
    # Process item
}

# Use batch operations
$batchSize = 100
$batches = [System.Linq.Enumerable]::Range(0, [Math]::Ceiling($items.Count / $batchSize)) | ForEach-Object {
    $items | Select-Object -Skip ($_ * $batchSize) -First $batchSize
}
```

## Security Considerations

### Credential Management
```powershell
# Use secure credential storage
$credential = Get-Credential -Message "Enter credentials"
$securePassword = ConvertTo-SecureString -String "password" -AsPlainText -Force

# Use Azure Key Vault for secrets
$secret = Get-AzKeyVaultSecret -VaultName "myvault" -Name "mysecret"
```

### Access Control
```powershell
# Implement role-based access
$userRoles = Get-ADUser -Identity $env:USERNAME -Properties MemberOf
$hasPermission = $userRoles.MemberOf -contains "CN=IT-Admins,OU=Groups,DC=contoso,DC=com"

if (-not $hasPermission) {
    throw "Insufficient permissions for this operation"
}
```

### Audit Logging
```powershell
# Comprehensive audit logging
$auditLog = @{
    Timestamp = Get-Date
    User = $env:USERNAME
    Operation = "Bulk User Update"
    Parameters = $PSBoundParameters
    Result = "Success"
}

$auditLog | ConvertTo-Json | Add-Content -Path ".\audit.log"
```

## Monitoring and Maintenance

### Health Checks
```powershell
# Check script health
Get-Process -Name "powershell" | Where-Object { $_.ProcessName -like "*script*" }

# Monitor resource usage
Get-Counter -Counter "\Process(powershell*)\% Processor Time" -SampleInterval 5 -MaxSamples 10
```

### Performance Monitoring
```powershell
# Measure script performance
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
# Script execution
$stopwatch.Stop()
Write-Log "Execution time: $($stopwatch.Elapsed)" -Level "INFO"
```

### Log Analysis
```powershell
# Analyze script logs
Get-ChildItem -Path ".\Logs" -Filter "*.log" | ForEach-Object {
    $content = Get-Content $_.FullName
    $errors = $content | Where-Object { $_ -like "*ERROR*" }
    $warnings = $content | Where-Object { $_ -like "*WARNING*" }
    
    Write-Host "File: $($_.Name)" -ForegroundColor Yellow
    Write-Host "Errors: $($errors.Count)" -ForegroundColor Red
    Write-Host "Warnings: $($warnings.Count)" -ForegroundColor Yellow
}
```

## Troubleshooting

### Common Issues
1. **Permission Errors**: Check user permissions and group memberships
2. **Module Errors**: Verify module installation and version compatibility
3. **Network Issues**: Check connectivity and firewall settings
4. **Resource Limits**: Monitor system resources and adjust batch sizes
5. **Timeout Errors**: Increase timeout values for large operations

### Debug Commands
```powershell
# Enable verbose debugging
$VerbosePreference = "Continue"
$DebugPreference = "Continue"

# Test module loading
Get-Module -ListAvailable | Where-Object { $_.Name -like "*AD*" }

# Test connectivity
Test-NetConnection -ComputerName "dc01.contoso.com" -Port 389

# Test Azure connectivity
Get-AzContext
Test-AzResourceGroupDeployment -ResourceGroupName "test-rg"
```

## Contributing

### Development Guidelines
1. **Follow Standards**: Use approved PowerShell coding standards
2. **Documentation**: Include comprehensive help and examples
3. **Testing**: Test all scripts before submission
4. **Security**: Implement proper security measures
5. **Performance**: Optimize for large-scale operations

### Development Process
1. **Fork Repository**: Create your own fork
2. **Create Branch**: Use feature branches for changes
3. **Make Changes**: Implement and test your changes
4. **Submit PR**: Create pull request with detailed description
5. **Review Process**: Security and code review required

## Support and Resources

### Documentation
- [PowerShell Documentation](https://docs.microsoft.com/en-us/powershell/)
- [Active Directory PowerShell](https://docs.microsoft.com/en-us/powershell/module/activedirectory/)
- [Azure PowerShell](https://docs.microsoft.com/en-us/powershell/azure/)
- [Exchange PowerShell](https://docs.microsoft.com/en-us/powershell/exchange/)

### Community Resources
- **PowerShell Gallery**: [powershellgallery.com](https://www.powershellgallery.com/)
- **Stack Overflow**: PowerShell tag
- **Reddit**: r/PowerShell
- **GitHub**: PowerShell repositories

### Training Resources
- [Microsoft Learn PowerShell](https://docs.microsoft.com/en-us/learn/paths/powershell/)
- [PowerShell Conference](https://powershell.org/events/)
- [Pluralsight PowerShell Courses](https://www.pluralsight.com/browse/software-development/powershell)

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

These scripts are provided as examples and should be adapted to your specific environment and requirements. Always test scripts in a staging environment before applying to production systems. 