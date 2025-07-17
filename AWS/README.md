# AWS Management Scripts

This directory contains comprehensive PowerShell scripts for managing AWS infrastructure across multiple services. Each script is designed with modern PowerShell practices, error handling, and security best practices.

## Directory Structure

```
AWS/
├── EC2/
│   ├── instance-monitoring.ps1
│   ├── backup-recovery.ps1
│   ├── instance-tagging.ps1
│   └── security-group-management.ps1
├── IAM/
│   ├── policy-management.ps1
│   └── role-management.ps1
├── Lambda/
│   ├── function-deployment.ps1
│   └── function-monitoring.ps1
├── S3/
│   ├── bucket-management.ps1
│   ├── security-audit.ps1
│   └── object-management.ps1
├── CloudFormation/
│   ├── ec2-instance.yaml
│   ├── s3-bucket.yaml
│   └── vpc-basic.yaml
└── Reporting/
    ├── cost-analysis.ps1
    ├── resource-inventory.ps1
    └── README.md
```

## EC2 Scripts

### instance-monitoring.ps1
**Purpose**: Comprehensive EC2 instance monitoring and health check script

**Key Features**:
- Real-time status checking and health monitoring
- Performance metrics collection (CPU, network, disk usage)
- Cost analysis and estimation
- Security analysis and compliance checking
- CloudWatch alarm monitoring
- Automated reporting and data export

**Usage Scenarios**:
- Daily operational monitoring and health checks
- Performance troubleshooting and optimization
- Cost analysis and budget planning
- Security compliance audits
- Capacity planning and resource optimization

**Functions**:
- `Get-InstanceStatus`: Retrieves real-time status information
- `Get-InstanceMetrics`: Collects comprehensive performance metrics
- `Get-InstanceHealth`: Performs comprehensive health checks
- `Get-InstanceCosts`: Calculates estimated costs
- `Show-InstanceAlerts`: Checks for CloudWatch alarms and security issues

### backup-recovery.ps1
**Purpose**: Comprehensive EC2 backup and disaster recovery management script

**Key Features**:
- Automated AMI (Amazon Machine Image) creation and management
- Snapshot management and lifecycle policies
- Disaster recovery procedures and testing
- Backup scheduling and automation
- Retention policy management and cleanup
- Cross-region backup replication

**Usage Scenarios**:
- Regular backup operations for production systems
- Disaster recovery planning and testing
- Compliance requirements (backup retention)
- Migration and environment replication
- Development and testing environment management

**Functions**:
- `Get-InstanceBackups`: Retrieves all backup information
- `New-InstanceBackup`: Creates complete backup of EC2 instance
- `Restore-InstanceFromBackup`: Restores instance from backup AMI
- `Remove-OldBackups`: Cleans up old backups based on retention policy
- `Set-BackupSchedule`: Sets up automated backup scheduling

### instance-tagging.ps1
**Purpose**: Comprehensive EC2 instance tagging and cost allocation management script

**Key Features**:
- Automated tag creation and management
- Cost allocation and billing organization
- Environment and project classification
- Compliance and security tagging
- Bulk tagging operations across multiple instances
- Tag validation and cleanup

**Usage Scenarios**:
- Cost allocation and billing organization
- Environment management (dev, staging, prod)
- Project and team organization
- Compliance and security requirements
- Resource lifecycle management

**Functions**:
- `Get-InstanceTags`: Retrieves all tags for a specific instance
- `Add-InstanceTags`: Adds new tags to an EC2 instance
- `Remove-InstanceTags`: Removes specific tags from an EC2 instance
- `Update-InstanceTags`: Updates existing tags on an EC2 instance
- `Bulk-TagInstances`: Applies tags to multiple instances based on pattern matching
- `Validate-InstanceTags`: Validates tags for compliance and best practices

### security-group-management.ps1
**Purpose**: Comprehensive security group management and analysis script

**Key Features**:
- Security group creation and configuration
- Rule management (ingress/egress)
- Security analysis and risk assessment
- Compliance auditing
- Bulk rule operations
- Security best practices enforcement

**Usage Scenarios**:
- Security group administration
- Network security compliance
- Risk assessment and mitigation
- Security audit preparation
- Automated security hardening

**Functions**:
- `Get-SecurityGroups`: Retrieves security group information
- `New-SecurityGroup`: Creates new security groups
- `Add-SecurityGroupRule`: Adds rules to security groups
- `Remove-SecurityGroupRule`: Removes rules from security groups
- `Analyze-SecurityGroup`: Performs security analysis
- `Audit-SecurityGroup`: Conducts compliance audits

## IAM Scripts

### policy-management.ps1
**Purpose**: Comprehensive IAM policy management and analysis script

**Key Features**:
- Policy creation and management
- Policy attachment and detachment
- Security analysis and risk assessment
- Compliance auditing
- Policy cleanup and optimization
- Best practices enforcement

**Usage Scenarios**:
- IAM policy administration
- Security compliance auditing
- Policy optimization and cleanup
- Access control management
- Security risk assessment

**Functions**:
- `Get-IAMPolicies`: Retrieves IAM policies
- `Get-PolicyDetails`: Gets detailed policy information
- `New-IAMPolicy`: Creates new IAM policies
- `Attach-PolicyToEntity`: Attaches policies to users/groups/roles
- `Detach-PolicyFromEntity`: Detaches policies from entities
- `Analyze-PolicySecurity`: Analyzes policy security risks
- `Audit-PolicyCompliance`: Audits policy compliance
- `Remove-UnusedPolicies`: Cleans up unused policies

### role-management.ps1
**Purpose**: Comprehensive IAM role management and trust relationship script

**Key Features**:
- Role creation and configuration
- Trust relationship management
- Permission auditing
- Role optimization
- Cross-account access management
- Security best practices

**Usage Scenarios**:
- IAM role administration
- Cross-account access setup
- Service-to-service authentication
- Permission auditing and optimization
- Security compliance

## Lambda Scripts

### function-deployment.ps1
**Purpose**: Comprehensive Lambda function deployment and management script

**Key Features**:
- Function packaging and deployment
- Version management
- Environment configuration
- Dependency management
- Deployment automation
- Rollback capabilities

**Usage Scenarios**:
- Lambda function deployment
- CI/CD pipeline integration
- Environment management
- Version control and rollbacks
- Automated deployments

### function-monitoring.ps1
**Purpose**: Comprehensive Lambda function monitoring and performance analysis script

**Key Features**:
- Performance metrics collection
- Error monitoring and alerting
- Log analysis
- Cost optimization
- Performance tuning
- Health monitoring

**Usage Scenarios**:
- Lambda function monitoring
- Performance optimization
- Error troubleshooting
- Cost analysis
- Health monitoring

## S3 Scripts

### bucket-management.ps1
**Purpose**: Comprehensive S3 bucket management and configuration script

**Key Features**:
- Bucket creation and configuration
- Lifecycle policy management
- Versioning and encryption setup
- Access control configuration
- Bucket optimization
- Compliance management

**Usage Scenarios**:
- S3 bucket administration
- Data lifecycle management
- Compliance requirements
- Access control setup
- Storage optimization

### security-audit.ps1
**Purpose**: Comprehensive S3 security audit and compliance script

**Key Features**:
- Security configuration auditing
- Access control analysis
- Encryption compliance checking
- Public access detection
- Security recommendations
- Compliance reporting

**Usage Scenarios**:
- Security compliance auditing
- Risk assessment
- Security hardening
- Compliance reporting
- Security monitoring

### object-management.ps1
**Purpose**: Comprehensive S3 object management and operations script

**Key Features**:
- Object operations (upload, download, copy)
- Bulk operations
- Lifecycle management
- Object analysis
- Storage optimization
- Data management

**Usage Scenarios**:
- S3 object administration
- Bulk data operations
- Storage optimization
- Data lifecycle management
- Object analysis

## CloudFormation Templates

### ec2-instance.yaml
**Purpose**: CloudFormation template for EC2 instance deployment

**Features**:
- EC2 instance creation
- Security group configuration
- IAM role attachment
- Tag management
- Monitoring setup

### s3-bucket.yaml
**Purpose**: CloudFormation template for S3 bucket deployment

**Features**:
- S3 bucket creation
- Bucket policies
- Lifecycle rules
- Encryption configuration
- Access control

### vpc-basic.yaml
**Purpose**: CloudFormation template for basic VPC setup

**Features**:
- VPC creation
- Subnet configuration
- Route tables
- Internet gateway
- Security groups

## Reporting Scripts

### cost-analysis.ps1
**Purpose**: AWS cost analysis and reporting script

**Features**:
- Cost data collection
- Cost trend analysis
- Resource cost allocation
- Budget monitoring
- Cost optimization recommendations

### resource-inventory.ps1
**Purpose**: AWS resource inventory and reporting script

**Features**:
- Resource discovery
- Inventory reporting
- Resource tagging analysis
- Compliance checking
- Resource optimization

## Common Features Across All Scripts

### Modern PowerShell Design
- Uses PowerShell 7+ features
- Modern parameter handling
- Structured error handling
- Color-coded output
- Progress indicators

### Error Handling
- Comprehensive try-catch blocks
- Graceful error recovery
- Detailed error messages
- Logging capabilities
- Error reporting

### Security Focus
- AWS credential management
- Least privilege principles
- Security best practices
- Compliance checking
- Audit capabilities

### Automation Ready
- Dry-run capabilities
- Batch operations
- Scheduled execution
- Integration friendly
- API-driven operations

### Usage Examples
Each script includes detailed usage examples and help documentation to guide users through common scenarios.

## Prerequisites

- PowerShell 7.0 or higher
- AWS CLI configured with appropriate credentials
- Required AWS permissions for the services being managed
- Network connectivity to AWS APIs

## Installation

1. Clone or download the scripts to your local machine
2. Ensure AWS CLI is installed and configured
3. Verify PowerShell 7+ is available
4. Test with dry-run mode before production use

## Usage

Each script can be run independently with appropriate parameters. Use the `-DryRun` parameter to test operations without making changes.

Example:
```powershell
.\EC2\instance-monitoring.ps1 -InstanceId i-1234567890abcdef0 -Action status
```

## Contributing

When adding new scripts or modifying existing ones:
- Follow the established documentation pattern
- Include comprehensive error handling
- Add usage examples
- Test with dry-run mode
- Update this README with new script information

## Security Notes

- Always use least privilege principles
- Test scripts in non-production environments first
- Review and audit script permissions regularly
- Use AWS IAM roles when possible
- Monitor script execution and results

## Support

For issues or questions:
1. Check the script's built-in help and usage examples
2. Review AWS CLI documentation for service-specific commands
3. Test with dry-run mode to understand script behavior
4. Verify AWS credentials and permissions 