# AWS Reporting Scripts

This directory contains PowerShell scripts for comprehensive AWS reporting and analysis.

## 📊 Scripts

### 1. Cost Analysis Script (`cost-analysis.ps1`)
Comprehensive AWS cost analysis and reporting with detailed breakdowns and recommendations.

**Features:**
- Monthly cost breakdown by service
- Cost trends over time
- Resource utilization analysis
- Cost optimization recommendations
- HTML report generation with charts
- Console output with summary statistics

**Usage:**
```powershell
# Basic cost analysis (last 30 days)
.\cost-analysis.ps1

# Detailed analysis for specific period
.\cost-analysis.ps1 -StartDate "2024-01-01" -EndDate "2024-01-31" -Detailed

# Analysis for specific region
.\cost-analysis.ps1 -Region us-west-2 -OutputPath "C:\Reports"
```

**Parameters:**
- `Region`: AWS region to analyze (default: us-east-1)
- `StartDate`: Start date for analysis (default: 30 days ago)
- `EndDate`: End date for analysis (default: today)
- `OutputPath`: Path to save reports (default: current directory)
- `Detailed`: Generate detailed cost breakdown

**Output:**
- HTML report with cost breakdown charts
- Console summary with top 5 services by cost
- Cost optimization recommendations

### 2. Resource Inventory Script (`resource-inventory.ps1`)
Comprehensive AWS resource inventory with detailed information and export capabilities.

**Features:**
- EC2 instances with details (type, state, IP addresses)
- S3 buckets and their properties
- RDS instances with configuration details
- Security groups and their rules
- IAM users and roles
- Load balancers and target groups
- CloudWatch alarms
- Optional CSV export for data analysis

**Usage:**
```powershell
# Basic resource inventory
.\resource-inventory.ps1

# Detailed inventory with tags
.\resource-inventory.ps1 -IncludeTags -ExportCSV

# Inventory for specific region
.\resource-inventory.ps1 -Region us-west-2 -OutputPath "C:\Reports"
```

**Parameters:**
- `Region`: AWS region to analyze (default: us-east-1)
- `OutputPath`: Path to save reports (default: current directory)
- `IncludeTags`: Include resource tags in the report
- `ExportCSV`: Export data to CSV format as well

**Output:**
- HTML report with resource summaries
- Optional CSV files for each resource type
- Console summary with resource counts

## 🔧 Prerequisites

### Required AWS Tools
```powershell
# Install AWS.Tools PowerShell module
Install-Module -Name AWS.Tools -Force -AllowClobber

# Install AWS CLI
# Download from: https://aws.amazon.com/cli/
```

### AWS Credentials
Configure AWS credentials using one of these methods:

**Option 1: AWS CLI Configuration**
```bash
aws configure
```

**Option 2: PowerShell AWS Credentials**
```powershell
Set-AWSCredential -AccessKey YOUR_ACCESS_KEY -SecretKey YOUR_SECRET_KEY
```

**Option 3: IAM Role (for EC2 instances)**
```powershell
# Automatically uses instance metadata service
```

## 📈 Report Examples

### Cost Analysis Report
The cost analysis script generates an HTML report with:
- **Cost Summary**: Total cost and period analyzed
- **Service Breakdown**: Cost by AWS service with percentages
- **Resource Summary**: Count of different resource types
- **Recommendations**: Cost optimization suggestions
- **Important Notes**: Best practices and considerations

### Resource Inventory Report
The resource inventory script generates an HTML report with:
- **Resource Summary**: Count of all resource types
- **EC2 Instances**: Instance details with status indicators
- **S3 Buckets**: Bucket information and locations
- **RDS Instances**: Database configuration details
- **Security Groups**: Security group rules and descriptions

## 🚀 Advanced Usage

### Scheduled Reporting
Set up automated reporting using Windows Task Scheduler:

```powershell
# Create a scheduled task for daily cost analysis
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Dev\GitHub\AWS\Reporting\cost-analysis.ps1 -OutputPath C:\Reports"
$Trigger = New-ScheduledTaskTrigger -Daily -At 9:00AM
Register-ScheduledTask -TaskName "AWS Daily Cost Report" -Action $Action -Trigger $Trigger
```

### Custom Reporting Periods
```powershell
# Monthly cost analysis
.\cost-analysis.ps1 -StartDate (Get-Date).AddMonths(-1).ToString("yyyy-MM-dd") -EndDate (Get-Date).ToString("yyyy-MM-dd")

# Quarterly analysis
.\cost-analysis.ps1 -StartDate (Get-Date).AddMonths(-3).ToString("yyyy-MM-dd") -EndDate (Get-Date).ToString("yyyy-MM-dd")
```

### Multi-Region Analysis
```powershell
# Analyze costs across multiple regions
$Regions = @("us-east-1", "us-west-2", "eu-west-1")
foreach ($Region in $Regions) {
    .\cost-analysis.ps1 -Region $Region -OutputPath "C:\Reports\$Region"
}
```

## 📊 Data Export

### CSV Export
The resource inventory script can export data to CSV files:
```powershell
.\resource-inventory.ps1 -ExportCSV -OutputPath "C:\Reports"
```

This creates separate CSV files for each resource type:
- `EC2Instances-YYYY-MM-DD_HH-mm.csv`
- `S3Buckets-YYYY-MM-DD_HH-mm.csv`
- `RDSInstances-YYYY-MM-DD_HH-mm.csv`
- `SecurityGroups-YYYY-MM-DD_HH-mm.csv`
- `IAMUsers-YYYY-MM-DD_HH-mm.csv`
- `IAMRoles-YYYY-MM-DD_HH-mm.csv`
- `LoadBalancers-YYYY-MM-DD_HH-mm.csv`
- `CloudWatchAlarms-YYYY-MM-DD_HH-mm.csv`

### Custom Data Analysis
Use the CSV exports for custom analysis:
```powershell
# Import CSV data for analysis
$EC2Data = Import-Csv "C:\Reports\EC2Instances-2024-01-15_14-30.csv"

# Analyze instance types
$EC2Data | Group-Object InstanceType | Sort-Object Count -Descending

# Find stopped instances
$EC2Data | Where-Object { $_.State -eq "stopped" }
```

## 🔍 Troubleshooting

### Common Issues

**1. Authentication Errors**
```powershell
# Verify AWS credentials
Get-AWSCredential

# Reconfigure credentials
Set-AWSCredential -AccessKey YOUR_ACCESS_KEY -SecretKey YOUR_SECRET_KEY
```

**2. Permission Errors**
Ensure your AWS user/role has the following permissions:
- `ce:GetCostAndUsage`
- `ec2:DescribeInstances`
- `s3:ListAllMyBuckets`
- `rds:DescribeDBInstances`
- `iam:ListUsers`
- `iam:ListRoles`
- `cloudwatch:DescribeAlarms`

**3. Region-Specific Issues**
```powershell
# Verify region access
Get-EC2Instance -Region us-east-1

# Set default region
Set-DefaultAWSRegion -Region us-east-1
```

### Debug Mode
Enable verbose output for troubleshooting:
```powershell
$VerbosePreference = "Continue"
.\cost-analysis.ps1 -Verbose
```

## 📝 Best Practices

### Security
- Use IAM roles instead of access keys when possible
- Implement least privilege access for reporting scripts
- Store sensitive data in AWS Secrets Manager
- Enable CloudTrail for audit logging

### Performance
- Run reports during off-peak hours
- Use appropriate AWS regions for faster access
- Consider pagination for large datasets
- Cache results when possible

### Maintenance
- Regularly update AWS.Tools module
- Review and update report templates
- Monitor script execution times
- Archive old reports periodically

## 🔄 Integration

### Email Notifications
```powershell
# Send cost report via email
$ReportPath = "C:\Reports\aws-cost-report-$(Get-Date -Format 'yyyy-MM-dd_HH-mm').html"
Send-MailMessage -From "aws-reports@company.com" -To "admin@company.com" -Subject "AWS Cost Report" -Body "Please find attached the AWS cost report." -Attachments $ReportPath -SmtpServer "smtp.company.com"
```

### Slack Integration
```powershell
# Send summary to Slack
$WebhookUrl = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
$Summary = "AWS Cost Report: Total cost $TotalCost for period $StartDate to $EndDate"
Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body @{text=$Summary} -ContentType "application/json"
```

## 📚 Additional Resources

- [AWS Cost Explorer API](https://docs.aws.amazon.com/ce/)
- [AWS PowerShell Tools](https://docs.aws.amazon.com/powershell/)
- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)
- [AWS Cost Optimization Best Practices](https://aws.amazon.com/cost-optimization/) 