<#
.SYNOPSIS
    AWS Resource Inventory and Reporting Script
    
.DESCRIPTION
    This script creates a comprehensive inventory of AWS resources including:
    - EC2 instances with details
    - S3 buckets and their contents
    - RDS instances
    - Security groups and their rules
    - IAM users and roles
    - Load balancers and target groups
    - CloudWatch alarms
    
.PARAMETER Region
    AWS region to analyze (default: us-east-1)
    
.PARAMETER OutputPath
    Path to save the report (default: current directory)
    
.PARAMETER IncludeTags
    Include resource tags in the report
    
.PARAMETER ExportCSV
    Export data to CSV format as well
    
.EXAMPLE
    .\resource-inventory.ps1 -Region us-west-2
    
.EXAMPLE
    .\resource-inventory.ps1 -IncludeTags -ExportCSV -OutputPath "C:\Reports"
    
.NOTES
    Author: IT Team
    Date: 2024
    Requires: AWS CLI and PowerShell AWS.Tools module
#>

param(
    [string]$Region = "us-east-1",
    [string]$OutputPath = ".",
    [switch]$IncludeTags,
    [switch]$ExportCSV
)

# Set AWS region
Set-DefaultAWSRegion -Region $Region

# Create output directory if it doesn't exist
if (!(Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force
}

$ReportDate = Get-Date -Format "yyyy-MM-dd_HH-mm"
$ReportFile = Join-Path $OutputPath "aws-resource-inventory-$ReportDate.html"

Write-Host "Starting AWS Resource Inventory..." -ForegroundColor Green
Write-Host "Region: $Region" -ForegroundColor Yellow

try {
    # Initialize data containers
    $InventoryData = @{
        EC2Instances = @()
        S3Buckets = @()
        RDSInstances = @()
        SecurityGroups = @()
        IAMUsers = @()
        IAMRoles = @()
        LoadBalancers = @()
        CloudWatchAlarms = @()
    }
    
    # Get EC2 Instances
    Write-Host "Collecting EC2 instance data..." -ForegroundColor Cyan
    $EC2Instances = Get-EC2Instance
    foreach ($instance in $EC2Instances) {
        $instanceData = @{
            InstanceId = $instance.InstanceId
            InstanceType = $instance.InstanceType
            State = $instance.State.Name
            LaunchTime = $instance.LaunchTime
            PublicIP = $instance.PublicIpAddress
            PrivateIP = $instance.PrivateIpAddress
            Platform = $instance.Platform
            VpcId = $instance.VpcId
            SubnetId = $instance.SubnetId
        }
        
        if ($IncludeTags) {
            $instanceData.Tags = $instance.Tags
        }
        
        $InventoryData.EC2Instances += $instanceData
    }
    
    # Get S3 Buckets
    Write-Host "Collecting S3 bucket data..." -ForegroundColor Cyan
    $S3Buckets = Get-S3Bucket
    foreach ($bucket in $S3Buckets) {
        try {
            $bucketLocation = Get-S3BucketLocation -BucketName $bucket.BucketName
            $bucketData = @{
                BucketName = $bucket.BucketName
                CreationDate = $bucket.CreationDate
                Location = $bucketLocation.LocationConstraint
            }
            
            if ($IncludeTags) {
                try {
                    $bucketData.Tags = Get-S3BucketTagging -BucketName $bucket.BucketName
                } catch {
                    $bucketData.Tags = "No tags"
                }
            }
            
            $InventoryData.S3Buckets += $bucketData
        } catch {
            Write-Warning "Could not get details for bucket: $($bucket.BucketName)"
        }
    }
    
    # Get RDS Instances
    Write-Host "Collecting RDS instance data..." -ForegroundColor Cyan
    $RDSInstances = Get-RDSInstance
    foreach ($instance in $RDSInstances) {
        $instanceData = @{
            DBInstanceIdentifier = $instance.DBInstanceIdentifier
            Engine = $instance.Engine
            EngineVersion = $instance.EngineVersion
            DBInstanceClass = $instance.DBInstanceClass
            DBInstanceStatus = $instance.DBInstanceStatus
            Endpoint = $instance.Endpoint.Address
            Port = $instance.Endpoint.Port
            AvailabilityZone = $instance.AvailabilityZone
            MultiAZ = $instance.MultiAZ
        }
        
        if ($IncludeTags) {
            $instanceData.Tags = $instance.TagList
        }
        
        $InventoryData.RDSInstances += $instanceData
    }
    
    # Get Security Groups
    Write-Host "Collecting security group data..." -ForegroundColor Cyan
    $SecurityGroups = Get-EC2SecurityGroup
    foreach ($sg in $SecurityGroups) {
        $sgData = @{
            GroupId = $sg.GroupId
            GroupName = $sg.GroupName
            Description = $sg.Description
            VpcId = $sg.VpcId
            InboundRules = $sg.IpPermissions
            OutboundRules = $sg.IpPermissionsEgress
        }
        
        if ($IncludeTags) {
            $sgData.Tags = $sg.Tags
        }
        
        $InventoryData.SecurityGroups += $sgData
    }
    
    # Get IAM Users
    Write-Host "Collecting IAM user data..." -ForegroundColor Cyan
    $IAMUsers = Get-IAMUser
    foreach ($user in $IAMUsers) {
        $userData = @{
            UserName = $user.UserName
            UserId = $user.UserId
            Arn = $user.Arn
            CreateDate = $user.CreateDate
            PasswordLastUsed = $user.PasswordLastUsed
        }
        
        if ($IncludeTags) {
            $userData.Tags = $user.Tags
        }
        
        $InventoryData.IAMUsers += $userData
    }
    
    # Get IAM Roles
    Write-Host "Collecting IAM role data..." -ForegroundColor Cyan
    $IAMRoles = Get-IAMRole
    foreach ($role in $IAMRoles) {
        $roleData = @{
            RoleName = $role.RoleName
            RoleId = $role.RoleId
            Arn = $role.Arn
            CreateDate = $role.CreateDate
            Description = $role.Description
        }
        
        if ($IncludeTags) {
            $roleData.Tags = $role.Tags
        }
        
        $InventoryData.IAMRoles += $roleData
    }
    
    # Get Load Balancers
    Write-Host "Collecting load balancer data..." -ForegroundColor Cyan
    $LoadBalancers = Get-ELB2LoadBalancer
    foreach ($lb in $LoadBalancers) {
        $lbData = @{
            LoadBalancerArn = $lb.LoadBalancerArn
            LoadBalancerName = $lb.LoadBalancerName
            DNSName = $lb.DNSName
            State = $lb.State.Code
            Type = $lb.Type
            Scheme = $lb.Scheme
        }
        
        if ($IncludeTags) {
            $lbData.Tags = $lb.Tags
        }
        
        $InventoryData.LoadBalancers += $lbData
    }
    
    # Get CloudWatch Alarms
    Write-Host "Collecting CloudWatch alarm data..." -ForegroundColor Cyan
    $CloudWatchAlarms = Get-CWMetricAlarm
    foreach ($alarm in $CloudWatchAlarms) {
        $alarmData = @{
            AlarmName = $alarm.AlarmName
            MetricName = $alarm.MetricName
            Namespace = $alarm.Namespace
            StateValue = $alarm.StateValue
            StateReason = $alarm.StateReason
            Threshold = $alarm.Threshold
            ComparisonOperator = $alarm.ComparisonOperator
        }
        
        if ($IncludeTags) {
            $alarmData.Tags = $alarm.Tags
        }
        
        $InventoryData.CloudWatchAlarms += $alarmData
    }
    
    # Generate HTML report
    Write-Host "Generating HTML report..." -ForegroundColor Cyan
    
    $HtmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>AWS Resource Inventory Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #232f3e; color: white; padding: 20px; border-radius: 5px; }
        .summary { background-color: #f8f9fa; padding: 20px; margin: 20px 0; border-radius: 5px; }
        .section { background-color: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #0073bb; color: white; }
        .count { font-weight: bold; color: #0073bb; font-size: 1.2em; }
        .status-running { color: #28a745; }
        .status-stopped { color: #dc3545; }
        .status-pending { color: #ffc107; }
    </style>
</head>
<body>
    <div class="header">
        <h1>AWS Resource Inventory Report</h1>
        <p>Generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        <p>Region: $Region</p>
    </div>
    
    <div class="summary">
        <h2>Resource Summary</h2>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px;">
            <div><strong>EC2 Instances:</strong> <span class="count">$($InventoryData.EC2Instances.Count)</span></div>
            <div><strong>S3 Buckets:</strong> <span class="count">$($InventoryData.S3Buckets.Count)</span></div>
            <div><strong>RDS Instances:</strong> <span class="count">$($InventoryData.RDSInstances.Count)</span></div>
            <div><strong>Security Groups:</strong> <span class="count">$($InventoryData.SecurityGroups.Count)</span></div>
            <div><strong>IAM Users:</strong> <span class="count">$($InventoryData.IAMUsers.Count)</span></div>
            <div><strong>IAM Roles:</strong> <span class="count">$($InventoryData.IAMRoles.Count)</span></div>
            <div><strong>Load Balancers:</strong> <span class="count">$($InventoryData.LoadBalancers.Count)</span></div>
            <div><strong>CloudWatch Alarms:</strong> <span class="count">$($InventoryData.CloudWatchAlarms.Count)</span></div>
        </div>
    </div>
"@
    
    # Add EC2 Instances section
    if ($InventoryData.EC2Instances.Count -gt 0) {
        $HtmlReport += @"
    <div class="section">
        <h3>EC2 Instances ($($InventoryData.EC2Instances.Count))</h3>
        <table>
            <tr><th>Instance ID</th><th>Type</th><th>State</th><th>Public IP</th><th>Private IP</th><th>Launch Time</th></tr>
"@
        
        foreach ($instance in $InventoryData.EC2Instances) {
            $stateClass = "status-$($instance.State.ToLower())"
            $HtmlReport += @"
            <tr>
                <td>$($instance.InstanceId)</td>
                <td>$($instance.InstanceType)</td>
                <td class="$stateClass">$($instance.State)</td>
                <td>$($instance.PublicIP)</td>
                <td>$($instance.PrivateIP)</td>
                <td>$($instance.LaunchTime.ToString("yyyy-MM-dd HH:mm"))</td>
            </tr>
"@
        }
        
        $HtmlReport += "</table></div>"
    }
    
    # Add S3 Buckets section
    if ($InventoryData.S3Buckets.Count -gt 0) {
        $HtmlReport += @"
    <div class="section">
        <h3>S3 Buckets ($($InventoryData.S3Buckets.Count))</h3>
        <table>
            <tr><th>Bucket Name</th><th>Creation Date</th><th>Location</th></tr>
"@
        
        foreach ($bucket in $InventoryData.S3Buckets) {
            $HtmlReport += @"
            <tr>
                <td>$($bucket.BucketName)</td>
                <td>$($bucket.CreationDate.ToString("yyyy-MM-dd HH:mm"))</td>
                <td>$($bucket.Location)</td>
            </tr>
"@
        }
        
        $HtmlReport += "</table></div>"
    }
    
    # Add RDS Instances section
    if ($InventoryData.RDSInstances.Count -gt 0) {
        $HtmlReport += @"
    <div class="section">
        <h3>RDS Instances ($($InventoryData.RDSInstances.Count))</h3>
        <table>
            <tr><th>Instance ID</th><th>Engine</th><th>Class</th><th>Status</th><th>Endpoint</th><th>Multi-AZ</th></tr>
"@
        
        foreach ($instance in $InventoryData.RDSInstances) {
            $HtmlReport += @"
            <tr>
                <td>$($instance.DBInstanceIdentifier)</td>
                <td>$($instance.Engine) $($instance.EngineVersion)</td>
                <td>$($instance.DBInstanceClass)</td>
                <td>$($instance.DBInstanceStatus)</td>
                <td>$($instance.Endpoint):$($instance.Port)</td>
                <td>$($instance.MultiAZ)</td>
            </tr>
"@
        }
        
        $HtmlReport += "</table></div>"
    }
    
    # Add Security Groups section
    if ($InventoryData.SecurityGroups.Count -gt 0) {
        $HtmlReport += @"
    <div class="section">
        <h3>Security Groups ($($InventoryData.SecurityGroups.Count))</h3>
        <table>
            <tr><th>Group ID</th><th>Group Name</th><th>Description</th><th>VPC ID</th><th>Inbound Rules</th><th>Outbound Rules</th></tr>
"@
        
        foreach ($sg in $InventoryData.SecurityGroups) {
            $HtmlReport += @"
            <tr>
                <td>$($sg.GroupId)</td>
                <td>$($sg.GroupName)</td>
                <td>$($sg.Description)</td>
                <td>$($sg.VpcId)</td>
                <td>$($sg.InboundRules.Count)</td>
                <td>$($sg.OutboundRules.Count)</td>
            </tr>
"@
        }
        
        $HtmlReport += "</table></div>"
    }
    
    $HtmlReport += @"
</body>
</html>
"@
    
    # Save the report
    $HtmlReport | Out-File -FilePath $ReportFile -Encoding UTF8
    
    # Export to CSV if requested
    if ($ExportCSV) {
        Write-Host "Exporting data to CSV files..." -ForegroundColor Cyan
        
        foreach ($resourceType in $InventoryData.Keys) {
            if ($InventoryData[$resourceType].Count -gt 0) {
                $csvFile = Join-Path $OutputPath "$resourceType-$ReportDate.csv"
                $InventoryData[$resourceType] | Export-Csv -Path $csvFile -NoTypeInformation
                Write-Host "  Exported $($InventoryData[$resourceType].Count) $resourceType to $csvFile" -ForegroundColor Green
            }
        }
    }
    
    Write-Host "Report generated successfully!" -ForegroundColor Green
    Write-Host "Report saved to: $ReportFile" -ForegroundColor Yellow
    
    # Display summary in console
    Write-Host "`nResource Summary:" -ForegroundColor Green
    Write-Host "  EC2 Instances: $($InventoryData.EC2Instances.Count)" -ForegroundColor White
    Write-Host "  S3 Buckets: $($InventoryData.S3Buckets.Count)" -ForegroundColor White
    Write-Host "  RDS Instances: $($InventoryData.RDSInstances.Count)" -ForegroundColor White
    Write-Host "  Security Groups: $($InventoryData.SecurityGroups.Count)" -ForegroundColor White
    Write-Host "  IAM Users: $($InventoryData.IAMUsers.Count)" -ForegroundColor White
    Write-Host "  IAM Roles: $($InventoryData.IAMRoles.Count)" -ForegroundColor White
    Write-Host "  Load Balancers: $($InventoryData.LoadBalancers.Count)" -ForegroundColor White
    Write-Host "  CloudWatch Alarms: $($InventoryData.CloudWatchAlarms.Count)" -ForegroundColor White
    
} catch {
    Write-Error "Error during resource inventory: $($_.Exception.Message)"
    Write-Host "Make sure you have proper AWS credentials configured." -ForegroundColor Red
    exit 1
}

Write-Host "`nResource inventory completed successfully!" -ForegroundColor Green 