<#
.SYNOPSIS
    AWS EC2 Instance Management Script
    
.DESCRIPTION
    This script provides comprehensive EC2 instance management capabilities including:
    - Start/Stop instances
    - Create AMI backups
    - Monitor instance health
    - Manage security groups
    - Generate instance reports
    - Tag management
    
.PARAMETER Action
    Action to perform: Start, Stop, Backup, Monitor, Report, Tag
    
.PARAMETER InstanceIds
    Comma-separated list of instance IDs
    
.PARAMETER TagName
    Tag name for filtering instances
    
.PARAMETER TagValue
    Tag value for filtering instances
    
.PARAMETER Region
    AWS region (default: us-east-1)
    
.PARAMETER BackupName
    Name for the AMI backup
    
.PARAMETER Force
    Force operation without confirmation
    
.EXAMPLE
    .\instance-management.ps1 -Action Start -InstanceIds "i-12345678,i-87654321"
    
.EXAMPLE
    .\instance-management.ps1 -Action Backup -TagName Environment -TagValue prod -BackupName "prod-backup-$(Get-Date -Format 'yyyy-MM-dd')"
    
.EXAMPLE
    .\instance-management.ps1 -Action Report -Region us-west-2
    
.NOTES
    Author: IT Team
    Date: 2024
    Requires: AWS.Tools PowerShell module
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Start", "Stop", "Backup", "Monitor", "Report", "Tag")]
    [string]$Action,
    
    [string]$InstanceIds,
    [string]$TagName,
    [string]$TagValue,
    [string]$Region = "us-east-1",
    [string]$BackupName,
    [switch]$Force
)

# Set AWS region
Set-DefaultAWSRegion -Region $Region

# Initialize variables
$Instances = @()
$Results = @()

Write-Host "AWS EC2 Instance Management" -ForegroundColor Green
Write-Host "Action: $Action" -ForegroundColor Yellow
Write-Host "Region: $Region" -ForegroundColor Yellow

try {
    # Get instances based on parameters
    if ($InstanceIds) {
        $InstanceIdList = $InstanceIds -split ","
        $Instances = Get-EC2Instance -InstanceId $InstanceIdList
    } elseif ($TagName -and $TagValue) {
        $Filter = @{Name="tag:$TagName"; Values=$TagValue}
        $Instances = Get-EC2Instance -Filter $Filter
    } else {
        $Instances = Get-EC2Instance
    }
    
    if ($Instances.Count -eq 0) {
        Write-Warning "No instances found matching the criteria."
        exit 1
    }
    
    Write-Host "Found $($Instances.Count) instance(s)" -ForegroundColor Cyan
    
    # Perform requested action
    switch ($Action) {
        "Start" {
            Start-EC2Instances
        }
        "Stop" {
            Stop-EC2Instances
        }
        "Backup" {
            Create-EC2Backups
        }
        "Monitor" {
            Monitor-EC2Instances
        }
        "Report" {
            Generate-EC2Report
        }
        "Tag" {
            Manage-EC2Tags
        }
    }
    
} catch {
    Write-Error "Error during EC2 management: $($_.Exception.Message)"
    exit 1
}

# Function to start EC2 instances
function Start-EC2Instances {
    Write-Host "Starting EC2 instances..." -ForegroundColor Cyan
    
    foreach ($instance in $Instances) {
        $instanceId = $instance.InstanceId
        $state = $instance.State.Name
        
        if ($state -eq "stopped") {
            try {
                Start-EC2Instance -InstanceId $instanceId
                Write-Host "Started instance: $instanceId" -ForegroundColor Green
                $Results += @{
                    InstanceId = $instanceId
                    Action = "Start"
                    Status = "Success"
                    Message = "Instance started successfully"
                }
            } catch {
                Write-Error "Failed to start instance $instanceId : $($_.Exception.Message)"
                $Results += @{
                    InstanceId = $instanceId
                    Action = "Start"
                    Status = "Failed"
                    Message = $_.Exception.Message
                }
            }
        } else {
            Write-Warning "Instance $instanceId is in state '$state' - cannot start"
            $Results += @{
                InstanceId = $instanceId
                Action = "Start"
                Status = "Skipped"
                Message = "Instance in state: $state"
            }
        }
    }
}

# Function to stop EC2 instances
function Stop-EC2Instances {
    Write-Host "Stopping EC2 instances..." -ForegroundColor Cyan
    
    if (-not $Force) {
        $confirmation = Read-Host "Are you sure you want to stop $($Instances.Count) instance(s)? (y/N)"
        if ($confirmation -ne "y" -and $confirmation -ne "Y") {
            Write-Host "Operation cancelled." -ForegroundColor Yellow
            return
        }
    }
    
    foreach ($instance in $Instances) {
        $instanceId = $instance.InstanceId
        $state = $instance.State.Name
        
        if ($state -eq "running") {
            try {
                Stop-EC2Instance -InstanceId $instanceId
                Write-Host "Stopped instance: $instanceId" -ForegroundColor Green
                $Results += @{
                    InstanceId = $instanceId
                    Action = "Stop"
                    Status = "Success"
                    Message = "Instance stopped successfully"
                }
            } catch {
                Write-Error "Failed to stop instance $instanceId : $($_.Exception.Message)"
                $Results += @{
                    InstanceId = $instanceId
                    Action = "Stop"
                    Status = "Failed"
                    Message = $_.Exception.Message
                }
            }
        } else {
            Write-Warning "Instance $instanceId is in state '$state' - cannot stop"
            $Results += @{
                InstanceId = $instanceId
                Action = "Stop"
                Status = "Skipped"
                Message = "Instance in state: $state"
            }
        }
    }
}

# Function to create EC2 backups
function Create-EC2Backups {
    Write-Host "Creating EC2 backups..." -ForegroundColor Cyan
    
    foreach ($instance in $Instances) {
        $instanceId = $instance.InstanceId
        $instanceName = ($instance.Tags | Where-Object { $_.Key -eq "Name" }).Value
        if (-not $instanceName) { $instanceName = $instanceId }
        
        $backupName = if ($BackupName) { "$BackupName-$instanceName" } else { "backup-$instanceName-$(Get-Date -Format 'yyyy-MM-dd-HHmm')" }
        
        try {
            # Create AMI
            $ami = New-EC2Image -InstanceId $instanceId -Name $backupName -Description "Backup created by management script"
            Write-Host "Created AMI backup: $($ami.ImageId) for instance: $instanceId" -ForegroundColor Green
            
            # Add tags to AMI
            $tags = @(
                @{Key="Name"; Value=$backupName},
                @{Key="BackupDate"; Value=(Get-Date -Format "yyyy-MM-dd")},
                @{Key="SourceInstance"; Value=$instanceId},
                @{Key="CreatedBy"; Value="EC2-Management-Script"}
            )
            New-EC2Tag -Resource $ami.ImageId -Tag $tags
            
            $Results += @{
                InstanceId = $instanceId
                Action = "Backup"
                Status = "Success"
                Message = "AMI created: $($ami.ImageId)"
                AMIId = $ami.ImageId
            }
        } catch {
            Write-Error "Failed to create backup for instance $instanceId : $($_.Exception.Message)"
            $Results += @{
                InstanceId = $instanceId
                Action = "Backup"
                Status = "Failed"
                Message = $_.Exception.Message
            }
        }
    }
}

# Function to monitor EC2 instances
function Monitor-EC2Instances {
    Write-Host "Monitoring EC2 instances..." -ForegroundColor Cyan
    
    foreach ($instance in $Instances) {
        $instanceId = $instance.InstanceId
        $state = $instance.State.Name
        $instanceType = $instance.InstanceType
        $launchTime = $instance.LaunchTime
        
        Write-Host "`nInstance: $instanceId" -ForegroundColor White
        Write-Host "  State: $state" -ForegroundColor $(if ($state -eq "running") { "Green" } else { "Red" })
        Write-Host "  Type: $instanceType" -ForegroundColor Yellow
        Write-Host "  Launch Time: $($launchTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Yellow
        
        # Get CloudWatch metrics if instance is running
        if ($state -eq "running") {
            try {
                $endTime = Get-Date
                $startTime = $endTime.AddMinutes(-5)
                
                $cpuMetrics = Get-CWMetricStatistics -Namespace AWS/EC2 -MetricName CPUUtilization -Dimension @{Name="InstanceId"; Value=$instanceId} -StartTime $startTime -EndTime $endTime -Period 300 -Statistic Average
                
                if ($cpuMetrics) {
                    $avgCPU = ($cpuMetrics | Measure-Object -Property Average -Average).Average
                    Write-Host "  CPU Utilization: $([math]::Round($avgCPU, 2))%" -ForegroundColor $(if ($avgCPU -gt 80) { "Red" } elseif ($avgCPU -gt 60) { "Yellow" } else { "Green" })
                }
                
                # Check security groups
                $securityGroups = $instance.SecurityGroups
                Write-Host "  Security Groups: $($securityGroups.GroupName -join ', ')" -ForegroundColor Cyan
                
            } catch {
                Write-Warning "Could not retrieve metrics for instance $instanceId"
            }
        }
        
        $Results += @{
            InstanceId = $instanceId
            Action = "Monitor"
            Status = "Success"
            State = $state
            InstanceType = $instanceType
        }
    }
}

# Function to generate EC2 report
function Generate-EC2Report {
    Write-Host "Generating EC2 report..." -ForegroundColor Cyan
    
    $reportData = @()
    
    foreach ($instance in $Instances) {
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
            SecurityGroups = ($instance.SecurityGroups.GroupName -join ', ')
            Tags = @{}
        }
        
        # Add tags
        foreach ($tag in $instance.Tags) {
            $instanceData.Tags[$tag.Key] = $tag.Value
        }
        
        $reportData += $instanceData
    }
    
    # Generate summary
    $runningCount = ($reportData | Where-Object { $_.State -eq "running" }).Count
    $stoppedCount = ($reportData | Where-Object { $_.State -eq "stopped" }).Count
    $totalCount = $reportData.Count
    
    Write-Host "`nEC2 Instance Report" -ForegroundColor Green
    Write-Host "==================" -ForegroundColor Green
    Write-Host "Total Instances: $totalCount" -ForegroundColor White
    Write-Host "Running: $runningCount" -ForegroundColor Green
    Write-Host "Stopped: $stoppedCount" -ForegroundColor Red
    
    # Instance type breakdown
    $instanceTypes = $reportData | Group-Object InstanceType | Sort-Object Count -Descending
    Write-Host "`nInstance Type Breakdown:" -ForegroundColor Yellow
    foreach ($type in $instanceTypes) {
        Write-Host "  $($type.Name): $($type.Count)" -ForegroundColor White
    }
    
    # Export to CSV if requested
    $csvFile = "ec2-report-$(Get-Date -Format 'yyyy-MM-dd-HHmm').csv"
    $reportData | Export-Csv -Path $csvFile -NoTypeInformation
    Write-Host "`nReport exported to: $csvFile" -ForegroundColor Green
    
    $Results += @{
        Action = "Report"
        Status = "Success"
        TotalInstances = $totalCount
        RunningInstances = $runningCount
        StoppedInstances = $stoppedCount
        ReportFile = $csvFile
    }
}

# Function to manage EC2 tags
function Manage-EC2Tags {
    Write-Host "Managing EC2 tags..." -ForegroundColor Cyan
    
    if (-not $TagName -or -not $TagValue) {
        Write-Error "TagName and TagValue parameters are required for tag management"
        return
    }
    
    foreach ($instance in $Instances) {
        $instanceId = $instance.InstanceId
        
        try {
            # Check if tag already exists
            $existingTag = $instance.Tags | Where-Object { $_.Key -eq $TagName }
            
            if ($existingTag) {
                if ($existingTag.Value -ne $TagValue) {
                    # Update existing tag
                    New-EC2Tag -Resource $instanceId -Tag @{Key=$TagName; Value=$TagValue}
                    Write-Host "Updated tag for instance: $instanceId" -ForegroundColor Green
                } else {
                    Write-Host "Tag already exists for instance: $instanceId" -ForegroundColor Yellow
                }
            } else {
                # Add new tag
                New-EC2Tag -Resource $instanceId -Tag @{Key=$TagName; Value=$TagValue}
                Write-Host "Added tag for instance: $instanceId" -ForegroundColor Green
            }
            
            $Results += @{
                InstanceId = $instanceId
                Action = "Tag"
                Status = "Success"
                TagName = $TagName
                TagValue = $TagValue
            }
        } catch {
            Write-Error "Failed to manage tags for instance $instanceId : $($_.Exception.Message)"
            $Results += @{
                InstanceId = $instanceId
                Action = "Tag"
                Status = "Failed"
                Message = $_.Exception.Message
            }
        }
    }
}

# Display results summary
if ($Results.Count -gt 0) {
    Write-Host "`nOperation Summary:" -ForegroundColor Green
    Write-Host "=================" -ForegroundColor Green
    
    $successCount = ($Results | Where-Object { $_.Status -eq "Success" }).Count
    $failedCount = ($Results | Where-Object { $_.Status -eq "Failed" }).Count
    $skippedCount = ($Results | Where-Object { $_.Status -eq "Skipped" }).Count
    
    Write-Host "Successful: $successCount" -ForegroundColor Green
    Write-Host "Failed: $failedCount" -ForegroundColor Red
    Write-Host "Skipped: $skippedCount" -ForegroundColor Yellow
}

Write-Host "`nEC2 management operation completed!" -ForegroundColor Green 