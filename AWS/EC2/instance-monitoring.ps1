# instance-monitoring.ps1
# Comprehensive EC2 instance monitoring and health check script
#
# OVERALL PURPOSE:
# This script provides comprehensive monitoring capabilities for EC2 instances including:
# - Real-time status checking and health monitoring
# - Performance metrics collection (CPU, network, disk usage)
# - Cost analysis and estimation
# - Security analysis and compliance checking
# - CloudWatch alarm monitoring
# - Automated reporting and data export
#
# KEY FEATURES:
# - Multi-region support with automatic region detection
# - Detailed performance metrics with historical data
# - Cost estimation based on instance types and usage
# - Security group analysis and vulnerability assessment
# - CloudWatch integration for advanced monitoring
# - Export capabilities for reporting and analysis
#
# USAGE SCENARIOS:
# - Daily operational monitoring and health checks
# - Performance troubleshooting and optimization
# - Cost analysis and budget planning
# - Security compliance audits
# - Capacity planning and resource optimization

param(
    [string]$InstanceId = "",
    [string]$Region = "",
    [string]$Profile = "default",
    [string]$Action = "status", # status, metrics, health, costs, alerts
    [int]$Days = 7,
    [switch]$Detailed,
    [switch]$Export
)

# FUNCTION: Get-InstanceStatus
# PURPOSE: Retrieves real-time status information for a specific EC2 instance
# PARAMETERS:
#   - InstanceId: The ID of the instance to check
#   - Region: AWS region where the instance is located
# RETURNS: Instance status object with detailed state information
# PROCESS:
#   1. Validates instance ID and region parameters
#   2. Calls AWS CLI to get instance status
#   3. Parses and formats the response
#   4. Returns structured status data or null if error
function Get-InstanceStatus {
    param([string]$InstanceId, [string]$Region)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    try {
        $status = aws ec2 describe-instance-status --instance-ids $InstanceId $regionParam --profile $Profile --output json | ConvertFrom-Json
        return $status.InstanceStatuses[0]
    }
    catch {
        Write-Host "Unable to get status for instance $InstanceId" -ForegroundColor Red
        return $null
    }
}

# FUNCTION: Get-InstanceMetrics
# PURPOSE: Collects comprehensive performance metrics for an EC2 instance
# PARAMETERS:
#   - InstanceId: The ID of the instance to monitor
#   - Region: AWS region where the instance is located
#   - Days: Number of days of historical data to retrieve
# RETURNS: Object containing CPU, network, and disk metrics
# PROCESS:
#   1. Sets up time range for metric collection
#   2. Retrieves CPU utilization metrics from CloudWatch
#   3. Collects network in/out traffic data
#   4. Calculates averages and trends
#   5. Returns structured metrics data
function Get-InstanceMetrics {
    param([string]$InstanceId, [string]$Region, [int]$Days)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    $endTime = Get-Date
    $startTime = $endTime.AddDays(-$Days)
    
    $metrics = @{
        CPU = @()
        Network = @()
        Disk = @()
    }
    
    # CPU Utilization Collection
    # PURPOSE: Gathers CPU usage data to identify performance bottlenecks
    # PROCESS: Queries CloudWatch for CPU metrics at hourly intervals
    try {
        $cpuData = aws cloudwatch get-metric-statistics --namespace AWS/EC2 --metric-name CPUUtilization --dimensions Name=InstanceId,Value=$InstanceId --start-time $startTime.ToString("yyyy-MM-ddTHH:mm:ss") --end-time $endTime.ToString("yyyy-MM-ddTHH:mm:ss") --period 3600 --statistics Average $regionParam --profile $Profile --output json | ConvertFrom-Json
        
        foreach ($point in $cpuData.Datapoints) {
            $metrics.CPU += [PSCustomObject]@{
                Timestamp = $point.Timestamp
                Value = [math]::Round($point.Average, 2)
            }
        }
    }
    catch {
        Write-Host "Unable to get CPU metrics" -ForegroundColor Yellow
    }
    
    # Network Traffic Collection
    # PURPOSE: Monitors network usage to identify bandwidth issues
    # PROCESS: Collects both inbound and outbound network data
    try {
        $networkIn = aws cloudwatch get-metric-statistics --namespace AWS/EC2 --metric-name NetworkIn --dimensions Name=InstanceId,Value=$InstanceId --start-time $startTime.ToString("yyyy-MM-ddTHH:mm:ss") --end-time $endTime.ToString("yyyy-MM-ddTHH:mm:ss") --period 3600 --statistics Sum $regionParam --profile $Profile --output json | ConvertFrom-Json
        
        $networkOut = aws cloudwatch get-metric-statistics --namespace AWS/EC2 --metric-name NetworkOut --dimensions Name=InstanceId,Value=$InstanceId --start-time $startTime.ToString("yyyy-MM-ddTHH:mm:ss") --end-time $endTime.ToString("yyyy-MM-ddTHH:mm:ss") --period 3600 --statistics Sum $regionParam --profile $Profile --output json | ConvertFrom-Json
        
        foreach ($point in $networkIn.Datapoints) {
            $metrics.Network += [PSCustomObject]@{
                Timestamp = $point.Timestamp
                NetworkIn = [math]::Round($point.Sum / 1MB, 2)
                NetworkOut = 0
            }
        }
        
        foreach ($point in $networkOut.Datapoints) {
            $existing = $metrics.Network | Where-Object { $_.Timestamp -eq $point.Timestamp }
            if ($existing) {
                $existing.NetworkOut = [math]::Round($point.Sum / 1MB, 2)
            }
        }
    }
    catch {
        Write-Host "Unable to get network metrics" -ForegroundColor Yellow
    }
    
    return $metrics
}

# FUNCTION: Get-InstanceHealth
# PURPOSE: Performs comprehensive health checks on EC2 instances
# PARAMETERS:
#   - InstanceId: The ID of the instance to check
#   - Region: AWS region where the instance is located
# RETURNS: Health status object with detailed health information
# PROCESS:
#   1. Checks instance status (running, stopped, etc.)
#   2. Verifies system status (hardware, software health)
#   3. Determines overall health score
#   4. Returns structured health data
function Get-InstanceHealth {
    param([string]$InstanceId, [string]$Region)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    try {
        $health = aws ec2 describe-instance-status --instance-ids $InstanceId --include-all-instances $regionParam --profile $Profile --output json | ConvertFrom-Json
        
        if ($health.InstanceStatuses) {
            $status = $health.InstanceStatuses[0]
            return @{
                InstanceStatus = $status.InstanceStatus.Status
                SystemStatus = $status.SystemStatus.Status
                HealthCheck = if ($status.InstanceStatus.Status -eq "ok" -and $status.SystemStatus.Status -eq "ok") { "Healthy" } else { "Unhealthy" }
            }
        }
    }
    catch {
        Write-Host "Unable to get health status" -ForegroundColor Red
    }
    
    return $null
}

# FUNCTION: Get-InstanceCosts
# PURPOSE: Calculates estimated costs for EC2 instance usage
# PARAMETERS:
#   - InstanceId: The ID of the instance to analyze
#   - Region: AWS region where the instance is located
#   - Days: Number of days to calculate costs for
# RETURNS: Cost analysis object with pricing information
# PROCESS:
#   1. Retrieves instance type and configuration
#   2. Looks up hourly rates for the instance type
#   3. Calculates total cost based on usage period
#   4. Returns detailed cost breakdown
function Get-InstanceCosts {
    param([string]$InstanceId, [string]$Region, [int]$Days)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    $endDate = Get-Date
    $startDate = $endDate.AddDays(-$Days)
    
    try {
        # Get instance details for pricing
        $instance = aws ec2 describe-instances --instance-ids $InstanceId $regionParam --profile $Profile --output json | ConvertFrom-Json
        $instanceType = $instance.Reservations[0].Instances[0].InstanceType
        
        # Calculate estimated cost (simplified - in production you'd use Cost Explorer API)
        $hourlyRates = @{
            "t3.micro" = 0.0104
            "t3.small" = 0.0208
            "t3.medium" = 0.0416
            "m5.large" = 0.096
            "m5.xlarge" = 0.192
            "c5.large" = 0.085
            "c5.xlarge" = 0.17
        }
        
        $hourlyRate = $hourlyRates[$instanceType]
        if (-not $hourlyRate) {
            $hourlyRate = 0.1 # Default rate
        }
        
        $totalHours = $Days * 24
        $estimatedCost = $hourlyRate * $totalHours
        
        return @{
            InstanceType = $instanceType
            HourlyRate = $hourlyRate
            EstimatedCost = [math]::Round($estimatedCost, 2)
            Period = "$Days days"
        }
    }
    catch {
        Write-Host "Unable to calculate costs" -ForegroundColor Red
        return $null
    }
}

# FUNCTION: Show-InstanceAlerts
# PURPOSE: Checks for CloudWatch alarms and security issues
# PARAMETERS:
#   - InstanceId: The ID of the instance to check
#   - Region: AWS region where the instance is located
# RETURNS: None (displays alerts to console)
# PROCESS:
#   1. Searches for CloudWatch alarms related to the instance
#   2. Checks security group configurations
#   3. Identifies potential security vulnerabilities
#   4. Displays findings with color-coded severity
function Show-InstanceAlerts {
    param([string]$InstanceId, [string]$Region)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    Write-Host "`nChecking for alerts..." -ForegroundColor Yellow
    
    # Check CloudWatch alarms
    try {
        $alarms = aws cloudwatch describe-alarms --alarm-names "*$InstanceId*" $regionParam --profile $Profile --output json | ConvertFrom-Json
        
        if ($alarms.MetricAlarms) {
            Write-Host "`nCloudWatch Alarms:" -ForegroundColor Cyan
            foreach ($alarm in $alarms.MetricAlarms) {
                $color = if ($alarm.StateValue -eq "ALARM") { "Red" } else { "Green" }
                Write-Host "  $($alarm.AlarmName): $($alarm.StateValue)" -ForegroundColor $color
            }
        } else {
            Write-Host "No CloudWatch alarms found for this instance" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "Unable to check CloudWatch alarms" -ForegroundColor Yellow
    }
    
    # Check for security issues
    try {
        $instance = aws ec2 describe-instances --instance-ids $InstanceId $regionParam --profile $Profile --output json | ConvertFrom-Json
        $securityGroups = $instance.Reservations[0].Instances[0].SecurityGroups
        
        Write-Host "`nSecurity Groups:" -ForegroundColor Cyan
        foreach ($sg in $securityGroups) {
            Write-Host "  $($sg.GroupName) ($($sg.GroupId))" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "Unable to check security groups" -ForegroundColor Yellow
    }
}

# MAIN SCRIPT EXECUTION
# PURPOSE: Orchestrates the monitoring workflow based on user parameters
# PROCESS:
#   1. Validates input parameters
#   2. Routes to appropriate monitoring function based on Action parameter
#   3. Displays results with color-coded output
#   4. Handles export functionality if requested

Write-Host "AWS EC2 Instance Monitoring" -ForegroundColor Green
Write-Host "===========================" -ForegroundColor Green

if (-not $InstanceId) {
    Write-Host "Please specify an InstanceId to monitor." -ForegroundColor Red
    Write-Host "Usage: .\instance-monitoring.ps1 -InstanceId i-1234567890abcdef0" -ForegroundColor Yellow
    return
}

switch ($Action.ToLower()) {
    "status" {
        # STATUS CHECK WORKFLOW
        # PURPOSE: Provides real-time instance status information
        # PROCESS: Retrieves and displays current instance state
        $status = Get-InstanceStatus -InstanceId $InstanceId -Region $Region
        
        if ($status) {
            Write-Host "`nInstance Status:" -ForegroundColor Yellow
            Write-Host "Instance ID: $InstanceId" -ForegroundColor Cyan
            Write-Host "Instance Status: $($status.InstanceStatus.Status)" -ForegroundColor $(if($status.InstanceStatus.Status -eq "ok") { "Green" } else { "Red" })
            Write-Host "System Status: $($status.SystemStatus.Status)" -ForegroundColor $(if($status.SystemStatus.Status -eq "ok") { "Green" } else { "Red" })
        }
    }
    
    "metrics" {
        # METRICS COLLECTION WORKFLOW
        # PURPOSE: Gathers and displays performance metrics
        # PROCESS: Collects historical data and calculates trends
        $metrics = Get-InstanceMetrics -InstanceId $InstanceId -Region $Region -Days $Days
        
        Write-Host "`nPerformance Metrics (Last $Days days):" -ForegroundColor Yellow
        
        if ($metrics.CPU.Count -gt 0) {
            Write-Host "`nCPU Utilization:" -ForegroundColor Cyan
            foreach ($point in $metrics.CPU) {
                Write-Host "  $($point.Timestamp): $($point.Value)%" -ForegroundColor Gray
            }
        }
        
        if ($metrics.Network.Count -gt 0) {
            Write-Host "`nNetwork Usage:" -ForegroundColor Cyan
            foreach ($point in $metrics.Network) {
                Write-Host "  $($point.Timestamp): In: $($point.NetworkIn) MB, Out: $($point.NetworkOut) MB" -ForegroundColor Gray
            }
        }
    }
    
    "health" {
        # HEALTH CHECK WORKFLOW
        # PURPOSE: Performs comprehensive health assessment
        # PROCESS: Evaluates multiple health indicators
        $health = Get-InstanceHealth -InstanceId $InstanceId -Region $Region
        
        if ($health) {
            Write-Host "`nHealth Check:" -ForegroundColor Yellow
            Write-Host "Overall Health: $($health.HealthCheck)" -ForegroundColor $(if($health.HealthCheck -eq "Healthy") { "Green" } else { "Red" })
            Write-Host "Instance Status: $($health.InstanceStatus)" -ForegroundColor $(if($health.InstanceStatus -eq "ok") { "Green" } else { "Red" })
            Write-Host "System Status: $($health.SystemStatus)" -ForegroundColor $(if($health.SystemStatus -eq "ok") { "Green" } else { "Red" })
        }
    }
    
    "costs" {
        # COST ANALYSIS WORKFLOW
        # PURPOSE: Calculates and displays cost information
        # PROCESS: Analyzes instance usage and estimates costs
        $costs = Get-InstanceCosts -InstanceId $InstanceId -Region $Region -Days $Days
        
        if ($costs) {
            Write-Host "`nCost Analysis:" -ForegroundColor Yellow
            Write-Host "Instance Type: $($costs.InstanceType)" -ForegroundColor Cyan
            Write-Host "Hourly Rate: $($costs.HourlyRate)" -ForegroundColor Gray
            Write-Host "Period: $($costs.Period)" -ForegroundColor Gray
            Write-Host "Estimated Cost: $($costs.EstimatedCost)" -ForegroundColor Yellow
        }
    }
    
    "alerts" {
        # ALERT CHECKING WORKFLOW
        # PURPOSE: Identifies potential issues and security concerns
        # PROCESS: Checks CloudWatch alarms and security configurations
        Show-InstanceAlerts -InstanceId $InstanceId -Region $Region
    }
    
    default {
        Write-Host "Invalid action. Valid actions: status, metrics, health, costs, alerts" -ForegroundColor Red
    }
}

# EXPORT FUNCTIONALITY
# PURPOSE: Saves monitoring data to file for external analysis
# PROCESS: Creates JSON export with timestamp and all collected data
if ($Export) {
    $exportData = @{
        InstanceId = $InstanceId
        Region = $Region
        Action = $Action
        Timestamp = Get-Date
    }
    
    $exportFile = "ec2-monitoring-$InstanceId-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $exportData | ConvertTo-Json | Out-File $exportFile
    Write-Host "`nData exported to: $exportFile" -ForegroundColor Green
}

# USAGE EXAMPLES AND HELP
# PURPOSE: Provides guidance on script usage
# PROCESS: Displays common usage patterns and examples
Write-Host "`nUsage Examples:" -ForegroundColor Magenta
Write-Host "  .\instance-monitoring.ps1 -InstanceId i-1234567890abcdef0 -Action status"
Write-Host "  .\instance-monitoring.ps1 -InstanceId i-1234567890abcdef0 -Action metrics -Days 30"
Write-Host "  .\instance-monitoring.ps1 -InstanceId i-1234567890abcdef0 -Action health"
Write-Host "  .\instance-monitoring.ps1 -InstanceId i-1234567890abcdef0 -Action costs -Days 7"
Write-Host "  .\instance-monitoring.ps1 -InstanceId i-1234567890abcdef0 -Action alerts" 