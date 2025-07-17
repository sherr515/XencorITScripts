# function-monitoring.ps1
# Comprehensive Lambda function monitoring and performance analysis script

param(
    [string]$FunctionName = "",
    [string]$Action = "monitor", # monitor, metrics, logs, errors, performance, alerts
    [string]$Region = "",
    [string]$Profile = "default",
    [int]$Days = 7,
    [string]$LogGroup = "",
    [switch]$Detailed,
    [switch]$Export
)

function Get-FunctionMetrics {
    param([string]$FunctionName, [string]$Region, [int]$Days)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    $endTime = Get-Date
    $startTime = $endTime.AddDays(-$Days)
    
    $metrics = @{
        Invocations = @()
        Errors = @()
        Duration = @()
        Throttles = @()
        ConcurrentExecutions = @()
    }
    
    try {
        # Invocations
        $invocations = aws cloudwatch get-metric-statistics --namespace AWS/Lambda --metric-name Invocations --dimensions Name=FunctionName,Value=$FunctionName --start-time $startTime.ToString("yyyy-MM-ddTHH:mm:ss") --end-time $endTime.ToString("yyyy-MM-ddTHH:mm:ss") --period 3600 --statistics Sum $regionParam --profile $Profile --output json | ConvertFrom-Json
        
        foreach ($point in $invocations.Datapoints) {
            $metrics.Invocations += [PSCustomObject]@{
                Timestamp = $point.Timestamp
                Value = $point.Sum
            }
        }
        
        # Errors
        $errors = aws cloudwatch get-metric-statistics --namespace AWS/Lambda --metric-name Errors --dimensions Name=FunctionName,Value=$FunctionName --start-time $startTime.ToString("yyyy-MM-ddTHH:mm:ss") --end-time $endTime.ToString("yyyy-MM-ddTHH:mm:ss") --period 3600 --statistics Sum $regionParam --profile $Profile --output json | ConvertFrom-Json
        
        foreach ($point in $errors.Datapoints) {
            $metrics.Errors += [PSCustomObject]@{
                Timestamp = $point.Timestamp
                Value = $point.Sum
            }
        }
        
        # Duration
        $duration = aws cloudwatch get-metric-statistics --namespace AWS/Lambda --metric-name Duration --dimensions Name=FunctionName,Value=$FunctionName --start-time $startTime.ToString("yyyy-MM-ddTHH:mm:ss") --end-time $endTime.ToString("yyyy-MM-ddTHH:mm:ss") --period 3600 --statistics Average $regionParam --profile $Profile --output json | ConvertFrom-Json
        
        foreach ($point in $duration.Datapoints) {
            $metrics.Duration += [PSCustomObject]@{
                Timestamp = $point.Timestamp
                Value = [math]::Round($point.Average, 2)
            }
        }
        
        # Throttles
        $throttles = aws cloudwatch get-metric-statistics --namespace AWS/Lambda --metric-name Throttles --dimensions Name=FunctionName,Value=$FunctionName --start-time $startTime.ToString("yyyy-MM-ddTHH:mm:ss") --end-time $endTime.ToString("yyyy-MM-ddTHH:mm:ss") --period 3600 --statistics Sum $regionParam --profile $Profile --output json | ConvertFrom-Json
        
        foreach ($point in $throttles.Datapoints) {
            $metrics.Throttles += [PSCustomObject]@{
                Timestamp = $point.Timestamp
                Value = $point.Sum
            }
        }
        
        # Concurrent Executions
        $concurrent = aws cloudwatch get-metric-statistics --namespace AWS/Lambda --metric-name ConcurrentExecutions --dimensions Name=FunctionName,Value=$FunctionName --start-time $startTime.ToString("yyyy-MM-ddTHH:mm:ss") --end-time $endTime.ToString("yyyy-MM-ddTHH:mm:ss") --period 3600 --statistics Maximum $regionParam --profile $Profile --output json | ConvertFrom-Json
        
        foreach ($point in $concurrent.Datapoints) {
            $metrics.ConcurrentExecutions += [PSCustomObject]@{
                Timestamp = $point.Timestamp
                Value = $point.Maximum
            }
        }
        
        return $metrics
    }
    catch {
        Write-Host "Unable to get function metrics" -ForegroundColor Red
        return $null
    }
}

function Get-FunctionLogs {
    param([string]$FunctionName, [string]$Region, [int]$Days)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    $endTime = Get-Date
    $startTime = $endTime.AddDays(-$Days)
    
    $logGroup = if ($LogGroup) { $LogGroup } else { "/aws/lambda/$FunctionName" }
    
    Write-Host "Retrieving logs from $logGroup..." -ForegroundColor Yellow
    
    try {
        $logs = aws logs filter-log-events --log-group-name $logGroup --start-time ([DateTimeOffset]::new($startTime).ToUnixTimeMilliseconds()) --end-time ([DateTimeOffset]::new($endTime).ToUnixTimeMilliseconds()) $regionParam --profile $Profile --output json | ConvertFrom-Json
        
        $logAnalysis = @{
            TotalEvents = $logs.events.Count
            ErrorEvents = @()
            SlowExecutions = @()
            RecentEvents = @()
        }
        
        foreach ($event in $logs.events) {
            $logMessage = $event.message
            
            # Check for errors
            if ($logMessage -match "ERROR|Exception|Error|Failed") {
                $logAnalysis.ErrorEvents += [PSCustomObject]@{
                    Timestamp = $event.timestamp
                    Message = $logMessage
                }
            }
            
            # Check for slow executions
            if ($logMessage -match "Duration: (\d+\.\d+) ms") {
                $duration = [double]$matches[1]
                if ($duration -gt 5000) { # 5 seconds threshold
                    $logAnalysis.SlowExecutions += [PSCustomObject]@{
                        Timestamp = $event.timestamp
                        Duration = $duration
                        Message = $logMessage
                    }
                }
            }
            
            # Get recent events
            if ($logAnalysis.RecentEvents.Count -lt 10) {
                $logAnalysis.RecentEvents += [PSCustomObject]@{
                    Timestamp = $event.timestamp
                    Message = $logMessage
                }
            }
        }
        
        return $logAnalysis
    }
    catch {
        Write-Host "Unable to retrieve function logs" -ForegroundColor Red
        return $null
    }
}

function Analyze-FunctionPerformance {
    param([string]$FunctionName, [string]$Region)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    Write-Host "Analyzing performance for function: $FunctionName" -ForegroundColor Yellow
    
    try {
        $function = aws lambda get-function --function-name $FunctionName $regionParam --profile $Profile --output json | ConvertFrom-Json
        $config = $function.Configuration
        
        $performance = @{
            FunctionName = $FunctionName
            Runtime = $config.Runtime
            MemorySize = $config.MemorySize
            Timeout = $config.Timeout
            CodeSize = $config.CodeSize
            LastModified = $config.LastModified
            Issues = @()
            Recommendations = @()
        }
        
        # Analyze memory usage
        if ($config.MemorySize -lt 512) {
            $performance.Issues += "Low memory allocation may cause performance issues"
            $performance.Recommendations += "Consider increasing memory allocation"
        }
        
        if ($config.MemorySize -gt 3008) {
            $performance.Recommendations += "Consider optimizing memory usage to reduce costs"
        }
        
        # Analyze timeout
        if ($config.Timeout -gt 900) {
            $performance.Issues += "Long timeout may indicate inefficient code"
            $performance.Recommendations += "Optimize function execution time"
        }
        
        # Analyze code size
        $codeSizeMB = [math]::Round($config.CodeSize / 1MB, 2)
        if ($codeSizeMB -gt 50) {
            $performance.Issues += "Large code size may impact cold start times"
            $performance.Recommendations += "Consider reducing code size or using layers"
        }
        
        # Check for environment variables
        if ($config.Environment -and $config.Environment.Variables) {
            $varCount = $config.Environment.Variables.Count
            if ($varCount -gt 10) {
                $performance.Recommendations += "Consider consolidating environment variables"
            }
        }
        
        return $performance
    }
    catch {
        Write-Host "Unable to analyze function performance" -ForegroundColor Red
        return $null
    }
}

function Get-FunctionErrors {
    param([string]$FunctionName, [string]$Region, [int]$Days)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    $endTime = Get-Date
    $startTime = $endTime.AddDays(-$Days)
    
    Write-Host "Analyzing errors for function: $FunctionName" -ForegroundColor Yellow
    
    try {
        $logGroup = "/aws/lambda/$FunctionName"
        
        # Get error logs
        $errorLogs = aws logs filter-log-events --log-group-name $logGroup --filter-pattern "ERROR" --start-time ([DateTimeOffset]::new($startTime).ToUnixTimeMilliseconds()) --end-time ([DateTimeOffset]::new($endTime).ToUnixTimeMilliseconds()) $regionParam --profile $Profile --output json | ConvertFrom-Json
        
        $errorAnalysis = @{
            TotalErrors = $errorLogs.events.Count
            ErrorTypes = @{}
            ErrorTrends = @()
            CriticalErrors = @()
        }
        
        foreach ($event in $errorLogs.events) {
            $message = $event.message
            
            # Categorize errors
            if ($message -match "timeout|Timeout") {
                $errorAnalysis.ErrorTypes["Timeout"]++
            } elseif ($message -match "memory|Memory") {
                $errorAnalysis.ErrorTypes["Memory"]++
            } elseif ($message -match "permission|Permission") {
                $errorAnalysis.ErrorTypes["Permission"]++
            } elseif ($message -match "network|Network") {
                $errorAnalysis.ErrorTypes["Network"]++
            } else {
                $errorAnalysis.ErrorTypes["Other"]++
            }
            
            # Identify critical errors
            if ($message -match "CRITICAL|FATAL|OutOfMemory|TimeoutException") {
                $errorAnalysis.CriticalErrors += [PSCustomObject]@{
                    Timestamp = $event.timestamp
                    Message = $message
                }
            }
        }
        
        return $errorAnalysis
    }
    catch {
        Write-Host "Unable to analyze function errors" -ForegroundColor Red
        return $null
    }
}

function Set-FunctionAlerts {
    param([string]$FunctionName, [string]$Region)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    Write-Host "Setting up CloudWatch alarms for function: $FunctionName" -ForegroundColor Yellow
    
    try {
        # Error rate alarm
        $errorAlarmName = "$FunctionName-ErrorRate"
        $errorAlarm = aws cloudwatch put-metric-alarm --alarm-name $errorAlarmName --alarm-description "High error rate for $FunctionName" --metric-name Errors --namespace AWS/Lambda --statistic Sum --period 300 --threshold 5 --comparison-operator GreaterThanThreshold --dimensions Name=FunctionName,Value=$FunctionName --evaluation-periods 2 $regionParam --profile $Profile
        
        # Duration alarm
        $durationAlarmName = "$FunctionName-Duration"
        $durationAlarm = aws cloudwatch put-metric-alarm --alarm-name $durationAlarmName --alarm-description "High duration for $FunctionName" --metric-name Duration --namespace AWS/Lambda --statistic Average --period 300 --threshold 10000 --comparison-operator GreaterThanThreshold --dimensions Name=FunctionName,Value=$FunctionName --evaluation-periods 2 $regionParam --profile $Profile
        
        # Throttle alarm
        $throttleAlarmName = "$FunctionName-Throttles"
        $throttleAlarm = aws cloudwatch put-metric-alarm --alarm-name $throttleAlarmName --alarm-description "High throttle rate for $FunctionName" --metric-name Throttles --namespace AWS/Lambda --statistic Sum --period 300 --threshold 10 --comparison-operator GreaterThanThreshold --dimensions Name=FunctionName,Value=$FunctionName --evaluation-periods 2 $regionParam --profile $Profile
        
        Write-Host "Alarms created successfully" -ForegroundColor Green
        Write-Host "  Error Rate Alarm: $errorAlarmName" -ForegroundColor Gray
        Write-Host "  Duration Alarm: $durationAlarmName" -ForegroundColor Gray
        Write-Host "  Throttle Alarm: $throttleAlarmName" -ForegroundColor Gray
    }
    catch {
        Write-Host "Failed to create alarms: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Export-MonitoringReport {
    param([string]$FunctionName, [object]$Metrics, [object]$Logs, [object]$Performance, [object]$Errors)
    
    $report = @{
        FunctionName = $FunctionName
        Timestamp = Get-Date
        Metrics = $Metrics
        Logs = $Logs
        Performance = $Performance
        Errors = $Errors
    }
    
    $reportFile = "lambda-monitoring-$FunctionName-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $report | ConvertTo-Json -Depth 10 | Out-File $reportFile
    
    Write-Host "Monitoring report exported to: $reportFile" -ForegroundColor Green
    return $reportFile
}

Write-Host "AWS Lambda Function Monitoring" -ForegroundColor Green
Write-Host "=============================" -ForegroundColor Green

if (-not $FunctionName) {
    Write-Host "Please specify a FunctionName to monitor" -ForegroundColor Red
    return
}

switch ($Action.ToLower()) {
    "monitor" {
        Write-Host "`nMonitoring function: $FunctionName" -ForegroundColor Yellow
        
        $metrics = Get-FunctionMetrics -FunctionName $FunctionName -Region $Region -Days $Days
        $logs = Get-FunctionLogs -FunctionName $FunctionName -Region $Region -Days $Days
        $performance = Analyze-FunctionPerformance -FunctionName $FunctionName -Region $Region
        
        if ($metrics) {
            $totalInvocations = ($metrics.Invocations | Measure-Object -Property Value -Sum).Sum
            $totalErrors = ($metrics.Errors | Measure-Object -Property Value -Sum).Sum
            $avgDuration = ($metrics.Duration | Measure-Object -Property Value -Average).Average
            $totalThrottles = ($metrics.Throttles | Measure-Object -Property Value -Sum).Sum
            
            Write-Host "`nFunction Metrics (Last $Days days):" -ForegroundColor Cyan
            Write-Host "Total Invocations: $totalInvocations" -ForegroundColor Green
            Write-Host "Total Errors: $totalErrors" -ForegroundColor $(if($totalErrors -eq 0) { "Green" } else { "Red" })
            Write-Host "Average Duration: $([math]::Round($avgDuration, 2)) ms" -ForegroundColor Gray
            Write-Host "Total Throttles: $totalThrottles" -ForegroundColor $(if($totalThrottles -eq 0) { "Green" } else { "Yellow" })
            
            if ($totalInvocations -gt 0) {
                $errorRate = [math]::Round(($totalErrors / $totalInvocations) * 100, 2)
                Write-Host "Error Rate: $errorRate%" -ForegroundColor $(if($errorRate -lt 5) { "Green" } elseif($errorRate -lt 10) { "Yellow" } else { "Red" })
            }
        }
        
        if ($logs) {
            Write-Host "`nLog Analysis:" -ForegroundColor Cyan
            Write-Host "Total Events: $($logs.TotalEvents)" -ForegroundColor Gray
            Write-Host "Error Events: $($logs.ErrorEvents.Count)" -ForegroundColor $(if($logs.ErrorEvents.Count -eq 0) { "Green" } else { "Red" })
            Write-Host "Slow Executions: $($logs.SlowExecutions.Count)" -ForegroundColor $(if($logs.SlowExecutions.Count -eq 0) { "Green" } else { "Yellow" })
        }
        
        if ($performance) {
            Write-Host "`nPerformance Analysis:" -ForegroundColor Cyan
            Write-Host "Memory: $($performance.MemorySize) MB" -ForegroundColor Gray
            Write-Host "Timeout: $($performance.Timeout) seconds" -ForegroundColor Gray
            Write-Host "Code Size: $([math]::Round($performance.CodeSize / 1MB, 2)) MB" -ForegroundColor Gray
            
            if ($performance.Issues.Count -gt 0) {
                Write-Host "`nIssues:" -ForegroundColor Red
                foreach ($issue in $performance.Issues) {
                    Write-Host "  - $issue" -ForegroundColor Red
                }
            }
            
            if ($performance.Recommendations.Count -gt 0) {
                Write-Host "`nRecommendations:" -ForegroundColor Yellow
                foreach ($rec in $performance.Recommendations) {
                    Write-Host "  - $rec" -ForegroundColor Yellow
                }
            }
        }
    }
    
    "metrics" {
        $metrics = Get-FunctionMetrics -FunctionName $FunctionName -Region $Region -Days $Days
        
        if ($metrics) {
            Write-Host "`nDetailed Metrics:" -ForegroundColor Cyan
            
            if ($metrics.Invocations.Count -gt 0) {
                Write-Host "`nInvocations:" -ForegroundColor Yellow
                foreach ($point in $metrics.Invocations) {
                    Write-Host "  $($point.Timestamp): $($point.Value)" -ForegroundColor Gray
                }
            }
            
            if ($metrics.Errors.Count -gt 0) {
                Write-Host "`nErrors:" -ForegroundColor Yellow
                foreach ($point in $metrics.Errors) {
                    Write-Host "  $($point.Timestamp): $($point.Value)" -ForegroundColor Red
                }
            }
            
            if ($metrics.Duration.Count -gt 0) {
                Write-Host "`nDuration (ms):" -ForegroundColor Yellow
                foreach ($point in $metrics.Duration) {
                    Write-Host "  $($point.Timestamp): $($point.Value)" -ForegroundColor Gray
                }
            }
        }
    }
    
    "logs" {
        $logs = Get-FunctionLogs -FunctionName $FunctionName -Region $Region -Days $Days
        
        if ($logs) {
            Write-Host "`nRecent Log Events:" -ForegroundColor Cyan
            foreach ($event in $logs.RecentEvents) {
                Write-Host "  $($event.Timestamp): $($event.Message)" -ForegroundColor Gray
            }
            
            if ($logs.ErrorEvents.Count -gt 0) {
                Write-Host "`nError Events:" -ForegroundColor Red
                foreach ($event in $logs.ErrorEvents | Select-Object -First 5) {
                    Write-Host "  $($event.Timestamp): $($event.Message)" -ForegroundColor Red
                }
            }
        }
    }
    
    "errors" {
        $errors = Get-FunctionErrors -FunctionName $FunctionName -Region $Region -Days $Days
        
        if ($errors) {
            Write-Host "`nError Analysis:" -ForegroundColor Cyan
            Write-Host "Total Errors: $($errors.TotalErrors)" -ForegroundColor $(if($errors.TotalErrors -eq 0) { "Green" } else { "Red" })
            
            if ($errors.ErrorTypes.Count -gt 0) {
                Write-Host "`nError Types:" -ForegroundColor Yellow
                foreach ($type in $errors.ErrorTypes.GetEnumerator()) {
                    Write-Host "  $($type.Key): $($type.Value)" -ForegroundColor Gray
                }
            }
            
            if ($errors.CriticalErrors.Count -gt 0) {
                Write-Host "`nCritical Errors:" -ForegroundColor Red
                foreach ($error in $errors.CriticalErrors | Select-Object -First 3) {
                    Write-Host "  $($error.Timestamp): $($error.Message)" -ForegroundColor Red
                }
            }
        }
    }
    
    "performance" {
        $performance = Analyze-FunctionPerformance -FunctionName $FunctionName -Region $Region
        
        if ($performance) {
            Write-Host "`nPerformance Analysis:" -ForegroundColor Cyan
            Write-Host "Runtime: $($performance.Runtime)" -ForegroundColor Gray
            Write-Host "Memory: $($performance.MemorySize) MB" -ForegroundColor Gray
            Write-Host "Timeout: $($performance.Timeout) seconds" -ForegroundColor Gray
            Write-Host "Code Size: $([math]::Round($performance.CodeSize / 1MB, 2)) MB" -ForegroundColor Gray
            Write-Host "Last Modified: $($performance.LastModified)" -ForegroundColor Gray
            
            if ($performance.Issues.Count -gt 0) {
                Write-Host "`nIssues:" -ForegroundColor Red
                foreach ($issue in $performance.Issues) {
                    Write-Host "  - $issue" -ForegroundColor Red
                }
            }
            
            if ($performance.Recommendations.Count -gt 0) {
                Write-Host "`nRecommendations:" -ForegroundColor Yellow
                foreach ($rec in $performance.Recommendations) {
                    Write-Host "  - $rec" -ForegroundColor Yellow
                }
            }
        }
    }
    
    "alerts" {
        Set-FunctionAlerts -FunctionName $FunctionName -Region $Region
    }
    
    default {
        Write-Host "Invalid action. Valid actions: monitor, metrics, logs, errors, performance, alerts" -ForegroundColor Red
    }
}

if ($Export) {
    $metrics = Get-FunctionMetrics -FunctionName $FunctionName -Region $Region -Days $Days
    $logs = Get-FunctionLogs -FunctionName $FunctionName -Region $Region -Days $Days
    $performance = Analyze-FunctionPerformance -FunctionName $FunctionName -Region $Region
    $errors = Get-FunctionErrors -FunctionName $FunctionName -Region $Region -Days $Days
    
    $reportFile = Export-MonitoringReport -FunctionName $FunctionName -Metrics $metrics -Logs $logs -Performance $performance -Errors $errors
}

Write-Host "`nUsage Examples:" -ForegroundColor Magenta
Write-Host "  .\function-monitoring.ps1 -FunctionName 'my-function' -Action monitor"
Write-Host "  .\function-monitoring.ps1 -FunctionName 'my-function' -Action metrics -Days 30"
Write-Host "  .\function-monitoring.ps1 -FunctionName 'my-function' -Action logs -Days 7"
Write-Host "  .\function-monitoring.ps1 -FunctionName 'my-function' -Action errors"
Write-Host "  .\function-monitoring.ps1 -FunctionName 'my-function' -Action performance"
Write-Host "  .\function-monitoring.ps1 -FunctionName 'my-function' -Action alerts" 