<#
.SYNOPSIS
    AWS Cost Analysis and Reporting Script
    
.DESCRIPTION
    This script analyzes AWS costs and generates detailed reports including:
    - Monthly cost breakdown by service
    - Cost trends over time
    - Resource utilization analysis
    - Cost optimization recommendations
    
.PARAMETER Region
    AWS region to analyze (default: us-east-1)
    
.PARAMETER StartDate
    Start date for cost analysis (default: 30 days ago)
    
.PARAMETER EndDate
    End date for cost analysis (default: today)
    
.PARAMETER OutputPath
    Path to save the report (default: current directory)
    
.PARAMETER Detailed
    Generate detailed cost breakdown
    
.EXAMPLE
    .\cost-analysis.ps1 -Region us-west-2 -Detailed
    
.EXAMPLE
    .\cost-analysis.ps1 -StartDate "2024-01-01" -EndDate "2024-01-31" -OutputPath "C:\Reports"
    
.NOTES
    Author: IT Team
    Date: 2024
    Requires: AWS CLI and PowerShell AWS.Tools module
#>

param(
    [string]$Region = "us-east-1",
    [string]$StartDate = (Get-Date).AddDays(-30).ToString("yyyy-MM-dd"),
    [string]$EndDate = (Get-Date).ToString("yyyy-MM-dd"),
    [string]$OutputPath = ".",
    [switch]$Detailed
)

# Set AWS region
Set-DefaultAWSRegion -Region $Region

# Create output directory if it doesn't exist
if (!(Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force
}

$ReportDate = Get-Date -Format "yyyy-MM-dd_HH-mm"
$ReportFile = Join-Path $OutputPath "aws-cost-report-$ReportDate.html"

Write-Host "Starting AWS Cost Analysis..." -ForegroundColor Green
Write-Host "Region: $Region" -ForegroundColor Yellow
Write-Host "Period: $StartDate to $EndDate" -ForegroundColor Yellow

try {
    # Get cost and usage data
    Write-Host "Fetching cost data..." -ForegroundColor Cyan
    
    $CostData = Get-CECostAndUsage -TimePeriodStart $StartDate -TimePeriodEnd $EndDate -Granularity MONTHLY -Metrics "BlendedCost" -GroupBy @(@{Type="DIMENSION";Key="SERVICE"})
    
    # Get detailed cost breakdown if requested
    if ($Detailed) {
        Write-Host "Fetching detailed cost breakdown..." -ForegroundColor Cyan
        $DetailedCostData = Get-CECostAndUsage -TimePeriodStart $StartDate -TimePeriodEnd $EndDate -Granularity DAILY -Metrics "BlendedCost" -GroupBy @(@{Type="DIMENSION";Key="SERVICE"})
    }
    
    # Get resource utilization data
    Write-Host "Analyzing resource utilization..." -ForegroundColor Cyan
    $EC2Instances = Get-EC2Instance
    $S3Buckets = Get-S3Bucket
    $RDSInstances = Get-RDSInstance
    
    # Calculate total costs
    $TotalCost = 0
    $ServiceCosts = @{}
    
    foreach ($cost in $CostData.ResultsByTime) {
        foreach ($group in $cost.Groups) {
            $serviceName = $group.Keys[0]
            $costAmount = [double]$group.Metrics.BlendedCost.Amount
            $TotalCost += $costAmount
            
            if ($ServiceCosts.ContainsKey($serviceName)) {
                $ServiceCosts[$serviceName] += $costAmount
            } else {
                $ServiceCosts[$serviceName] = $costAmount
            }
        }
    }
    
    # Generate HTML report
    Write-Host "Generating HTML report..." -ForegroundColor Cyan
    
    $HtmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>AWS Cost Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #232f3e; color: white; padding: 20px; border-radius: 5px; }
        .summary { background-color: #f8f9fa; padding: 20px; margin: 20px 0; border-radius: 5px; }
        .service-cost { background-color: white; padding: 15px; margin: 10px 0; border-left: 4px solid #0073bb; }
        .cost-breakdown { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .chart { background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .recommendation { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .warning { background-color: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; margin: 10px 0; border-radius: 5px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #0073bb; color: white; }
        .percentage { font-weight: bold; color: #0073bb; }
    </style>
</head>
<body>
    <div class="header">
        <h1>AWS Cost Analysis Report</h1>
        <p>Generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        <p>Region: $Region | Period: $StartDate to $EndDate</p>
    </div>
    
    <div class="summary">
        <h2>Cost Summary</h2>
        <p><strong>Total Cost:</strong> $($TotalCost.ToString("C"))</p>
        <p><strong>Period:</strong> $StartDate to $EndDate</p>
        <p><strong>Days Analyzed:</strong> $((Get-Date $EndDate) - (Get-Date $StartDate)).Days days</p>
    </div>
    
    <div class="cost-breakdown">
        <div class="chart">
            <h3>Cost by Service</h3>
            <table>
                <tr><th>Service</th><th>Cost</th><th>Percentage</th></tr>
"@
    
    # Add service cost breakdown
    $SortedServices = $ServiceCosts.GetEnumerator() | Sort-Object Value -Descending
    foreach ($service in $SortedServices) {
        $percentage = ($service.Value / $TotalCost * 100).ToString("F2")
        $HtmlReport += @"
                <tr>
                    <td>$($service.Key)</td>
                    <td>$($service.Value.ToString("C"))</td>
                    <td class="percentage">$percentage%</td>
                </tr>
"@
    }
    
    $HtmlReport += @"
            </table>
        </div>
        
        <div class="chart">
            <h3>Resource Summary</h3>
            <table>
                <tr><th>Resource Type</th><th>Count</th></tr>
                <tr><td>EC2 Instances</td><td>$($EC2Instances.Count)</td></tr>
                <tr><td>S3 Buckets</td><td>$($S3Buckets.Count)</td></tr>
                <tr><td>RDS Instances</td><td>$($RDSInstances.Count)</td></tr>
            </table>
        </div>
    </div>
    
    <div class="recommendation">
        <h3>Cost Optimization Recommendations</h3>
        <ul>
"@
    
    # Generate recommendations based on analysis
    $HighCostServices = $SortedServices | Where-Object { $_.Value -gt ($TotalCost * 0.1) }
    foreach ($service in $HighCostServices) {
        $HtmlReport += "<li><strong>$($service.Key):</strong> Consider reviewing usage and optimizing resources</li>"
    }
    
    if ($EC2Instances.Count -gt 0) {
        $HtmlReport += "<li><strong>EC2:</strong> Review instance types and consider using Spot instances for non-critical workloads</li>"
    }
    
    if ($S3Buckets.Count -gt 0) {
        $HtmlReport += "<li><strong>S3:</strong> Implement lifecycle policies to move data to cheaper storage classes</li>"
    }
    
    $HtmlReport += @"
        </ul>
    </div>
    
    <div class="warning">
        <h3>Important Notes</h3>
        <ul>
            <li>This report shows blended costs (including credits and discounts)</li>
            <li>Consider implementing cost allocation tags for better tracking</li>
            <li>Review unused resources regularly to reduce costs</li>
            <li>Set up billing alerts to monitor spending</li>
        </ul>
    </div>
</body>
</html>
"@
    
    # Save the report
    $HtmlReport | Out-File -FilePath $ReportFile -Encoding UTF8
    
    Write-Host "Report generated successfully!" -ForegroundColor Green
    Write-Host "Report saved to: $ReportFile" -ForegroundColor Yellow
    
    # Display summary in console
    Write-Host "`nCost Summary:" -ForegroundColor Green
    Write-Host "Total Cost: $($TotalCost.ToString("C"))" -ForegroundColor White
    Write-Host "Top 5 Services by Cost:" -ForegroundColor Yellow
    
    $Top5Services = $SortedServices | Select-Object -First 5
    foreach ($service in $Top5Services) {
        $percentage = ($service.Value / $TotalCost * 100).ToString("F2")
        Write-Host "  $($service.Key): $($service.Value.ToString("C")) ($percentage%)" -ForegroundColor White
    }
    
} catch {
    Write-Error "Error during cost analysis: $($_.Exception.Message)"
    Write-Host "Make sure you have proper AWS credentials configured." -ForegroundColor Red
    exit 1
}

Write-Host "`nCost analysis completed successfully!" -ForegroundColor Green 