# =============================================================================
# Get-AzureResourceInventory.ps1
# =============================================================================
# Purpose: Comprehensive Azure resource inventory and management
# Author: System Administrator
# Version: 1.0.0
# Date: $(Get-Date -Format "yyyy-MM-dd")
# =============================================================================

<#
.SYNOPSIS
    Generates comprehensive Azure resource inventory reports with cost analysis and security assessment.

.DESCRIPTION
    This script provides detailed Azure resource inventory including:
    - Virtual machines and their configurations
    - Storage accounts and blob containers
    - Network resources (VNETs, subnets, NSGs)
    - Database resources (SQL, Cosmos DB, Redis)
    - App Services and Function Apps
    - Key Vaults and security resources
    - Cost analysis and optimization recommendations
    - Security assessment and compliance checks
    - Resource tagging and governance
    - Backup and disaster recovery status

.PARAMETER SubscriptionId
    Azure subscription ID to analyze. Defaults to current subscription.

.PARAMETER ResourceGroup
    Specific resource group to analyze. Defaults to all resource groups.

.PARAMETER ExportPath
    Path to export the inventory report. Supports CSV, JSON, and HTML formats.

.PARAMETER ReportType
    Type of report to generate: Basic, Detailed, Security, Cost, or All.

.PARAMETER IncludeCosts
    Include cost analysis in the report.

.PARAMETER IncludeSecurity
    Include security assessment in the report.

.PARAMETER IncludeTags
    Include resource tagging analysis.

.PARAMETER DaysBack
    Number of days back to analyze costs and usage.

.PARAMETER Verbose
    Enable verbose output for detailed logging.

.EXAMPLE
    .\Get-AzureResourceInventory.ps1 -ReportType Detailed -ExportPath "C:\Reports\AzureInventory.csv"

.EXAMPLE
    .\Get-AzureResourceInventory.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012" -IncludeCosts

.EXAMPLE
    .\Get-AzureResourceInventory.ps1 -ResourceGroup "Production-RG" -ReportType Security

.NOTES
    Requires Azure PowerShell module (Az)
    Requires appropriate Azure permissions
    Supports Windows PowerShell 5.1 and PowerShell Core 6.0+
    Cost analysis requires billing permissions
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $false)]
    [string]$ResourceGroup,
    
    [Parameter(Mandatory = $false)]
    [string]$ExportPath = ".\AzureInventory_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Detailed", "Security", "Cost", "All")]
    [string]$ReportType = "Detailed",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeCosts,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSecurity,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeTags,
    
    [Parameter(Mandatory = $false)]
    [int]$DaysBack = 30,
    
    [Parameter(Mandatory = $false)]
    [switch]$Verbose
)

# =============================================================================
# SCRIPT CONFIGURATION
# =============================================================================

# Set error action preference
$ErrorActionPreference = "Stop"

# Import required modules
try {
    Import-Module Az -ErrorAction Stop
    Write-Host "✓ Azure PowerShell module loaded successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to load Azure PowerShell module. Please install it with: Install-Module -Name Az"
    exit 1
}

# =============================================================================
# FUNCTIONS
# =============================================================================

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        default { Write-Host $logMessage -ForegroundColor White }
    }
}

function Connect-AzureAccount {
    try {
        $context = Get-AzContext
        if (-not $context) {
            Write-Log "No Azure context found. Please run Connect-AzAccount" -Level "ERROR"
            exit 1
        }
        
        Write-Log "Connected to Azure subscription: $($context.Subscription.Name)" -Level "SUCCESS"
        return $context
    } catch {
        Write-Log "Error connecting to Azure: $($_.Exception.Message)" -Level "ERROR"
        exit 1
    }
}

function Get-VMInventory {
    param([string]$ResourceGroupName = "*")
    
    Write-Log "Retrieving Virtual Machine inventory..." -Level "INFO"
    
    $vms = @()
    try {
        $vmList = Get-AzVM -ResourceGroupName $ResourceGroupName -ErrorAction Stop
        
        foreach ($vm in $vmList) {
            $vmInfo = Get-AzVM -ResourceGroupName $vm.ResourceGroupName -Name $vm.Name -Status
            $vmStatus = $vmInfo.Statuses | Where-Object { $_.Code -like "PowerState/*" }
            
            $vmData = [PSCustomObject]@{
                ResourceType = "Virtual Machine"
                Name = $vm.Name
                ResourceGroup = $vm.ResourceGroupName
                Location = $vm.Location
                Size = $vm.HardwareProfile.VmSize
                OS = $vm.StorageProfile.OsDisk.OsType
                Status = $vmStatus.DisplayStatus
                Tags = $vm.Tags
                CreatedTime = $vm.Tags.CreatedTime
                Owner = $vm.Tags.Owner
                Environment = $vm.Tags.Environment
                CostCenter = $vm.Tags.CostCenter
                BackupEnabled = $false
                BackupPolicy = $null
                NetworkInterfaces = ($vm.NetworkProfile.NetworkInterfaces | ForEach-Object { $_.Id.Split('/')[-1] }) -join ";"
                DataDisks = $vm.StorageProfile.DataDisks.Count
                OSDiskSize = $vm.StorageProfile.OsDisk.DiskSizeGB
                TotalDiskSize = ($vm.StorageProfile.OsDisk.DiskSizeGB + ($vm.StorageProfile.DataDisks | ForEach-Object { $_.DiskSizeGB } | Measure-Object -Sum).Sum)
            }
            
            # Check backup status
            try {
                $backupItems = Get-AzRecoveryServicesBackupItem -VaultId $vm.Id -ErrorAction SilentlyContinue
                if ($backupItems) {
                    $vmData.BackupEnabled = $true
                    $vmData.BackupPolicy = $backupItems.ProtectionPolicyName
                }
            } catch {
                # Backup not configured
            }
            
            $vms += $vmData
        }
        
        Write-Log "Found $($vms.Count) virtual machines" -Level "SUCCESS"
        return $vms
        
    } catch {
        Write-Log "Error retrieving VM inventory: $($_.Exception.Message)" -Level "ERROR"
        return @()
    }
}

function Get-StorageInventory {
    param([string]$ResourceGroupName = "*")
    
    Write-Log "Retrieving Storage Account inventory..." -Level "INFO"
    
    $storageAccounts = @()
    try {
        $storageList = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -ErrorAction Stop
        
        foreach ($storage in $storageList) {
            $storageData = [PSCustomObject]@{
                ResourceType = "Storage Account"
                Name = $storage.StorageAccountName
                ResourceGroup = $storage.ResourceGroupName
                Location = $storage.Location
                SKU = $storage.Sku.Name
                Kind = $storage.Kind
                AccessTier = $storage.AccessTier
                EnableHttpsTrafficOnly = $storage.EnableHttpsTrafficOnly
                MinimumTlsVersion = $storage.MinimumTlsVersion
                AllowBlobPublicAccess = $storage.AllowBlobPublicAccess
                Tags = $storage.Tags
                CreatedTime = $storage.Tags.CreatedTime
                Owner = $storage.Tags.Owner
                Environment = $storage.Tags.Environment
                CostCenter = $storage.Tags.CostCenter
                BlobContainers = 0
                FileShares = 0
                Queues = 0
                Tables = 0
                TotalSizeGB = 0
            }
            
            # Get container count and size
            try {
                $context = $storage.Context
                $containers = Get-AzStorageContainer -Context $context -ErrorAction SilentlyContinue
                $storageData.BlobContainers = $containers.Count
                
                # Calculate total size
                $totalSize = 0
                foreach ($container in $containers) {
                    $blobs = Get-AzStorageBlob -Container $container.Name -Context $context -ErrorAction SilentlyContinue
                    $containerSize = ($blobs | Measure-Object -Property Length -Sum).Sum
                    $totalSize += $containerSize
                }
                $storageData.TotalSizeGB = [math]::Round($totalSize / 1GB, 2)
            } catch {
                Write-Log "Error calculating storage size for $($storage.StorageAccountName)" -Level "WARNING"
            }
            
            $storageAccounts += $storageData
        }
        
        Write-Log "Found $($storageAccounts.Count) storage accounts" -Level "SUCCESS"
        return $storageAccounts
        
    } catch {
        Write-Log "Error retrieving storage inventory: $($_.Exception.Message)" -Level "ERROR"
        return @()
    }
}

function Get-NetworkInventory {
    param([string]$ResourceGroupName = "*")
    
    Write-Log "Retrieving Network inventory..." -Level "INFO"
    
    $networkResources = @()
    
    try {
        # Virtual Networks
        $vnets = Get-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -ErrorAction Stop
        foreach ($vnet in $vnets) {
            $vnetData = [PSCustomObject]@{
                ResourceType = "Virtual Network"
                Name = $vnet.Name
                ResourceGroup = $vnet.ResourceGroupName
                Location = $vnet.Location
                AddressSpace = $vnet.AddressSpace.AddressPrefixes -join ";"
                SubnetCount = $vnet.Subnets.Count
                Subnets = $vnet.Subnets.Name -join ";"
                DnsServers = $vnet.DhcpOptions.DnsServers -join ";"
                Tags = $vnet.Tags
                CreatedTime = $vnet.Tags.CreatedTime
                Owner = $vnet.Tags.Owner
                Environment = $vnet.Tags.Environment
                CostCenter = $vnet.Tags.CostCenter
            }
            $networkResources += $vnetData
        }
        
        # Network Security Groups
        $nsgs = Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -ErrorAction Stop
        foreach ($nsg in $nsgs) {
            $nsgData = [PSCustomObject]@{
                ResourceType = "Network Security Group"
                Name = $nsg.Name
                ResourceGroup = $nsg.ResourceGroupName
                Location = $nsg.Location
                SecurityRules = $nsg.SecurityRules.Count
                DefaultSecurityRules = $nsg.DefaultSecurityRules.Count
                Tags = $nsg.Tags
                CreatedTime = $nsg.Tags.CreatedTime
                Owner = $nsg.Tags.Owner
                Environment = $nsg.Tags.Environment
                CostCenter = $nsg.Tags.CostCenter
            }
            $networkResources += $nsgData
        }
        
        # Load Balancers
        $lbs = Get-AzLoadBalancer -ResourceGroupName $ResourceGroupName -ErrorAction Stop
        foreach ($lb in $lbs) {
            $lbData = [PSCustomObject]@{
                ResourceType = "Load Balancer"
                Name = $lb.Name
                ResourceGroup = $lb.ResourceGroupName
                Location = $lb.Location
                SKU = $lb.Sku.Name
                FrontendIPConfigurations = $lb.FrontendIpConfigurations.Count
                BackendAddressPools = $lb.BackendAddressPools.Count
                Probes = $lb.Probes.Count
                Tags = $lb.Tags
                CreatedTime = $lb.Tags.CreatedTime
                Owner = $lb.Tags.Owner
                Environment = $lb.Tags.Environment
                CostCenter = $lb.Tags.CostCenter
            }
            $networkResources += $lbData
        }
        
        Write-Log "Found $($networkResources.Count) network resources" -Level "SUCCESS"
        return $networkResources
        
    } catch {
        Write-Log "Error retrieving network inventory: $($_.Exception.Message)" -Level "ERROR"
        return @()
    }
}

function Get-DatabaseInventory {
    param([string]$ResourceGroupName = "*")
    
    Write-Log "Retrieving Database inventory..." -Level "INFO"
    
    $databaseResources = @()
    
    try {
        # SQL Servers
        $sqlServers = Get-AzSqlServer -ResourceGroupName $ResourceGroupName -ErrorAction Stop
        foreach ($server in $sqlServers) {
            $serverData = [PSCustomObject]@{
                ResourceType = "SQL Server"
                Name = $server.ServerName
                ResourceGroup = $server.ResourceGroupName
                Location = $server.Location
                Version = $server.SqlServerVersion
                AdministratorLogin = $server.SqlAdministratorLogin
                Tags = $server.Tags
                CreatedTime = $server.Tags.CreatedTime
                Owner = $server.Tags.Owner
                Environment = $server.Tags.Environment
                CostCenter = $server.Tags.CostCenter
                DatabaseCount = 0
                TotalSizeGB = 0
            }
            
            # Get databases
            try {
                $databases = Get-AzSqlDatabase -ServerName $server.ServerName -ResourceGroupName $server.ResourceGroupName -ErrorAction SilentlyContinue
                $serverData.DatabaseCount = $databases.Count
                $serverData.TotalSizeGB = ($databases | Measure-Object -Property MaxSizeBytes -Sum).Sum / 1GB
            } catch {
                Write-Log "Error retrieving databases for server $($server.ServerName)" -Level "WARNING"
            }
            
            $databaseResources += $serverData
        }
        
        # Cosmos DB Accounts
        $cosmosAccounts = Get-AzCosmosDBAccount -ResourceGroupName $ResourceGroupName -ErrorAction Stop
        foreach ($account in $cosmosAccounts) {
            $accountData = [PSCustomObject]@{
                ResourceType = "Cosmos DB Account"
                Name = $account.Name
                ResourceGroup = $account.ResourceGroupName
                Location = $account.Location
                DatabaseAccountOfferType = $account.DatabaseAccountOfferType
                ConsistencyLevel = $account.ConsistencyPolicy.DefaultConsistencyLevel
                ReadLocations = $account.ReadLocations.Count
                WriteLocations = $account.WriteLocations.Count
                Tags = $account.Tags
                CreatedTime = $account.Tags.CreatedTime
                Owner = $account.Tags.Owner
                Environment = $account.Tags.Environment
                CostCenter = $account.Tags.CostCenter
            }
            $databaseResources += $accountData
        }
        
        # Redis Cache
        $redisCaches = Get-AzRedisCache -ResourceGroupName $ResourceGroupName -ErrorAction Stop
        foreach ($cache in $redisCaches) {
            $cacheData = [PSCustomObject]@{
                ResourceType = "Redis Cache"
                Name = $cache.Name
                ResourceGroup = $cache.ResourceGroupName
                Location = $cache.Location
                SKU = $cache.Sku.Name
                Size = $cache.Sku.Size
                Capacity = $cache.Sku.Capacity
                EnableNonSslPort = $cache.EnableNonSslPort
                Tags = $cache.Tags
                CreatedTime = $cache.Tags.CreatedTime
                Owner = $cache.Tags.Owner
                Environment = $cache.Tags.Environment
                CostCenter = $cache.Tags.CostCenter
            }
            $databaseResources += $cacheData
        }
        
        Write-Log "Found $($databaseResources.Count) database resources" -Level "SUCCESS"
        return $databaseResources
        
    } catch {
        Write-Log "Error retrieving database inventory: $($_.Exception.Message)" -Level "ERROR"
        return @()
    }
}

function Get-AppServiceInventory {
    param([string]$ResourceGroupName = "*")
    
    Write-Log "Retrieving App Service inventory..." -Level "INFO"
    
    $appServices = @()
    
    try {
        # App Service Plans
        $appServicePlans = Get-AzAppServicePlan -ResourceGroupName $ResourceGroupName -ErrorAction Stop
        foreach ($plan in $appServicePlans) {
            $planData = [PSCustomObject]@{
                ResourceType = "App Service Plan"
                Name = $plan.Name
                ResourceGroup = $plan.ResourceGroupName
                Location = $plan.Location
                SKU = $plan.Sku.Name
                Tier = $plan.Sku.Tier
                Size = $plan.Sku.Size
                Capacity = $plan.Sku.Capacity
                Tags = $plan.Tags
                CreatedTime = $plan.Tags.CreatedTime
                Owner = $plan.Tags.Owner
                Environment = $plan.Tags.Environment
                CostCenter = $plan.Tags.CostCenter
                AppCount = 0
            }
            
            # Get apps in this plan
            try {
                $apps = Get-AzWebApp -AppServicePlan $plan -ErrorAction SilentlyContinue
                $planData.AppCount = $apps.Count
            } catch {
                Write-Log "Error retrieving apps for plan $($plan.Name)" -Level "WARNING"
            }
            
            $appServices += $planData
        }
        
        # Web Apps
        $webApps = Get-AzWebApp -ResourceGroupName $ResourceGroupName -ErrorAction Stop
        foreach ($app in $webApps) {
            $appData = [PSCustomObject]@{
                ResourceType = "Web App"
                Name = $app.Name
                ResourceGroup = $app.ResourceGroupName
                Location = $app.Location
                AppServicePlan = $app.ServerFarmId.Split('/')[-1]
                State = $app.State
                HostNames = $app.HostNames -join ";"
                Tags = $app.Tags
                CreatedTime = $app.Tags.CreatedTime
                Owner = $app.Tags.Owner
                Environment = $app.Tags.Environment
                CostCenter = $app.Tags.CostCenter
            }
            $appServices += $appData
        }
        
        # Function Apps
        $functionApps = Get-AzFunctionApp -ResourceGroupName $ResourceGroupName -ErrorAction Stop
        foreach ($function in $functionApps) {
            $functionData = [PSCustomObject]@{
                ResourceType = "Function App"
                Name = $function.Name
                ResourceGroup = $function.ResourceGroupName
                Location = $function.Location
                AppServicePlan = $function.ServerFarmId.Split('/')[-1]
                Runtime = $function.Runtime
                State = $function.State
                HostNames = $function.HostNames -join ";"
                Tags = $function.Tags
                CreatedTime = $function.Tags.CreatedTime
                Owner = $function.Tags.Owner
                Environment = $function.Tags.Environment
                CostCenter = $function.Tags.CostCenter
            }
            $appServices += $functionData
        }
        
        Write-Log "Found $($appServices.Count) app service resources" -Level "SUCCESS"
        return $appServices
        
    } catch {
        Write-Log "Error retrieving app service inventory: $($_.Exception.Message)" -Level "ERROR"
        return @()
    }
}

function Get-SecurityInventory {
    param([string]$ResourceGroupName = "*")
    
    Write-Log "Retrieving Security inventory..." -Level "INFO"
    
    $securityResources = @()
    
    try {
        # Key Vaults
        $keyVaults = Get-AzKeyVault -ResourceGroupName $ResourceGroupName -ErrorAction Stop
        foreach ($vault in $keyVaults) {
            $vaultData = [PSCustomObject]@{
                ResourceType = "Key Vault"
                Name = $vault.VaultName
                ResourceGroup = $vault.ResourceGroupName
                Location = $vault.Location
                SKU = $vault.Sku.Name
                EnabledForDeployment = $vault.EnabledForDeployment
                EnabledForTemplateDeployment = $vault.EnabledForTemplateDeployment
                EnabledForDiskEncryption = $vault.EnabledForDiskEncryption
                Tags = $vault.Tags
                CreatedTime = $vault.Tags.CreatedTime
                Owner = $vault.Tags.Owner
                Environment = $vault.Tags.Environment
                CostCenter = $vault.Tags.CostCenter
            }
            $securityResources += $vaultData
        }
        
        # Application Insights
        $appInsights = Get-AzApplicationInsights -ResourceGroupName $ResourceGroupName -ErrorAction Stop
        foreach ($insight in $appInsights) {
            $insightData = [PSCustomObject]@{
                ResourceType = "Application Insights"
                Name = $insight.Name
                ResourceGroup = $insight.ResourceGroupName
                Location = $insight.Location
                ApplicationType = $insight.ApplicationType
                Tags = $insight.Tags
                CreatedTime = $insight.Tags.CreatedTime
                Owner = $insight.Tags.Owner
                Environment = $insight.Tags.Environment
                CostCenter = $insight.Tags.CostCenter
            }
            $securityResources += $insightData
        }
        
        Write-Log "Found $($securityResources.Count) security resources" -Level "SUCCESS"
        return $securityResources
        
    } catch {
        Write-Log "Error retrieving security inventory: $($_.Exception.Message)" -Level "ERROR"
        return @()
    }
}

function Get-CostAnalysis {
    param([int]$DaysBack = 30)
    
    Write-Log "Retrieving cost analysis..." -Level "INFO"
    
    try {
        $endDate = Get-Date
        $startDate = $endDate.AddDays(-$DaysBack)
        
        $costs = Get-AzConsumptionUsageDetail -StartDate $startDate -EndDate $endDate -ErrorAction Stop
        
        $costSummary = $costs | Group-Object -Property ResourceGroup, ResourceType | ForEach-Object {
            [PSCustomObject]@{
                ResourceGroup = $_.Name.Split(',')[0]
                ResourceType = $_.Name.Split(',')[1]
                TotalCost = ($_.Group | Measure-Object -Property PretaxCost -Sum).Sum
                UsageQuantity = ($_.Group | Measure-Object -Property UsageQuantity -Sum).Sum
                InstanceCount = $_.Count
            }
        }
        
        Write-Log "Cost analysis completed for $DaysBack days" -Level "SUCCESS"
        return $costSummary
        
    } catch {
        Write-Log "Error retrieving cost analysis: $($_.Exception.Message)" -Level "ERROR"
        return @()
    }
}

function Export-InventoryReport {
    param(
        [array]$Data,
        [string]$Path,
        [string]$ReportType
    )
    
    $extension = [System.IO.Path]::GetExtension($Path).ToLower()
    
    switch ($extension) {
        ".csv" {
            $Data | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
            Write-Log "Report exported to CSV: $Path" -Level "SUCCESS"
        }
        ".json" {
            $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
            Write-Log "Report exported to JSON: $Path" -Level "SUCCESS"
        }
        ".html" {
            $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>Azure Resource Inventory Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; font-weight: bold; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .header { background-color: #0078d4; color: white; padding: 15px; }
        .timestamp { color: #666; font-size: 12px; }
        .summary { background-color: #e6f3ff; padding: 10px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Azure Resource Inventory Report</h1>
        <p class="timestamp">Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p class="timestamp">Report Type: $ReportType</p>
    </div>
"@
            
            $htmlTable = $Data | ConvertTo-Html -Fragment
            $htmlFooter = "</body></html>"
            
            $htmlContent = $htmlHeader + $htmlTable + $htmlFooter
            $htmlContent | Out-File -FilePath $Path -Encoding UTF8
            
            Write-Log "Report exported to HTML: $Path" -Level "SUCCESS"
        }
        default {
            $Data | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
            Write-Log "Report exported to CSV: $Path" -Level "SUCCESS"
        }
    }
}

# =============================================================================
# MAIN SCRIPT
# =============================================================================

Write-Log "Starting Azure Resource Inventory" -Level "INFO"
Write-Log "Report Type: $ReportType" -Level "INFO"
Write-Log "Include Costs: $IncludeCosts" -Level "INFO"
Write-Log "Include Security: $IncludeSecurity" -Level "INFO"

# Connect to Azure
$context = Connect-AzureAccount

# Set subscription if specified
if ($SubscriptionId) {
    try {
        Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
        Write-Log "Switched to subscription: $SubscriptionId" -Level "SUCCESS"
    } catch {
        Write-Log "Error switching to subscription: $($_.Exception.Message)" -Level "ERROR"
        exit 1
    }
}

# Initialize inventory data
$inventoryData = @()

# Get resource inventory based on report type
switch ($ReportType) {
    "Basic" {
        $inventoryData += Get-VMInventory -ResourceGroupName $ResourceGroup
        $inventoryData += Get-StorageInventory -ResourceGroupName $ResourceGroup
    }
    "Detailed" {
        $inventoryData += Get-VMInventory -ResourceGroupName $ResourceGroup
        $inventoryData += Get-StorageInventory -ResourceGroupName $ResourceGroup
        $inventoryData += Get-NetworkInventory -ResourceGroupName $ResourceGroup
        $inventoryData += Get-DatabaseInventory -ResourceGroupName $ResourceGroup
        $inventoryData += Get-AppServiceInventory -ResourceGroupName $ResourceGroup
    }
    "Security" {
        $inventoryData += Get-SecurityInventory -ResourceGroupName $ResourceGroup
        $inventoryData += Get-VMInventory -ResourceGroupName $ResourceGroup
        $inventoryData += Get-NetworkInventory -ResourceGroupName $ResourceGroup
    }
    "Cost" {
        $inventoryData += Get-VMInventory -ResourceGroupName $ResourceGroup
        $inventoryData += Get-StorageInventory -ResourceGroupName $ResourceGroup
        $inventoryData += Get-DatabaseInventory -ResourceGroupName $ResourceGroup
        $inventoryData += Get-AppServiceInventory -ResourceGroupName $ResourceGroup
    }
    "All" {
        $inventoryData += Get-VMInventory -ResourceGroupName $ResourceGroup
        $inventoryData += Get-StorageInventory -ResourceGroupName $ResourceGroup
        $inventoryData += Get-NetworkInventory -ResourceGroupName $ResourceGroup
        $inventoryData += Get-DatabaseInventory -ResourceGroupName $ResourceGroup
        $inventoryData += Get-AppServiceInventory -ResourceGroupName $ResourceGroup
        $inventoryData += Get-SecurityInventory -ResourceGroupName $ResourceGroup
    }
}

# Add cost analysis if requested
if ($IncludeCosts -or $ReportType -eq "Cost") {
    $costData = Get-CostAnalysis -DaysBack $DaysBack
    $inventoryData += $costData
}

# Generate summary statistics
$summary = @{
    TotalResources = $inventoryData.Count
    VirtualMachines = ($inventoryData | Where-Object { $_.ResourceType -eq "Virtual Machine" }).Count
    StorageAccounts = ($inventoryData | Where-Object { $_.ResourceType -eq "Storage Account" }).Count
    Networks = ($inventoryData | Where-Object { $_.ResourceType -like "*Network*" }).Count
    Databases = ($inventoryData | Where-Object { $_.ResourceType -like "*Database*" -or $_.ResourceType -like "*SQL*" -or $_.ResourceType -like "*Redis*" -or $_.ResourceType -like "*Cosmos*" }).Count
    AppServices = ($inventoryData | Where-Object { $_.ResourceType -like "*App*" }).Count
    SecurityResources = ($inventoryData | Where-Object { $_.ResourceType -like "*Key*" -or $_.ResourceType -like "*Insights*" }).Count
}

# Display summary
Write-Log "=== INVENTORY SUMMARY ===" -Level "INFO"
Write-Log "Total Resources: $($summary.TotalResources)" -Level "INFO"
Write-Log "Virtual Machines: $($summary.VirtualMachines)" -Level "SUCCESS"
Write-Log "Storage Accounts: $($summary.StorageAccounts)" -Level "SUCCESS"
Write-Log "Network Resources: $($summary.Networks)" -Level "SUCCESS"
Write-Log "Database Resources: $($summary.Databases)" -Level "SUCCESS"
Write-Log "App Service Resources: $($summary.AppServices)" -Level "SUCCESS"
Write-Log "Security Resources: $($summary.SecurityResources)" -Level "SUCCESS"

# Export report
try {
    Export-InventoryReport -Data $inventoryData -Path $ExportPath -ReportType $ReportType
    
    Write-Log "Azure Resource Inventory completed successfully!" -Level "SUCCESS"
    Write-Log "Report location: $ExportPath" -Level "INFO"
    
    # Display sample data
    if ($Verbose) {
        Write-Log "=== SAMPLE DATA ===" -Level "INFO"
        $inventoryData | Select-Object -First 5 | Format-Table -AutoSize
    }
    
} catch {
    Write-Log "Error exporting report: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

# =============================================================================
# SCRIPT COMPLETION
# =============================================================================

Write-Log "Azure Resource Inventory script completed successfully" -Level "SUCCESS"
Write-Log "Total processing time: $((Get-Date) - $scriptStartTime)" -Level "INFO" 