# security-group-management.ps1
# Comprehensive security group management and analysis script

param(
    [string]$GroupId = "",
    [string]$Action = "list", # list, create, update, analyze, audit, cleanup
    [string]$Region = "",
    [string]$Profile = "default",
    [string]$GroupName = "",
    [string]$Description = "",
    [string]$VpcId = "",
    [string]$RuleFile = "",
    [switch]$DryRun,
    [switch]$Force
)

function Get-SecurityGroups {
    param([string]$GroupId, [string]$Region)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    try {
        if ($GroupId) {
            $groups = aws ec2 describe-security-groups --group-ids $GroupId $regionParam --profile $Profile --output json | ConvertFrom-Json
            return $groups.SecurityGroups
        } else {
            $groups = aws ec2 describe-security-groups $regionParam --profile $Profile --output json | ConvertFrom-Json
            return $groups.SecurityGroups
        }
    }
    catch {
        Write-Host "Unable to get security groups" -ForegroundColor Red
        return @()
    }
}

function New-SecurityGroup {
    param([string]$GroupName, [string]$Description, [string]$VpcId, [string]$Region)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    Write-Host "Creating security group: $GroupName" -ForegroundColor Yellow
    
    try {
        if (-not $DryRun) {
            $result = aws ec2 create-security-group --group-name $GroupName --description $Description --vpc-id $VpcId $regionParam --profile $Profile --output json | ConvertFrom-Json
            
            Write-Host "Security group created: $($result.GroupId)" -ForegroundColor Green
            return $result.GroupId
        } else {
            Write-Host "[DRY RUN] Would create security group: $GroupName" -ForegroundColor Cyan
            return "dry-run-group-id"
        }
    }
    catch {
        Write-Host "Failed to create security group: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Add-SecurityGroupRule {
    param([string]$GroupId, [string]$Protocol, [int]$Port, [string]$Source, [string]$RuleType, [string]$Region)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    Write-Host "Adding $RuleType rule: $Protocol`:$Port from $Source" -ForegroundColor Yellow
    
    try {
        $ruleParams = @(
            "--group-id $GroupId",
            "--protocol $Protocol",
            "--port $Port",
            "--source $Source"
        )
        
        if ($RuleType -eq "ingress") {
            $cmd = "aws ec2 authorize-security-group-ingress $($ruleParams -join ' ') $regionParam --profile $Profile"
        } else {
            $cmd = "aws ec2 authorize-security-group-egress $($ruleParams -join ' ') $regionParam --profile $Profile"
        }
        
        if (-not $DryRun) {
            Invoke-Expression $cmd
            Write-Host "Rule added successfully" -ForegroundColor Green
        } else {
            Write-Host "[DRY RUN] Would add rule: $cmd" -ForegroundColor Cyan
        }
        
        return $true
    }
    catch {
        Write-Host "Failed to add rule: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Remove-SecurityGroupRule {
    param([string]$GroupId, [string]$Protocol, [int]$Port, [string]$Source, [string]$RuleType, [string]$Region)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    Write-Host "Removing $RuleType rule: $Protocol`:$Port from $Source" -ForegroundColor Yellow
    
    try {
        $ruleParams = @(
            "--group-id $GroupId",
            "--protocol $Protocol",
            "--port $Port",
            "--source $Source"
        )
        
        if ($RuleType -eq "ingress") {
            $cmd = "aws ec2 revoke-security-group-ingress $($ruleParams -join ' ') $regionParam --profile $Profile"
        } else {
            $cmd = "aws ec2 revoke-security-group-egress $($ruleParams -join ' ') $regionParam --profile $Profile"
        }
        
        if (-not $DryRun) {
            Invoke-Expression $cmd
            Write-Host "Rule removed successfully" -ForegroundColor Green
        } else {
            Write-Host "[DRY RUN] Would remove rule: $cmd" -ForegroundColor Cyan
        }
        
        return $true
    }
    catch {
        Write-Host "Failed to remove rule: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Analyze-SecurityGroup {
    param([string]$GroupId, [string]$Region)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    Write-Host "Analyzing security group: $GroupId" -ForegroundColor Yellow
    
    try {
        $group = aws ec2 describe-security-groups --group-ids $GroupId $regionParam --profile $Profile --output json | ConvertFrom-Json
        $sg = $group.SecurityGroups.Item(0)
        
        $analysis = @{
            GroupId = $sg.GroupId
            GroupName = $sg.GroupName
            VpcId = $sg.VpcId
            InboundRules = $sg.IpPermissions
            OutboundRules = $sg.IpPermissionsEgress
            RiskLevel = "Low"
            Issues = @()
            Recommendations = @()
        }
        
        # Analyze inbound rules
        $openPorts = @()
        $publicAccess = @()
        
        foreach ($rule in $sg.IpPermissions) {
            if ($rule.IpRanges) {
                foreach ($ipRange in $rule.IpRanges) {
                    if ($ipRange.CidrIp -eq "0.0.0.0/0") {
                        $publicAccess += "$($rule.FromPort)-$($rule.ToPort)"
                        $analysis.RiskLevel = "High"
                        $analysis.Issues += "Public access on port $($rule.FromPort)-$($rule.ToPort)"
                    }
                }
            }
            
            if ($rule.FromPort -and $rule.ToPort) {
                $openPorts += "$($rule.FromPort)-$($rule.ToPort)"
            }
        }
        
        # Check for common security issues
        $commonPorts = @(22, 23, 3389, 1433, 3306, 5432, 6379, 27017)
        foreach ($port in $commonPorts) {
            if ($openPorts -contains $port) {
                $analysis.Issues += "Common service port $port is open"
            }
        }
        
        # Generate recommendations
        if ($publicAccess.Count -gt 0) {
            $analysis.Recommendations += "Restrict public access to specific IP ranges"
        }
        
        if ($openPorts.Count -gt 10) {
            $analysis.Recommendations += "Consider reducing the number of open ports"
        }
        
        if (-not ($sg.IpPermissionsEgress | Where-Object { $_.IpRanges.CidrIp -eq "0.0.0.0/0" })) {
            $analysis.Recommendations += "Consider restricting outbound traffic"
        }
        
        return $analysis
    }
    catch {
        Write-Host "Unable to analyze security group" -ForegroundColor Red
        return $null
    }
}

function Audit-SecurityGroupCompliance {
    param([string]$GroupId, [string]$Region)
    
    $analysis = Analyze-SecurityGroup -GroupId $GroupId -Region $Region
    if (-not $analysis) { return }
    
    $compliance = @{
        Compliant = $true
        Score = 100
        Issues = @()
        Standards = @{
            CIS = $true
            NIST = $true
            PCI = $true
        }
    }
    
    # CIS Compliance
    if ($analysis.Issues | Where-Object { $_ -like "*Public access*" }) {
        $compliance.Standards.CIS = $false
        $compliance.Score -= 30
        $compliance.Issues += "CIS: Public access not allowed"
    }
    
    # NIST Compliance
    if ($analysis.Issues | Where-Object { $_ -like "*Common service port*" }) {
        $compliance.Standards.NIST = $false
        $compliance.Score -= 20
        $compliance.Issues += "NIST: Unnecessary ports open"
    }
    
    # PCI Compliance
    if ($analysis.RiskLevel -eq "High") {
        $compliance.Standards.PCI = $false
        $compliance.Score -= 25
        $compliance.Issues += "PCI: High-risk configuration"
    }
    
    if ($compliance.Score -lt 70) {
        $compliance.Compliant = $false
    }
    
    return $compliance
}

function Bulk-UpdateSecurityGroup {
    param([string]$GroupId, [string]$RuleFile, [string]$Region)
    
    if (-not (Test-Path $RuleFile)) {
        Write-Host "Rule file not found: $RuleFile" -ForegroundColor Red
        return
    }
    
    try {
        $ruleData = Get-Content $RuleFile | ConvertFrom-Json
        
        Write-Host "Processing bulk rule updates..." -ForegroundColor Yellow
        
        foreach ($operation in $ruleData) {
            if ($operation.Action -eq "add") {
                Add-SecurityGroupRule -GroupId $GroupId -Protocol $operation.Protocol -Port $operation.Port -Source $operation.Source -RuleType $operation.RuleType -Region $Region
            } elseif ($operation.Action -eq "remove") {
                Remove-SecurityGroupRule -GroupId $GroupId -Protocol $operation.Protocol -Port $operation.Port -Source $operation.Source -RuleType $operation.RuleType -Region $Region
            }
        }
        
        Write-Host "Bulk update completed" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to process bulk updates: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Cleanup-UnusedSecurityGroups {
    param([string]$Region)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    Write-Host "Finding unused security groups..." -ForegroundColor Yellow
    
    try {
        $groups = Get-SecurityGroups -Region $Region
        $unusedGroups = @()
        
        foreach ($group in $groups) {
            # Check if group is attached to any instances
            $instances = aws ec2 describe-instances --filters "Name=instance.group-id,Values=$($group.GroupId)" $regionParam --profile $Profile --output json | ConvertFrom-Json
            
            if ($instances.Reservations.Count -eq 0) {
                $unusedGroups += $group
            }
        }
        
        if ($unusedGroups.Count -gt 0) {
            Write-Host "`nUnused security groups found:" -ForegroundColor Yellow
            foreach ($group in $unusedGroups) {
                Write-Host "  $($group.GroupName) ($($group.GroupId))" -ForegroundColor Gray
                Write-Host "    Description: $($group.Description)" -ForegroundColor Gray
                
                if (-not $DryRun) {
                    if ($Force -or (Read-Host "Delete this group? (y/N)") -eq "y") {
                        aws ec2 delete-security-group --group-id $group.GroupId $regionParam --profile $Profile
                        Write-Host "    Deleted" -ForegroundColor Green
                    }
                } else {
                    Write-Host "    [DRY RUN] Would delete" -ForegroundColor Cyan
                }
            }
        } else {
            Write-Host "No unused security groups found" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Unable to cleanup unused security groups" -ForegroundColor Red
    }
}

Write-Host "AWS Security Group Management" -ForegroundColor Green
Write-Host "=============================" -ForegroundColor Green

switch ($Action.ToLower()) {
    "list" {
        $groups = Get-SecurityGroups -GroupId $GroupId -Region $Region
        
        if ($groups.Count -eq 0) {
            Write-Host "No security groups found." -ForegroundColor Yellow
            return
        }
        
        Write-Host "`nSecurity Groups:" -ForegroundColor Yellow
        Write-Host ("=" * 100) -ForegroundColor DarkGray
        
        foreach ($group in $groups) {
            Write-Host "Group: " -NoNewline -ForegroundColor White
            Write-Host "$($group.GroupName) ($($group.GroupId))" -ForegroundColor Cyan
            Write-Host "VPC: " -NoNewline -ForegroundColor White
            Write-Host $group.VpcId -ForegroundColor Gray
            Write-Host "Description: " -NoNewline -ForegroundColor White
            Write-Host $group.Description -ForegroundColor Gray
            
            Write-Host "Inbound Rules: " -NoNewline -ForegroundColor White
            Write-Host $group.IpPermissions.Count -ForegroundColor $(if($group.IpPermissions.Count -eq 0) { "Green" } else { "Yellow" })
            
            Write-Host "Outbound Rules: " -NoNewline -ForegroundColor White
            Write-Host $group.IpPermissionsEgress.Count -ForegroundColor $(if($group.IpPermissionsEgress.Count -eq 0) { "Green" } else { "Yellow" })
            
            Write-Host ""
        }
        
        Write-Host "Total groups: $($groups.Count)" -ForegroundColor Green
    }
    
    "create" {
        if (-not $GroupName -or -not $Description -or -not $VpcId) {
            Write-Host "Please specify GroupName, Description, and VpcId" -ForegroundColor Red
            return
        }
        
        New-SecurityGroup -GroupName $GroupName -Description $Description -VpcId $VpcId -Region $Region
    }
    
    "update" {
        if (-not $GroupId -or -not $RuleFile) {
            Write-Host "Please specify GroupId and RuleFile" -ForegroundColor Red
            return
        }
        
        Bulk-UpdateSecurityGroup -GroupId $GroupId -RuleFile $RuleFile -Region $Region
    }
    
    "analyze" {
        if (-not $GroupId) {
            Write-Host "Please specify a GroupId to analyze" -ForegroundColor Red
            return
        }
        
        $analysis = Analyze-SecurityGroup -GroupId $GroupId -Region $Region
        
        if ($analysis) {
            Write-Host "`nSecurity Analysis:" -ForegroundColor Cyan
            Write-Host "Risk Level: $($analysis.RiskLevel)" -ForegroundColor $(if($analysis.RiskLevel -eq "Low") { "Green" } else { "Red" })
            Write-Host "Inbound Rules: $($analysis.InboundRules.Count)" -ForegroundColor Gray
            Write-Host "Outbound Rules: $($analysis.OutboundRules.Count)" -ForegroundColor Gray
            
            if ($analysis.Issues.Count -gt 0) {
                Write-Host "`nIssues:" -ForegroundColor Red
                foreach ($issue in $analysis.Issues) {
                    Write-Host "  - $issue" -ForegroundColor Red
                }
            }
            
            if ($analysis.Recommendations.Count -gt 0) {
                Write-Host "`nRecommendations:" -ForegroundColor Yellow
                foreach ($rec in $analysis.Recommendations) {
                    Write-Host "  - $rec" -ForegroundColor Yellow
                }
            }
        }
    }
    
    "audit" {
        if (-not $GroupId) {
            Write-Host "Please specify a GroupId to audit" -ForegroundColor Red
            return
        }
        
        $compliance = Audit-SecurityGroupCompliance -GroupId $GroupId -Region $Region
        
        if ($compliance) {
            Write-Host "`nCompliance Audit:" -ForegroundColor Cyan
            Write-Host "Compliant: $($compliance.Compliant)" -ForegroundColor $(if($compliance.Compliant) { "Green" } else { "Red" })
            Write-Host "Score: $($compliance.Score)/100" -ForegroundColor $(if($compliance.Score -ge 70) { "Green" } else { "Red" })
            
            Write-Host "`nStandards:" -ForegroundColor Yellow
            Write-Host "CIS: $($compliance.Standards.CIS)" -ForegroundColor $(if($compliance.Standards.CIS) { "Green" } else { "Red" })
            Write-Host "NIST: $($compliance.Standards.NIST)" -ForegroundColor $(if($compliance.Standards.NIST) { "Green" } else { "Red" })
            Write-Host "PCI: $($compliance.Standards.PCI)" -ForegroundColor $(if($compliance.Standards.PCI) { "Green" } else { "Red" })
            
            if ($compliance.Issues.Count -gt 0) {
                Write-Host "`nCompliance Issues:" -ForegroundColor Red
                foreach ($issue in $compliance.Issues) {
                    Write-Host "  - $issue" -ForegroundColor Red
                }
            }
        }
    }
    
    "cleanup" {
        Cleanup-UnusedSecurityGroups -Region $Region
    }
    
    default {
        Write-Host "Invalid action. Valid actions: list, create, update, analyze, audit, cleanup" -ForegroundColor Red
    }
}

Write-Host "`nUsage Examples:" -ForegroundColor Magenta
Write-Host "  .\security-group-management.ps1 -Action list"
Write-Host "  .\security-group-management.ps1 -Action create -GroupName 'web-sg' -Description 'Web server security group' -VpcId 'vpc-12345678'"
Write-Host "  .\security-group-management.ps1 -Action update -GroupId 'sg-12345678' -RuleFile 'rules.json'"
Write-Host "  .\security-group-management.ps1 -Action analyze -GroupId 'sg-12345678'"
Write-Host "  .\security-group-management.ps1 -Action audit -GroupId 'sg-12345678'"
Write-Host "  .\security-group-management.ps1 -Action cleanup -Force" 