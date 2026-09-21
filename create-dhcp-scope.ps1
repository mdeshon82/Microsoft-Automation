Import-Module DhcpServer

$ErrorActionPreference = "Stop"

$DnsServers = @(
    "@@DNS_SERVERS@@",
    "@@DNS_SERVERS@@"
)

$LeaseDuration = New-TimeSpan -Days 1
$DnsDomain = "@@DOMNAIN_NAME@@"

$Scopes = @(

    # @@NAME@@
    [PSCustomObject]@{
        Name       = "@@NAME@@"
        ScopeId    = "10.0.0.0"
        StartRange = "10.0.0.50"
        EndRange   = "10.0.0.250"
        Gateway    = "10.0.0.1"
    }

    
    
)


foreach ($Scope in $Scopes) {

    Write-Host ""
    Write-Host "Processing $($Scope.Name)" -ForegroundColor Cyan

    $ExistingScope = Get-DhcpServerv4Scope `
        -ScopeId $Scope.ScopeId `
        -ErrorAction SilentlyContinue

    if (-not $ExistingScope) {

        Add-DhcpServerv4Scope `
            -Name $Scope.Name `
            -Description $Scope.Name `
            -StartRange $Scope.StartRange `
            -EndRange $Scope.EndRange `
            -SubnetMask "255.255.255.0" `
            -LeaseDuration $LeaseDuration `
            -State Active

        Write-Host "Created scope $($Scope.ScopeId)" -ForegroundColor Green
    }
    else {
        Write-Host "Scope $($Scope.ScopeId) already exists. Skipping scope creation." -ForegroundColor Yellow
    }

    Set-DhcpServerv4OptionValue `
        -ScopeId $Scope.ScopeId `
        -Router $Scope.Gateway `
        -DnsServer $DnsServers `
        -DnsDomain $DnsDomain

    Write-Host "Gateway: $($Scope.Gateway)" -ForegroundColor Gray
    Write-Host "DNS: @@DNS_SERVERS@@" -ForegroundColor Gray
    Write-Host "DNS Domain: @@DOMAIN_NAME@@" -ForegroundColor Gray
}

Write-Host ""
Write-Host "DHCP scope creation complete." -ForegroundColor Green

Get-DhcpServerv4Scope |
    Sort-Object ScopeId |
    Format-Table ScopeId, Name, StartRange, EndRange, SubnetMask, State -AutoSize