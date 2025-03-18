$PrintServer = "ENTER_PRINTSERVER_FQDN"

$PrinterGroups = @{
   "Printer_Example" = @("Printer_Name_onPrintServer")
        # Add your printers here
    )
}

function MD-InstallPrinters {
    param (
        [string]$Location
    )
    
    if ($PrinterGroups.ContainsKey($Location)) {
        $Printers = $PrinterGroups[$Location]
        $InstallationResults = @()
        
        foreach ($Printer in $Printers) {
            $PrinterConnection = "\\$PrintServer\$Printer"
            try {
                Add-Printer -ConnectionName $PrinterConnection
                Write-Host "Successfully installed printer: $Printer" -ForegroundColor Green
                $InstallationResults += [PSCustomObject]@{Printer=$Printer;Status="Installed"}
            } catch {
                Write-Host "Failed to install printer: $Printer" -ForegroundColor Red
                $InstallationResults += [PSCustomObject]@{Printer=$Printer;Status="Failed"}
            }
        }
        
        Write-Host "`nSummary for $Location:" -ForegroundColor Cyan
        foreach ($Result in $InstallationResults) {
            Write-Host "Printer: $($Result.Printer), Status: $($Result.Status)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Location $Location not found." -ForegroundColor Red
    }
}

function Get-PrinterLocations {
    Write-Host "Available Locations:" -ForegroundColor Cyan
    foreach ($location in $PrinterGroups.Keys) {
        Write-Host $location -ForegroundColor Yellow
    }
}

# Export the functions
Export-ModuleMember -Function MD-InstallPrinters, Get-PrinterLocations
