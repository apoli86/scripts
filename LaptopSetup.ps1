# powershell -executionpolicy bypass -File .\UserSetup.ps1

[cultureinfo]::CurrentUICulture = 'en-US'

# Step 1: Ensure Windows Firewall, Defender, and Updates are active

# Check and enable Windows Firewall
if ((Get-Service -Name 'MpsSvc').Status -ne 'Running') {
    Write-Host "Windows Firewall is not active. Enabling..."
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Write-Host "Windows Firewall activated."
} else {
    Write-Host "Windows Firewall is already active."
}

# Check and enable Windows Defender
if ((Get-Service -Name 'WinDefend').Status -ne 'Running') {
    Write-Host "Windows Defender is not active. Enabling..."
    Set-Service -Name 'WinDefend' -StartupType Automatic
    Start-Service -Name 'WinDefend'
    Write-Host "Windows Defender activated."
} else {
    Write-Host "Windows Defender is already active."
}

# Check and enable Windows Updates
if ((Get-Service -Name 'wuauserv').Status -ne 'Running') {
    Write-Host "Windows Updates are not active. Enabling..."
    Set-Service -Name 'wuauserv' -StartupType Automatic
    Start-Service -Name 'wuauserv'
    Write-Host "Windows Updates activated."
} else {
    Write-Host "Windows Updates are already active."
}

Write-Host "Removing Copilot package"
Get-AppxPackage Microsoft.Copilot | Remove-AppxPackage

Write-Host "Removing XBox packages"
Get-AppxPackage | Where {$_.Name -Match 'Xbox'} | Remove-AppxPackage

Write-Host "Removing Dropbox packages"
Get-AppxPackage | Where {$_.Name -Match 'Dropbox'} | Remove-AppxPackage

Write-Host "Removing MSTeams package"
Get-AppxPackage | Where {$_.Name -Match 'MSTeams'} | Remove-AppxPackage

Write-Host "Removing BingSearch package"
Get-AppxPackage | Where {$_.Name -Match 'Microsoft.BingSearch'} | Remove-AppxPackage

Write-Host "Removing Whiteboard package"
Get-AppxPackage | Where {$_.Name -Match 'Microsoft.Whiteboard'} | Remove-AppxPackage

Write-Host "Removing ZuneMusic package"
Get-AppxPackage | Where {$_.Name -Match 'Microsoft.ZuneMusic'} | Remove-AppxPackage

Write-Host "Removing YourPhone package"
Get-AppxPackage | Where {$_.Name -Match 'Microsoft.YourPhone'} | Remove-AppxPackage


