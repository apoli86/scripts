# powershell -executionpolicy bypass -File .\UserSetup.ps1

[cultureinfo]::CurrentUICulture = 'en-US'

$allowedDomain = 'corriere.it'
$username = 'OPSUser'

New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS

$userSID = Get-WmiObject win32_useraccount | Where {$_.name -Match $username } | Select sid -ExpandProperty sid

$registryPath = "HKU:\$userSID\SOFTWARE\Policies\Microsoft\Edge"

# Create the registry key if it doesn't exist
if (!(Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force
}

# Enable URL restriction mode
New-ItemProperty -Path $registryPath -Name 'URLAllowlist' -PropertyType MultiString -Value @("https://$allowedDomain/*") -Force

# Block all other domains
New-ItemProperty -Path $registryPath -Name 'URLBlocklist' -PropertyType MultiString -Value @("*") -Force

# Disable settings changes in Edge for the new user
New-ItemProperty -Path $registryPath -Name 'BrowserSettingsPolicy' -PropertyType DWord -Value 1 -Force

# Disable Microsoft Store apps for the new user
$storePolicyPath = "HKU:\$userSID\SOFTWARE\Policies\Microsoft\WindowsStore"
if (!(Test-Path $storePolicyPath)) {
    New-Item -Path $storePolicyPath -Force
}
New-ItemProperty -Path $storePolicyPath -Name 'AllowStoreApps' -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path $storePolicyPath -Name 'RemoveWindowsStore' -PropertyType DWord -Value 1 -Force

# Disable Copilot app for the new user
$copilotPolicyPath = "HKU:\$userSID\SOFTWARE\Policies\Microsoft\Windows\Copilot"
if (!(Test-Path $copilotPolicyPath)) {
    New-Item -Path $copilotPolicyPath -Force
}
New-ItemProperty -Path $copilotPolicyPath -Name 'CopilotEnabled' -PropertyType DWord -Value 0 -Force

# Disable Copilot app for the new user
$outlookPolicyPath = "HKU:\$userSID\SOFTWARE\Policies\Microsoft\Office\Outlook"
if (!(Test-Path $outlookPolicyPath)) {
    New-Item -Path $outlookPolicyPath -Force
}
New-ItemProperty -Path $outlookPolicyPath -Name 'DisableOutlook' -PropertyType DWord -Value 1 -Force

Write-Host "Access restricted to the domain: $allowedDomain for user $username, settings changes disabled, and Microsoft Store apps disabled, Copilot disabled, Outlook disabled for the user"
