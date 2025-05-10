# powershell -executionpolicy bypass -File .\02-UserCreation.ps1
# Generate a random password (10 characters: letters, numbers, special characters @!#)
function Generate-HumanPassword {
    param(
        [int]$NumberLength = 2,
        [int]$SymbolCount = 1
    )

    # Word lists
    $adjectives = @("quick", "lazy", "fuzzy", "bright", "silent", "brave", "tiny", "happy", "clever", "odd")
    $nouns = @("fox", "dog", "rocket", "moon", "river", "cloud", "lion", "piano", "wizard", "tiger")
    $symbols = @("!", "@", "#", "$", "%", "&", "*", "?")

    # Random selections
    $adj = Get-Random -InputObject $adjectives
    $noun = Get-Random -InputObject $nouns
    $number = -join ((0..9) | Get-Random -Count $NumberLength)
    $symbol = -join (1..$SymbolCount | ForEach-Object { Get-Random -InputObject $symbols })

    # Compose password
    return "$adj-$noun-$number$symbol"
}

# Example: Generate and print a password
$password  = Generate-HumanPassword -NumberLength 2 -SymbolCount 1

# Define the target username
$username = 'OPSUser'

# Create the new non-admin user with the generated password

$exists = Get-LocalUser | Where-Object {$_.Name -eq $username}
if ( $exists ) {
	Remove-LocalUser -Name $username
	Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.LocalPath -like "*OPSUser*" } | Remove-CimInstance
}
New-LocalUser -Name $username -Password (ConvertTo-SecureString -String $password -AsPlainText -Force) -AccountNeverExpires -Description "Restricted OPSUser"
Add-LocalGroupMember -Group 'Users' -Member $username

# Output the created username and password
Write-Host "User created: $username"
Write-Host "Password: $password"
Write-Host "Creating profile"
echo $password | clip
Write-Host "Execute the following command to initialize the user profile"
Write-Host "runas.exe /profile /user:$username cmd"
runas.exe /profile /user:$username cmd