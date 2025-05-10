# Generate a random password (10 characters: letters, numbers, special characters @!#)
function Generate-HumanPassword {
    param (
        [int]$Length = 12
    )

    $words = @('apple', 'banana', 'cherry', 'delta', 'echo', 'foxtrot', 'grape', 'hotel', 'india', 'juliet', 'kiwi', 'lemon')
    $symbols = '!@#$%&*'
    $password = ''

    for ($i = 0; $i -lt $Length / 4; $i++) {
        $password += $words[(Get-Random -Minimum 0 -Maximum $words.Length)]
        $password += (Get-Random -Minimum 0 -Maximum 9)
        $password += $symbols[(Get-Random -Minimum 0 -Maximum $symbols.Length)]
    }

    return $password.Substring(0, $Length)
}

# Example: Generate and print a password
$password  = Generate-HumanPassword -Length 12

# Define the target username
$username = 'OPSUser'

# Create the new non-admin user with the generated password

$exists = Get-LocalUser | Where-Object {$_.Name -eq $username}
if ( $exists ) {
	Remove-LocalUser -Name $username
	Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.LocalPath -like "*OPSUser*" } | Remove-CimInstance
}
New-LocalUser -Name $username -Password (ConvertTo-SecureString -String $password -AsPlainText -Force) -AccountNeverExpires -Description "Restricted Edge User"
Add-LocalGroupMember -Group 'Users' -Member $username

# Output the created username and password
Write-Host "User created: $username"
Write-Host "Password: $password"
Write-Host "Creating profile"
echo $password | clip
Write-Host "Execute the following command to initialize the user profile"
Write-Host "runas.exe /profile /user:$username cmd"
runas.exe /profile /user:$username cmd