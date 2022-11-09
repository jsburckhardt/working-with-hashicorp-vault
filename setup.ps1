# setup config
$vaultpath = "C:\vault2"
$ipadress = "127.0.0.1"
$apiaddress      = "http://" + $ipadress + ":8200"
$ConfigHcl    = "$vaultpath\config.hcl"
$StoragePath  = "$vaultpath\data"
$logpath      = "$vaultpath\log"
$configpath   = "$vaultpath\config"
$TaskName = "vaulttask"
$Exportfile = "$VaultPath\config\UnsealKeys.xml"
$AESKeyFile = "$VaultPath\config\AESkey.txt"
$secret_shares    = 5
$secret_threshold = 3
$AESKeySize = 32

Function Convertto-SecureHashAES             {
  [CmdletBinding()]
  Param(
      # Param1 help description
      [Parameter(Mandatory=$true)]
      [string[]]$token ,
      [Parameter(Mandatory=$true)]
      [string[]]$tokenName ,

      # Param3 help description
      [Parameter(Mandatory=$false)]
      $AESKey
  )
  process{
      New-object -TypeName PSObject -Property @{
          AESKey = $AESkey
          Hash   = ConvertFrom-SecureString -SecureString (Convert-PLainpasswordtoSecurestring -token $token) -Key $AESKey
          Name   = $tokenName
      }
  }
  end{
      return $result
  }
}


# validate vault is in the path
if (!(Get-Command vault -ErrorAction SilentlyContinue)) {
    Write-Host "Vault is not in the path, please install vault and add it to the path"
    exit
}

# install -vault
# Install-Vault -VaultPath $vaultpath 
if(!(test-path $vaultPath))              { $create = New-Item -ItemType Directory -path $vaultPath               ; if($Create -like $false){Break}  } 
if(!(test-path $storagePath))            { $create = New-Item -ItemType Directory -path $storagePath             ; if($Create -like $false){Break}  }
if(!(test-path $vaultPath\log))          { $create = New-Item -ItemType Directory -path $vaultPath\log           ; if($Create -like $false){Break}  }
if(!(test-path $vaultPath\config))       { $create = New-Item -ItemType Directory -path $vaultPath\config        ; if($Create -like $false){Break}  }
if(!(test-path $vaultPath\config\policy)){ $create = New-Item -ItemType Directory -path $vaultPath\config\policy ; if($Create -like $false){Break}  }
if ( !(test-path  $vaultPath\vault.exe )) { Write-Host "Vault is not in the path, please install vault and add it to the vaultpath" ; exit }

# create config.hcl
$ConfigHclContent = @"
storage "file" {
  path = "$(($storagePath).replace("\","/"))"
}

listener "tcp" {
    address     = "0.0.0.0:8200"
    tls_disable = 1
}

api_addr      = "$apiaddress"
ui            = true
disable_mlock = true

"@
$ConfigHclContent | Out-File -FilePath $ConfigHcl -Encoding ASCII

# start-vault ($StartVault = start-vault -vaultpath $vaultpath -APIaddress "http://127.0.0.1:8200")
$action  = New-ScheduledTaskAction -Execute "$vaultpath\vault.exe" -Argument "server -config=`"$vaultpath\config.hcl`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$createTask = Register-ScheduledTask -Action $action `
        -Trigger $trigger `
        -TaskName $taskname `
        -Description "Run Hashicorp Vault" `
        -User system `
        -ErrorAction stop
                            # restart machine

# start-vaultinit and export file (start-VaultInit -APIAddress http://127.0.0.1:8200 -VaultPath c:\vault)
$uri  = $apiaddress + "/v1/sys/init"
$data = "{`"secret_shares`": $secret_shares, `"secret_threshold`": $secret_threshold}"
$initialize = Invoke-RestMethod -uri $uri -Method post -body $data

$VaultINITKeys = new-object -TypeName psobject -Property @{
  UnsealKey1         = $($initialize.keys)[0]
  UnsealKey2         = $($initialize.keys)[1]
  UnsealKey3         = $($initialize.keys)[2]
  UnsealKey4         = $($initialize.keys)[3]
  UnsealKey5         = $($initialize.keys)[4]
  UnsealKey_base64_1 = $($initialize.keys_base64)[0]
  UnsealKey_base64_2 = $($initialize.keys_base64)[1]
  UnsealKey_base64_3 = $($initialize.keys_base64)[2]
  UnsealKey_base64_4 = $($initialize.keys_base64)[3]
  UnsealKey_base64_5 = $($initialize.keys_base64)[4]
  InitialRootToken   = $($initialize.root_token)
} | select-object UnsealKey1,UnsealKey2,UnsealKey3,UnsealKey4,UnsealKey5,InitialRootToken,UnsealKey_base64_1,UnsealKey_base64_2,UnsealKey_base64_3,UnsealKey_base64_4,UnsealKey_base64_5

$AESKey = (New-Object Byte[] $AESKeySize)
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($AESKey)
$EncryptedKeys = new-object -TypeName psobject -Property @{
UnsealKey1         = (Convertto-SecureHashAES -token "$($VaultINITKeys.UnsealKey1)" -tokenName "UnsealKey1" -AESKey $AESKey).hash
UnsealKey2         = (Convertto-SecureHashAES -token "$($VaultINITKeys.UnsealKey2)" -tokenName "UnsealKey2" -AESKey $AESKey).hash
UnsealKey3         = (Convertto-SecureHashAES -token "$($VaultINITKeys.UnsealKey3)" -tokenName "UnsealKey3" -AESKey $AESKey).hash
UnsealKey4         = (Convertto-SecureHashAES -token "$($VaultINITKeys.UnsealKey4)" -tokenName "UnsealKey4" -AESKey $AESKey).hash
UnsealKey5         = (Convertto-SecureHashAES -token "$($VaultINITKeys.UnsealKey5)" -tokenName "UnsealKey5" -AESKey $AESKey).hash
UnsealKey_base64_1 = (Convertto-SecureHashAES -token "$($VaultINITKeys.UnsealKey_base64_1)" -tokenName "UnsealKey1" -AESKey $AESKey).hash
UnsealKey_base64_2 = (Convertto-SecureHashAES -token "$($VaultINITKeys.UnsealKey_base64_2)" -tokenName "UnsealKey1" -AESKey $AESKey).hash
UnsealKey_base64_3 = (Convertto-SecureHashAES -token "$($VaultINITKeys.UnsealKey_base64_3)" -tokenName "UnsealKey1" -AESKey $AESKey).hash
UnsealKey_base64_4 = (Convertto-SecureHashAES -token "$($VaultINITKeys.UnsealKey_base64_4)" -tokenName "UnsealKey1" -AESKey $AESKey).hash
UnsealKey_base64_5 = (Convertto-SecureHashAES -token "$($VaultINITKeys.UnsealKey_base64_5)" -tokenName "UnsealKey1" -AESKey $AESKey).hash
InitialRootToken   = (Convertto-SecureHashAES -token "$($VaultINITKeys.InitialRootToken)" -tokenName "InitialRootToken" -AESKey $AESKey).hash
} | select-object UnsealKey1,UnsealKey2,UnsealKey3,UnsealKey4,UnsealKey5,InitialRootToken,UnsealKey_base64_1,UnsealKey_base64_2,UnsealKey_base64_3,UnsealKey_base64_4,UnsealKey_base64_5

write-host "`$EncryptedKeys | Export-Clixml -Path $exportfile"
$EncryptedKeys | Export-Clixml -Path $exportfile

$AESKey | out-file -FilePath $AESKeyFile




write-host "===============================================================" -ForegroundColor Magenta
write-host " HASHICORP VAULT  - Unseal Keys and Roottokens "                 -ForegroundColor Magenta
write-host "===============================================================" -ForegroundColor Magenta
write-warning "Keys are generated ONCE!!"
write-warning " --> If you close the screen the keys are gone!!!! "
write-host "==============================================================="
write-host " UnsealKey1        : $($VaultINITKeys.UnsealKey1)"
write-host " UnsealKey2        : $($VaultINITKeys.UnsealKey2)"
write-host " UnsealKey3        : $($VaultINITKeys.UnsealKey3)"
write-host " UnsealKey4        : $($VaultINITKeys.UnsealKey4)"
write-host " UnsealKey5        : $($VaultINITKeys.UnsealKey5)"
write-host " UnsealKey1 base64 : $($VaultINITKeys.UnsealKey_base64_1)"
write-host " UnsealKey2 base64 : $($VaultINITKeys.UnsealKey_base64_2)"
write-host " UnsealKey3 base64 : $($VaultINITKeys.UnsealKey_base64_3)"
write-host " UnsealKey4 base64 : $($VaultINITKeys.UnsealKey_base64_4)"
write-host " UnsealKey5 base64 : $($VaultINITKeys.UnsealKey_base64_5)"
write-host " InitialRootToken  : $($VaultINITKeys.InitialRootToken)"
write-host ""
write-host "Vault initialized with 5 key shares and a key threshold of 3. "
write-host "Please securely distribute the key shares printed above. When the Vault is re-sealed,"
write-host "restarted, or stopped, you must supply at least 3 of these keys to unseal it"
write-host "before it can start servicing requests."
write-host ""
write-host "Vault does not store the generated master key. Without at least 3 key to"
write-host "reconstruct the master key, Vault will remain permanently sealed!"
write-host ""
write-host "It is possible to generate new unseal keys, provided you have a quorum of"
write-host "existing unseal keys shares. See `"vault operator rekey`" for more information."
write-host "===============================================================" -ForegroundColor Magenta

# validate vault status
# unseal the vault
# login
# create approle auth
