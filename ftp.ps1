# Importar funciones de utils
. .\utils.ps1

function installFtp {
    PrintMessage "info" "Instalando servidor FTP..."
    
    dism /online /enable-feature /featurename:IIS-FTPServer /all > $null 
    dism /online /enable-feature /featurename:IIS-ManagementConsole /all > $null 
    net start ftpsvc > $null 

    enableFirewallRules > $null

    if (Validate-FTP-Site -siteName $global:siteName -ftpPath $global:iftpPath) {
        PrintMessage "info" "Creando sitio ftp..."
        New-WebFtpSite -Name $global:siteName -Port 21 > $null 
        PrintMessage "success" "Servidor FTP instalado y servicio iniciado."
        enableFirewallRules > $null
        return $true
    } else {
        PrintMessage "error" "El sitio FTP ya existe."
        return $false;
    }
}

function setupFtp {
    mkdir "$global:iftpPath\general" > $null 
    mkdir "$global:iftpPath\LocalUser" > $null 
    mkdir "$global:iftpPath\LocalUser\Public" > $null 

    cmd /c mklink /j "$global:iftpPath\LocalUser\Public\general" "$global:iftpPath\general" > $null 

    $path = "$global:iftpPath\general"

    # Otorgar permisos de lectura y escritura a Everyone
    $acl = Get-Acl $path
    $permission = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.SetAccessRule($permission)
    Set-Acl -Path $path -AclObject $acl

    # También agregar permisos para el usuario anónimo de IIS (si aplica)
    $anonUser = "IUSR"
    $permissionAnon = New-Object System.Security.AccessControl.FileSystemAccessRule($anonUser, "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($permissionAnon)
    Set-Acl -Path $path -AclObject $acl

    Set-ItemProperty "IIS:\Sites\$global:siteName" -Name physicalPath -Value $global:iftpPath > $null 

    # Configurar SSL (permitir pero no requerir)
    Import-Module WebAdministration > $null 
    Set-ItemProperty "IIS:\Sites\$global:siteName" -Name ftpServer.security.ssl.controlChannelPolicy -Value "SslAllow" > $null 
    Set-ItemProperty "IIS:\Sites\$global:siteName" -Name ftpServer.security.ssl.dataChannelPolicy -Value "SslAllow" > $null 

    # Activar el aislamiento de usuarios
    Set-ItemProperty "IIS:\Sites\$global:siteName" -Name ftpServer.userIsolation.mode -Value 3 > $null 

    # Activar autenticación básica
    Set-ItemProperty "IIS:\Sites\$global:siteName" -Name ftpServer.security.authentication.basicAuthentication.enabled -Value $true > $null 
    Set-ItemProperty "IIS:\Sites\$global:siteName" -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $true > $null 

    PrintMessage "success" "Creacion de carpetas y configuraciones terminado."
}

function setupGroups {
    PrintMessage "info" "Configurando los grupos..."

    $reprobadosGroup = "reprobados"
    $recursadoresGroup = "recursadores"

    # Crear grupos locales
    New-LocalGroup -Name $reprobadosGroup -ErrorAction SilentlyContinue > $null 
    New-LocalGroup -Name $recursadoresGroup -ErrorAction SilentlyContinue > $null 

    # Rutas de las carpetas
    $reprobadosFolder = "$global:iftpPath\$reprobadosGroup"
    $recursadoresFolder = "$global:iftpPath\$recursadoresGroup"

    # Crear carpetas
    New-Item -ItemType Directory -Path $reprobadosFolder -Force > $null 
    New-Item -ItemType Directory -Path $recursadoresFolder -Force > $null 

    # Conceder permisos exclusivos
    icacls $reprobadosFolder /grant "${reprobadosGroup}:(OI)(CI)F" > $null 
    icacls $recursadoresFolder /grant "${recursadoresGroup}:(OI)(CI)F" > $null 

    icacls $reprobadosFolder /grant "${reprobadosGroup}:(OI)(CI)F" /T > $null 
    icacls $recursadoresFolder /grant "${recursadoresGroup}:(OI)(CI)F" /T > $null 

    # Denegar acceso a grupos opuestos
    icacls $reprobadosFolder /deny "${recursadoresGroup}:(OI)(CI)F" > $null 
    icacls $recursadoresFolder /deny "${reprobadosGroup}:(OI)(CI)F" > $null 

    # agregar permiso de read, write a todos 
    Add-WebConfiguration "/system.ftpServer/security/authorization" -Location $global:siteName -PSPath IIS:\ -Value @{accessType="Allow";users="*";permissions="Read,Write"} > $null 
    Add-WebConfiguration "/system.ftpServer/security/authorization" -Location $global:siteName -PSPath IIS:\ -Value @{accessType="Allow";users="?";permissions="Read,Write"} > $null 

    PrintMessage "success" "Grupos configurados correctamente."
}

function getUsername {
    # Bucle para validar el username
    do {
        $userName = InputText "Nombre del usuario"
    } while (-not (Validate-UserName $userName) -or (User-Exists $userName))
    return $userName
}

function getPassword {
    do {
        $password = InputText "Contraseña"  
    } while (-not (Validate-PasswordComplexity -Password $password))
    return $password
}

function getGroup {
    $userGroup = $null

    do{
        PrintMessage "" "Grupos:"
        PrintMessage "" "1) reprobados"
        PrintMessage "" "2) recursadores"
        $choice = InputNumber "Seleccione el grupo"

        switch ($choice) {
            1 { 
                $userGroup = "reprobados"
                break
            }
            2 { 
                $userGroup = "recursadores" 
                break
            }
            default { 
                PrintMessage "error" "Opción inválida, intente nuevamente."
                continue
            }
        }
        
    } while (-not $userGroup)

    return $userGroup
}

function createUserFolders {
    param (
        [string]$localUserPath,
        [string]$userName,
        [string]$userGroup
    )

    $userFolder = "$localUserPath\$userName"
    $userIntraFolder = "$localUserPath\$userName\$userName"

    if (!(Test-Path -Path $userFolder)) {
        New-Item -Path $userFolder -ItemType Directory > $null 
    }

    if (!(Test-Path -Path $userIntraFolder)) {
        New-Item -Path $userIntraFolder -ItemType Directory > $null 
    }

    # Junction: crear junctions a su grupo y a general
    $groupFolderPath = "$global:iftpPath\$userGroup"
    $generalFolderPath = "$global:iftpPath\general"

    cmd /c mklink /j "$userFolder\$userGroup" $groupFolderPath > $null 
    cmd /c mklink /j "$userFolder\general" $generalFolderPath > $null 

    # Dar permisos a carpetas
    icacls $userFolder /grant "${userName}:(OI)(CI)F" > $null 
    icacls $userFolder /grant "${userName}:(OI)(CI)F" /T > $null 

    icacls $userIntraFolder /grant "${userName}:(OI)(CI)F" > $null 
    icacls $userIntraFolder /grant "${userName}:(OI)(CI)F" /T > $null 

    icacls $groupFolderPath /grant "${userName}:(OI)(CI)F" > $null 
    icacls $groupFolderPath /grant "${userName}:(OI)(CI)F" /T > $null 

    icacls $generalFolderPath /grant "${userName}:(OI)(CI)F" > $null 
    icacls $generalFolderPath /grant "${userName}:(OI)(CI)F" /T > $null 

    icacls "$userFolder\$userGroup" /grant "${userName}:(OI)(CI)F" > $null 
    icacls "$userFolder\$userGroup" /grant "${userName}:(OI)(CI)F" /T > $null 
    
    icacls "$userFolder\general" /grant "${userName}:(OI)(CI)F" > $null 
    icacls "$userFolder\general" /grant "${userName}:(OI)(CI)F" /T > $null 

    Add-LocalGroupMember -Group $userGroup -Member $userName > $null 
    PrintMessage "success" "Usuario configurado correctamente"
}

function setupUsers {
    # Variables iniciales
    $localUserPath = "$global:iftpPath\LocalUser"
    $userCount = InputNumber "Cuántos usuarios desea crear"

    for ($j = 1; $j -le $userCount; $j++) {
        PrintMessage "info" "Para salir de la creacion de usuarios, presione Ctrl+C"

        $userName = getUsername
        $password = getPassword
        $userGroup = getGroup

        $confirmInput = InputText "Seguro que quiere crear al usuario? [lo que sea/N]"
        if ($confirmInput.ToUpper() -eq "N") {
            PrintMessage "info" "Usuario cancelado"
            $j--
            continue
        }

        $addUserOutput = net user $userName $password /add > $null 2>&1

        if ($LASTEXITCODE -ne 0) {
            PrintMessage "error" "error al agregar usuario"
            PrintMessage "error" "El proceso de creacion de usuario va a comenzar de nuevo, verifica el usuario y la contraseña"
            $j--
            continue
        }

        # Crear carpetas para el usuario y su grupo
        createUserFolders $localUserPath $userName $userGroup
    }

    PrintMessage "success" "Usuarios configurados correctamente."
}

# ====================
function configureFtp {
    $global:siteName = "FTPServer"
    $global:iftpPath = "C:\inetpub\ftproot\$global:siteName"

    $ftpInstalled = installFtp

    if(-not $ftpInstalled){
        return
    }

    setupFtp
    setupGroups
    Restart-WebItem -PSPath "IIS:\Sites\$global:siteName" 
}

function configureUsers {
    $global:siteName = "FTPServer"
    $global:iftpPath = "C:\inetpub\ftproot\$global:siteName"

    setupUsers
    Restart-WebItem -PSPath "IIS:\Sites\$global:siteName" 
}