# Importar funciones de utils
. .\utils.ps1

function Configure-FtpSSL {
    $certSubject = "FTP SSL Certificate - $($env:COMPUTERNAME)"
    $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$certSubject" }
    
    if (-not $cert) {
        PrintMessage "info" "Creando certificado autofirmado para SSL en FTP..."
        $cert = New-SelfSignedCertificate `
            -DnsName $env:COMPUTERNAME `
            -CertStoreLocation "cert:\LocalMachine\My" `
            -Subject "CN=$certSubject" `
            -KeySpec Signature `
            -KeyLength 2048 `
            -KeyExportPolicy Exportable `
            -NotAfter (Get-Date).AddYears(5)
    }

    Import-Module WebAdministration
    Set-ItemProperty "IIS:\Sites\$global:siteName" -Name ftpServer.security.ssl.serverCertHash -Value $cert.Thumbprint
    Set-ItemProperty "IIS:\Sites\$global:siteName" -Name ftpServer.security.ssl.controlChannelPolicy -Value "SslRequire"
    Set-ItemProperty "IIS:\Sites\$global:siteName" -Name ftpServer.security.ssl.dataChannelPolicy -Value "SslRequire"
    Set-ItemProperty "IIS:\Sites\$global:siteName" -Name ftpServer.security.ssl.ssl128 -Value $true

    New-NetFirewallRule -DisplayName "FTP-SSL" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 990 -ErrorAction SilentlyContinue

    PrintMessage "success" "SSL habilitado correctamente para el sitio FTP."
    PrintMessage "info" "Certificado: CN=$certSubject - Thumbprint: $($cert.Thumbprint)"
}

function installFtp {
    PrintMessage "info" "Instalando servidor FTP..."
    
    dism /online /enable-feature /featurename:IIS-FTPServer /all > $null 
    dism /online /enable-feature /featurename:IIS-ManagementConsole /all > $null 
    net start ftpsvc > $null 

    enableFirewallRules > $null

    if (Validate-FTP-Site -siteName $global:siteName -ftpPath $global:iftpPath) {
        PrintMessage "info" "Creando sitio ftp..."
        New-WebFtpSite -Name $global:siteName -Port 21 > $null 
        Configure-FtpSSL
        PrintMessage "success" "Servidor FTP instalado y servicio iniciado."
        enableFirewallRules > $null
        return $true
    }
    else {
        PrintMessage "error" "El sitio FTP ya existe."
        return $false;
    }
}

function setupHttpInstallersFolders {
    $basePath = "$global:iftpPath\http\Windows"
    $carpetas = @("Apache", "Tomcat", "Nginx", "IIS", "Otros")

    foreach ($nombre in $carpetas) {
        $ruta = Join-Path $basePath $nombre
        if (!(Test-Path $ruta)) {
            New-Item -Path $ruta -ItemType Directory > $null
        }
    }

    PrintMessage "success" "Estructura de carpetas para instaladores HTTP creada en: $basePath"
}

function setupFtp {
    mkdir "$global:iftpPath\general" > $null 

    $path = "$global:iftpPath\general"
    $acl = Get-Acl $path
    $permission = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.SetAccessRule($permission)
    Set-Acl -Path $path -AclObject $acl

    $anonUser = "IUSR"
    $permissionAnon = New-Object System.Security.AccessControl.FileSystemAccessRule($anonUser, "Read", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($permissionAnon)
    Set-Acl -Path $path -AclObject $acl

    $permissionAnonWrite = New-Object System.Security.AccessControl.FileSystemAccessRule($anonUser, "Write", "ContainerInherit,ObjectInherit", "None", "Deny")
    $acl.AddAccessRule($permissionAnonWrite)

    Set-ItemProperty "IIS:\Sites\$global:siteName" -Name physicalPath -Value $global:iftpPath > $null 

    Import-Module WebAdministration > $null 
    Set-ItemProperty "IIS:\Sites\$global:siteName" -Name ftpServer.security.ssl.controlChannelPolicy -Value "SslAllow" > $null 
    Set-ItemProperty "IIS:\Sites\$global:siteName" -Name ftpServer.security.ssl.dataChannelPolicy -Value "SslAllow" > $null 

    Set-ItemProperty "IIS:\Sites\$global:siteName" -Name ftpServer.userIsolation.mode -Value 3 > $null 
    Set-ItemProperty "IIS:\Sites\$global:siteName" -Name ftpServer.security.authentication.basicAuthentication.enabled -Value $true > $null 
    Set-ItemProperty "IIS:\Sites\$global:siteName" -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $true > $null 

    setupHttpInstallersFolders

    PrintMessage "success" "Creación de carpetas y configuración inicial terminada."
}

function getUsername {
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

function createUserFolders {
    param (
        [string]$localUserPath,
        [string]$userName
    )

    $userFolder = "$localUserPath\$userName"

    if (!(Test-Path -Path $userFolder)) {
        New-Item -Path $userFolder -ItemType Directory > $null 
    }

    icacls $userFolder /grant "${userName}:(OI)(CI)F" /T > $null 
    PrintMessage "success" "Carpeta del usuario creada: $userFolder"
}

function setupUsers {
    $localUserPath = "$global:iftpPath\LocalUser"
    if (!(Test-Path $localUserPath)) {
        New-Item -ItemType Directory -Path $localUserPath > $null 
    }

    $userCount = InputNumber "Cuántos usuarios desea crear"

    for ($j = 1; $j -le $userCount; $j++) {
        PrintMessage "info" "Para salir de la creación de usuarios, presione Ctrl+C"

        $userName = getUsername
        $password = getPassword

        $confirmInput = InputText "Seguro que quiere crear al usuario? [lo que sea/N]"
        if ($confirmInput.ToUpper() -eq "N") {
            PrintMessage "info" "Usuario cancelado"
            $j--
            continue
        }

        $addUserOutput = net user $userName $password /add > $null 2>&1

        if ($LASTEXITCODE -ne 0) {
            PrintMessage "error" "Error al agregar usuario"
            $j--
            continue
        }

        createUserFolders $localUserPath $userName
    }

    PrintMessage "success" "Usuarios configurados correctamente."
}

# ====================
function configureFtp {
    $global:siteName = "FTPServer"
    $global:iftpPath = "C:\inetpub\ftproot\$global:siteName"

    $ftpInstalled = installFtp
    if (-not $ftpInstalled) {
        return
    }

    setupFtp
    Restart-WebItem -PSPath "IIS:\Sites\$global:siteName" 
}

function configureUsers {
    $global:siteName = "FTPServer"
    $global:iftpPath = "C:\inetpub\ftproot\$global:siteName"

    setupUsers
    Restart-WebItem -PSPath "IIS:\Sites\$global:siteName" 
}

function createHttpFtpUser {
    $basePath = $global:iftpPath

    # Crear carpeta LocalUser si no existe
    if (-not (Test-Path "$basePath\LocalUser")) {
        New-Item -Path "$basePath\LocalUser" -ItemType Directory -Force > $null
    }


    PrintMessage "info" "Para salir de la creacion de usuarios, presione Ctrl+C"

    $userName = "httpftp"
    $password = "P@ssw0rd123"

    # Crear usuario
    try {
        New-LocalUser -Name $userName -Password (ConvertTo-SecureString $password -AsPlainText -Force) -ErrorAction Stop > $null
        PrintMessage "success" "Usuario $userName creado correctamente"
            
        # Configurar carpetas y permisos
        createUserFolders -basePath $basePath -userName $userName
    }
    catch {
        PrintMessage "error" "Error al crear el usuario: $_"
        $j--
        continue
    }

    PrintMessage "success" "Todos los usuarios configurados correctamente."
}