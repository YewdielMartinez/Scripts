# Carga de funciones (por ejemplo, importar el archivo si está en otra ubicación)
.\funciones_http.ps1
.\funciones_ftpcito2.ps1

$global:ftpPort = 21

# Función para validar la contraseña
function Validate-PasswordComplexity {
    param (
        [string]$Password
    )

    if (-not $Password -or $Password.Length -lt 8) {
        Write-Host "Error: La contraseña debe tener al menos 8 caracteres."
        return $false
    }

    # Se requieren al menos 3 de las 4 categorías
    $categories = 0
    if ($Password -match "[A-Z]") { $categories++ }   # Mayúscula
    if ($Password -match "[a-z]") { $categories++ }   # Minúscula
    if ($Password -match "\d")    { $categories++ }   # Número
    if ($Password -match "[^\w]")  { $categories++ }   # Carácter especial

    if ($categories -ge 3) {
        return $true
    } else {
        Write-Host "Error: La contraseña debe contener al menos 3 de estas 4 categorías: mayúsculas, minúsculas, números o caracteres especiales."
        return $false
    }
}

# Función para validar el nombre de usuario
function Validate-UserName {
    param (
        [string]$nombreUsuario
    )

    # La expresión regular permite letras, números, guiones bajos y medios; no permite comenzar con carácter especial o número
    $regex = '^[a-zA-Z_][a-zA-Z0-9_-]{1,18}$'
    
    if ($nombreUsuario -match $regex) {
        return $true
    } else {
        Write-Host "Nombre de usuario no válido. Debe tener al menos 2 caracteres y usar solo letras, números, guiones bajos o medios. No debe comenzar con caracteres especiales ni números."
        return $false
    }
}

# Función para verificar si el usuario local ya existe
function User-Exists {
    param (
        [string]$nombreUsuario
    )
    
    if (Get-LocalUser -Name $nombreUsuario -ErrorAction SilentlyContinue) {
        Write-Host "El usuario '$nombreUsuario' ya existe en el sistema." 
        return $true
    } else {
        return $false
    }
}

# Función para validar si el directorio y puerto están disponibles
function Validate-FTP-Site {
    param (
        [string]$ftpPath
    )

    if (-not (Test-Path $ftpPath)) {
        Write-Host "El directorio '$ftpPath' no existe. Creándolo..."
        New-Item -Path $ftpPath -ItemType Directory -Force | Out-Null
    }

    # Verificamos si el puerto configurado ya está en uso
    $portInUse = Get-NetTCPConnection -LocalPort $global:ftpPort -ErrorAction SilentlyContinue
    if ($portInUse) {
        Write-Host "Error: El puerto $($global:ftpPort) ya está en uso por otro servicio."
        # Se solicita al usuario ingresar un puerto alternativo
        $newPort = Read-Host "Ingrese un puerto alternativo para el FTP o presione Enter para cancelar"
        if ([string]::IsNullOrWhiteSpace($newPort)) {
            Write-Host "No se ingresó un puerto. Cancelando la configuración."
            return $false
        }
        if ($newPort -match "^\d+$") {
            $global:ftpPort = [int]$newPort
            # Se vuelve a verificar si el nuevo puerto también está en uso
            $portInUse = Get-NetTCPConnection -LocalPort $global:ftpPort -ErrorAction SilentlyContinue
            if ($portInUse) {
                Write-Host "El puerto alternativo $($global:ftpPort) también está en uso. Cancelando la configuración."
                return $false
            }
        } else {
            Write-Host "El valor ingresado no es un puerto válido. Cancelando la configuración."
            return $false
        }
    }

    return $true
}


# Función para solicitar un número y validarlo
function InputNumber {
    param (
        [string]$mensaje = "Ingrese un número:"
    )

    do {
        $entrada = Read-Host $mensaje
        if ($entrada -match "^\d+(\.\d+)?$") {
            return [double]$entrada
        } else {
            Write-Host "Error: Debe ingresar un valor numérico válido."
        }
    } while ($true)
}

# Función para solicitar un texto y validarlo (no vacío)
function InputText {
    param (
        [string]$mensaje = "Ingrese un texto:"
    )

    do {
        $entrada = Read-Host $mensaje
        if ($entrada -match "^\s*$") {
            Write-Host "No puede estar vacío. Intente nuevamente."
        } else {
            return $entrada
        }
    } while ($true)
}

# Función para instalar y configurar el servidor FTP en IIS
function Install-FTP {
    # Instalar características requeridas
    Install-WindowsFeature Web-FTP-Server -IncludeAllSubFeature
    Install-WindowsFeature Web-Server -IncludeManagementTools
    Import-Module WebAdministration

    # Definir variables globales con interpolación correcta
    $global:siteName = "FTPServer"
    $global:iftpPath = "C:\inetpub\ftproot\$($global:siteName)"

    # Validar directorio y puerto (sin revisar existencia del sitio para evitar conflicto)
    if (-not (Validate-FTP-Site -ftpPath $global:iftpPath)) {
        Write-Host "Error en la configuración del directorio o puerto."
        return $false
    }

    # Si ya existe un sitio con ese nombre, lo eliminamos para una instalación limpia.
    $existingSite = Get-WebSite -Name $global:siteName -ErrorAction SilentlyContinue
    if ($existingSite) {
        Write-Host "El sitio FTP '$global:siteName' ya existe. Eliminándolo para reinstalar..."
        Remove-WebSite -Name $global:siteName -ErrorAction SilentlyContinue
    }

    # Crear el sitio FTP
    New-WebFtpSite -Name $global:siteName -Port $global:ftpPort -PhysicalPath $global:iftpPath
    Write-Host "FTP y servidor web IIS instalados correctamente en el puerto $($global:ftpPort)."
    return $true
}

# Función para crear la estructura de carpetas y configurar permisos para el FTP
function Setup-FTP {
    # Lista de carpetas a crear con la nueva estructura:
    # 1. La carpeta "http"
    # 2. La subcarpeta "windows" dentro de "http"
    # 3. Dentro de "windows": las carpetas de los servicios "Tomcat" y "Nginx"
    # 4. La carpeta "LocalUser" para los usuarios
    $folders = @(
        "$($global:iftpPath)\http",
        "$($global:iftpPath)\http\windows",
        "$($global:iftpPath)\http\windows\Tomcat",
        "$($global:iftpPath)\http\windows\Nginx",
        "$($global:iftpPath)\LocalUser"
    )

    foreach ($folder in $folders) {
        if (-not (Test-Path $folder)) {
            New-Item -ItemType Directory -Path $folder -Force | Out-Null
            Write-Host "Carpeta creada: $folder"
        }
    }

    # Configuración de permisos básicos – ajusta o elimina permisos a grupos si lo deseas.
    $acl = Get-Acl $global:iftpPath
    $permissions = @(
        [System.Security.AccessControl.FileSystemAccessRule]::new("Everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"),
        [System.Security.AccessControl.FileSystemAccessRule]::new("IUSR", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    )
    foreach ($permission in $permissions) {
        $acl.AddAccessRule($permission)
    }
    Set-Acl -Path $global:iftpPath -AclObject $acl

    # Habilitar herencia en LocalUser
    $localUserPath = "$($global:iftpPath)\LocalUser"
    $localUserAcl = Get-Acl $localUserPath
    $localUserAcl.SetAccessRuleProtection($false, $true)
    Set-Acl -Path $localUserPath -AclObject $localUserAcl

    # Configurar parámetros del sitio FTP en IIS
    Set-ItemProperty "IIS:\Sites\$($global:siteName)" -Name ftpServer.security.ssl.controlChannelPolicy -Value "SslAllow"
    Set-ItemProperty "IIS:\Sites\$($global:siteName)" -Name ftpServer.security.ssl.dataChannelPolicy -Value "SslAllow"
    Set-ItemProperty "IIS:\Sites\$($global:siteName)" -Name ftpServer.userIsolation.mode -Value 3
    Set-ItemProperty "IIS:\Sites\$($global:siteName)" -Name ftpServer.security.authentication.basicAuthentication.enabled -Value $true
    Set-ItemProperty "IIS:\Sites\$($global:siteName)" -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $true

    # Agregar regla de autorización FTP
    Add-WebConfiguration "/system.ftpServer/security/authorization" -Location $global:siteName -PSPath IIS:\ -Value @{
        accessType  = "Allow"
        users       = "*"
        permissions = "Read,Write"
    }

    Write-Host "Estructura de carpetas y configuración FTP completada."
}


# Función para obtener el nombre del usuario, validando que cumpla el formato y no exista
function Get-Username {
    do {
        $userName = InputText "Nombre del usuario:"
    } while (-not (Validate-UserName $userName) -or (User-Exists $userName))
    return $userName
}

# Función para obtener la contraseña validándola
function Get-Password {
    do {
        $password = InputText "Contraseña:"
    } while (-not (Validate-PasswordComplexity -Password $password))
    return $password
}

# Función para crear la carpeta del usuario y crear enlaces simbólicos (junction) a las carpetas de servicios
function Create-UserFolders {
    param (
        [string]$basePath,
        [string]$userName
    )

    # Crear la carpeta del usuario dentro de LocalUser
    $userFolder = "$basePath\LocalUser\$userName"
    New-Item -Path $userFolder -ItemType Directory -Force | Out-Null

    # Configuración de permisos: se asigna FullControl directamente al usuario
    $acl = Get-Acl $userFolder
    $permission = [System.Security.AccessControl.FileSystemAccessRule]::new($userName, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($permission)
    Set-Acl -Path $userFolder -AclObject $acl

    # Crear enlaces simbólicos para los servicios Tomcat y Nginx
    # La ruta de destino ahora es: $global:iftpPath\http\windows\<Servicio>
    $services = @("Tomcat", "Nginx")
    foreach ($service in $services) {
        $targetPath = "$global:iftpPath\http\windows\$service"
        $linkPath = "$userFolder\$service"
        if (Test-Path $targetPath) {
            # Crea un enlace de tipo junction; se requiere ejecutar como administrador
            cmd /c mklink /j "$linkPath" "$targetPath" | Out-Null
            Write-Host "Enlace simbólico creado: $linkPath -> $targetPath"
        } else {
            Write-Host "No se encontró el destino $targetPath para el servicio $service."
        }
    }

    Write-Host "Carpetas y permisos configurados para el usuario $userName"
}




# Función para configurar la creación de usuarios
function Setup-Users {
    $localUserPath = "$($global:iftpPath)\LocalUser"
    $userCount = InputNumber "¿Cuántos usuarios desea crear?"

    for ($j = 1; $j -le $userCount; $j++) {
        $userName = Get-Username
        $password = Get-Password
        
        $confirmInput = InputText "¿Seguro que quiere crear el usuario $userName? (Ingrese 'N' para cancelar o 'S' para confirmar)"
        if ($confirmInput.ToUpper() -eq "N") {
            Write-Host "Creación de usuario cancelada."
            $j--
            continue
        }

        $addUserOutput = net user $userName $password /add

        if ($LASTEXITCODE -ne 0) {
            Write-Host "Error al agregar el usuario. Reiniciando el proceso para $userName."
            $j--
            continue
        }

        # Crear carpetas y enlaces para el usuario creado
        Create-UserFolders -basePath $localUserPath -userName $userName
    }

    Write-Host "Usuarios configurados correctamente."
}

# Función para configurar el FTP (instala, crea estructura y reinicia el sitio)
function Configure-FTP {
    if (Install-FTP) {
        Setup-FTP
        Restart-WebItem -PSPath "IIS:\Sites\$($global:siteName)" -ErrorAction SilentlyContinue
    }
}

# Función para configurar usuarios
function Configure-Users {
    # Asegurarse de que las variables globales estén definidas
    $global:siteName = "FTPServer"
    $global:iftpPath = "C:\inetpub\ftproot\$($global:siteName)"
    
    Setup-Users
    Restart-WebItem -PSPath "IIS:\Sites\$($global:siteName)" -ErrorAction SilentlyContinue
}