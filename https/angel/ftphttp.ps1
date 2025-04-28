# Importar funciones de utils
. .\utils.ps1

function installFtp {
    PrintMessage "info" "Instalando IIS y servidor FTP..."
    
    # Verificar si IIS está instalado
    $iisInstalled = Get-WindowsFeature -Name Web-Server | Where-Object { $_.InstallState -eq "Installed" }
    if (-not $iisInstalled) {
        PrintMessage "info" "IIS no está instalado. Procediendo con la instalación..."
        dism /online /enable-feature /featurename:IIS-WebServer /all > $null
    }
    
    # Instalar el servidor FTP de IIS y la consola de administración
    dism /online /enable-feature /featurename:IIS-FTPServer /all > $null 
    dism /online /enable-feature /featurename:IIS-ManagementConsole /all > $null 
    net start w3svc > $null # Iniciar servicio de IIS (World Wide Web Publishing Service)
    net start ftpsvc > $null # Iniciar servicio FTP

    enableFirewallRules > $null

    if (Validate-FTP-Site -siteName $global:siteName -ftpPath $global:iftpPath) {
        PrintMessage "info" "Creando sitio FTP..."
        New-WebFtpSite -Name $global:siteName -Port 21 -PhysicalPath $global:iftpPath > $null 
        PrintMessage "success" "Servidor FTP instalado y servicio iniciado."
        enableFirewallRules > $null
        return $true
    }
    else {
        PrintMessage "error" "El sitio FTP ya existe."
        return $false;
    }
}


function setupFtp {
    # Crear estructura de carpetas
    $folders = @(
        "$global:iftpPath\windows",
        "$global:iftpPath\http",
        "$global:iftpPath\http\IIS",
        "$global:iftpPath\http\Tomcat",
        "$global:iftpPath\http\Nginx",
        "$global:iftpPath\LocalUser"
    )

    foreach ($folder in $folders) {
        if (-not (Test-Path $folder)) {
            New-Item -ItemType Directory -Path $folder -Force > $null
            PrintMessage "info" "Carpeta creada: $folder"
        }
    }

    # Configurar permisos base para todas las carpetas
    $acl = Get-Acl $global:iftpPath
    $permissions = @(
        [System.Security.AccessControl.FileSystemAccessRule]::new("Everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"),
        [System.Security.AccessControl.FileSystemAccessRule]::new("IUSR", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    )

    foreach ($permission in $permissions) {
        $acl.AddAccessRule($permission)
    }
    Set-Acl -Path $global:iftpPath -AclObject $acl

    # Configurar permisos heredables para LocalUser
    $localUserAcl = Get-Acl "$global:iftpPath\LocalUser"
    $localUserAcl.SetAccessRuleProtection($false, $true) # Habilitar herencia
    Set-Acl -Path "$global:iftpPath\LocalUser" -AclObject $localUserAcl

    # Configuración del servidor FTP
    Set-ItemProperty "IIS:\Sites\$global:siteName" -Name ftpServer.security.ssl.controlChannelPolicy -Value "SslAllow" > $null 
    Set-ItemProperty "IIS:\Sites\$global:siteName" -Name ftpServer.security.ssl.dataChannelPolicy -Value "SslAllow" > $null 
    Set-ItemProperty "IIS:\Sites\$global:siteName" -Name ftpServer.userIsolation.mode -Value 3 > $null 
    Set-ItemProperty "IIS:\Sites\$global:siteName" -Name ftpServer.security.authentication.basicAuthentication.enabled -Value $true > $null 
    Set-ItemProperty "IIS:\Sites\$global:siteName" -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $true > $null 

    # Configurar reglas de autorización FTP para permitir acceso completo a todos
    Add-WebConfiguration "/system.ftpServer/security/authorization" -Location $global:siteName -PSPath IIS:\ -Value @{
        accessType  = "Allow"
        users       = "*"
        permissions = "Read,Write"
    } > $null

    Add-WebConfiguration "/system.ftpServer/security/authorization" -Location "$global:siteName/LocalUser" -PSPath IIS:\ -Value @{
        accessType  = "Allow"
        users       = "*"
        permissions = "Read,Write"
    } > $null

    PrintMessage "success" "Estructura de carpetas y configuración FTP completada."
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
        [string]$basePath,
        [string]$userName
    )

    # Crear carpeta personal del usuario
    $userFolder = "$basePath\LocalUser\$userName"
    New-Item -Path $userFolder -ItemType Directory -Force > $null

    # Configurar permisos para el usuario (todos tendrán acceso completo)
    $acl = Get-Acl $userFolder
    $permissions = @(
        [System.Security.AccessControl.FileSystemAccessRule]::new("Everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"),
        [System.Security.AccessControl.FileSystemAccessRule]::new("IUSR", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"),
        [System.Security.AccessControl.FileSystemAccessRule]::new($userName, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    )

    foreach ($permission in $permissions) {
        $acl.AddAccessRule($permission)
    }
    Set-Acl -Path $userFolder -AclObject $acl

    # Crear enlaces simbólicos a las carpetas de servicios
    $services = @("IIS", "Tomcat", "Nginx", "windows")
    foreach ($service in $services) {
        $targetPath = "$basePath\$service"
        if ($service -ne "windows") {
            $targetPath = "$basePath\http\$service"
        }
        $linkPath = "$userFolder\$service"
        if (Test-Path $targetPath) {
            cmd /c mklink /j $linkPath $targetPath > $null
        }
    }

    PrintMessage "success" "Carpetas y permisos configurados para el usuario $userName"
}

function setupUsers {
    $userCount = InputNumber "Cuántos usuarios desea crear"
    $basePath = $global:iftpPath

    # Crear carpeta LocalUser si no existe
    if (-not (Test-Path "$basePath\LocalUser")) {
        New-Item -Path "$basePath\LocalUser" -ItemType Directory -Force > $null
    }

    for ($j = 1; $j -le $userCount; $j++) {
        PrintMessage "info" "Para salir de la creacion de usuarios, presione Ctrl+C"

        $userName = getUsername
        $password = getPassword

        $confirmInput = InputText "¿Seguro que quiere crear al usuario? [S/N]"
        if ($confirmInput.ToUpper() -eq "N") {
            PrintMessage "info" "Usuario cancelado"
            $j--
            continue
        }

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
    }

    PrintMessage "success" "Todos los usuarios configurados correctamente."
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

    PrintMessage "info" "Para salir de la creación de usuarios, presione Ctrl+C"

    $userName = "httpftp"
    $password = "P@ssw0rd123"

    # Verificar si el usuario ya existe
    if (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue) {
        PrintMessage "info" "El usuario '$userName' ya existe. Se omite la creación."
    } else {
        # Crear usuario
        try {
            New-LocalUser -Name $userName -Password (ConvertTo-SecureString $password -AsPlainText -Force) -ErrorAction Stop > $null
            PrintMessage "success" "Usuario '$userName' creado correctamente."
        }
        catch {
            PrintMessage "error" "Error al crear el usuario: $_"
            return
        }
    }

    # Configurar carpetas y permisos (siempre se ejecuta)
    createUserFolders -basePath $basePath -userName $userName

    PrintMessage "success" "Todos los usuarios configurados correctamente."
}


function Install-FromFTP {
    param (
        [string]$software,  # "Tomcat" o "Nginx"
        [int]$port,         # Puerto de instalación
        [string]$ftpUser = "httpftp",
        [string]$ftpPassword = "P@ssw0rd123"
    )

    # Validar software y puerto
    if ($software -notin @("Tomcat", "Nginx")) {
        Write-Host "Error: Debes especificar 'Tomcat' o 'Nginx'." -ForegroundColor Red
        return
    }

    if ($port -lt 1 -or $port -gt 65535) {
        Write-Host "Error: El puerto debe estar entre 1 y 65535." -ForegroundColor Red
        return
    }

    # Obtener la IP de la máquina local
    $ftpServer = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" } | Select-Object -ExpandProperty IPAddress | Select-Object -First 1)

    if (-not $ftpServer) {
        Write-Host "No se pudo determinar la dirección IP del servidor FTP." -ForegroundColor Red
        return
    }

    Write-Host "`nEl servidor FTP está en: $ftpServer"

    # Definir las rutas de los instaladores
    $ftpPaths = @{
        "Tomcat" = "ftp://$ftpServer/FTPServer/http/Tomcat/"
        "Nginx"  = "ftp://$ftpServer/FTPServer/http/Nginx/"
    }

    $localInstallPath = "C:\Temp\ftp_installs\$software"
    if (-not (Test-Path $localInstallPath)) {
        New-Item -ItemType Directory -Path $localInstallPath | Out-Null
    }

    Write-Host "`nDescargando $software desde FTP..."

    # Descargar archivos del directorio FTP seleccionado
    $ftpUri = $ftpPaths[$software]
    
    $webClient = New-Object System.Net.WebClient
    $webClient.Credentials = New-Object System.Net.NetworkCredential($ftpUser, $ftpPassword)

    try {
        $fileList = $webClient.DownloadString($ftpUri) -split "`r`n" | Where-Object { $_ -match "\.zip$" -or $_ -match "\.msi$" }
        if ($fileList.Count -eq 0) {
            Write-Host "No se encontraron archivos en $ftpUri." -ForegroundColor Red
            return
        }

        foreach ($file in $fileList) {
            $remoteFile = "$ftpUri$file"
            $localFile = "$localInstallPath\$file"
            
            if (-not (Test-Path $localFile)) {
                Write-Host "Descargando: $file..."
                $webClient.DownloadFile($remoteFile, $localFile)
            } else {
                Write-Host "El archivo $file ya existe localmente, omitiendo descarga."
            }
        }
    }
    catch {
        Write-Host "Error al descargar archivos: $_" -ForegroundColor Red
        return
    }

    Write-Host "Archivos descargados correctamente en $localInstallPath."

    # Instalación según el software seleccionado
    switch ($software) {
        "Tomcat" {
            Write-Host "Instalando Tomcat en el puerto $port..."
            $tomcatInstaller = Get-ChildItem -Path $localInstallPath -Filter "*.zip" | Select-Object -First 1
            if ($tomcatInstaller) {
                Expand-Archive -Path $tomcatInstaller.FullName -DestinationPath "C:\Tomcat" -Force
                Write-Host "Tomcat instalado en C:\Tomcat"

                # Configurar el puerto en server.xml
                $serverXml = "C:\Tomcat\conf\server.xml"
                if (Test-Path $serverXml) {
                    (Get-Content $serverXml) -replace 'port="8080"', "port=`"$port`"" | Set-Content $serverXml
                    Write-Host "Puerto de Tomcat configurado en server.xml a $port."
                } else {
                    Write-Host "No se encontró server.xml para configurar el puerto." -ForegroundColor Yellow
                }
            } else {
                Write-Host "No se encontró un archivo ZIP de Tomcat." -ForegroundColor Red
            }
        }
        "Nginx" {
            Write-Host "Instalando Nginx en el puerto $port..."
            $nginxInstaller = Get-ChildItem -Path $localInstallPath -Filter "*.zip" | Select-Object -First 1
            if ($nginxInstaller) {
                Expand-Archive -Path $nginxInstaller.FullName -DestinationPath "C:\Nginx" -Force
                Write-Host "Nginx instalado en C:\Nginx"

                # Configurar el puerto en nginx.conf
                $nginxConf = "C:\Nginx\conf\nginx.conf"
                if (Test-Path $nginxConf) {
                    (Get-Content $nginxConf) -replace 'listen\s+\d+', "listen $port" | Set-Content $nginxConf
                    Write-Host "Puerto de Nginx configurado en nginx.conf a $port."
                } else {
                    Write-Host "No se encontró nginx.conf para configurar el puerto." -ForegroundColor Yellow
                }
            } else {
                Write-Host "No se encontró un archivo ZIP de Nginx." -ForegroundColor Red
            }
        }
    }

    Write-Host "`nProceso completado." -ForegroundColor Green
}

function InstallTomcatFTP {
    param(
        [int]$puerto
    )

    Write-Host "`n=== Instalación de Apache Tomcat ==="

    # Preguntar si se quiere SSL
    $ssl = Preguntar-SSL
    $sslPort = $null
    
    if ($ssl) {
        $sslPort = Solicitar-Puerto -mensaje "Ingrese el puerto HTTPS para Tomcat" -defaultPort 8443
        if (-not $sslPort) {
            Write-Host "No se configurará SSL."
            $ssl = $false
        }
    }

    # Configuración FTP
    $ftpUser = "httpftp"
    $ftpPass = "P@ssw0rd123"
    $localIp = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" }).IPAddress
    $ftpBasePath = "ftp://$localIp/FTPServer/http/Tomcat"

    # Crear credenciales FTP
    $ftpCredentials = New-Object System.Net.NetworkCredential($ftpUser, $ftpPass)

    # Obtener las versiones disponibles desde el servidor FTP local
    $tomcatVersions = @{}
    
    try {
        # Listar directorios de versiones disponibles
        $request = [System.Net.FtpWebRequest]::Create("$ftpBasePath/")
        $request.Credentials = $ftpCredentials
        $request.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectoryDetails
        $response = $request.GetResponse()
        $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
        $directories = @()

        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            if ($line -match "<DIR>") {
                $dirName = $line -split '\s+' | Select-Object -Last 1
                $directories += $dirName
            }
        }
        $reader.Close()
        $response.Close()

        # Para cada directorio, buscar archivos zip
        foreach ($dir in $directories) {
            try {
                $request = [System.Net.FtpWebRequest]::Create("$ftpBasePath/$dir/")
                $request.Credentials = $ftpCredentials
                $request.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectoryDetails
                $response = $request.GetResponse()
                $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
                $files = @()

                while (-not $reader.EndOfStream) {
                    $line = $reader.ReadLine()
                    if ($line -notmatch "<DIR>" -and $line -match "\.zip$") {
                        $fileName = $line -split '\s+' | Select-Object -Last 1
                        $files += $fileName
                    }
                }
                $reader.Close()
                $response.Close()

                if ($files.Count -gt 0) {
                    $versionNumber = $dir -replace '[^0-9.]', ''
                    $tomcatVersions[$dir] = @{
                        Version = $versionNumber
                        Url = "$ftpBasePath/$dir/$($files[0])"
                        FtpCredentials = $ftpCredentials
                    }
                }
            } catch {
                Write-Host "Error al leer contenido del directorio $dir $_"
                continue
            }
        }
    } catch {
        Write-Host "Error al conectar al servidor FTP: $_"
        return
    }

    if ($tomcatVersions.Count -eq 0) {
        Write-Host "No se encontraron versiones de Tomcat en el servidor FTP local. Abortando."
        return
    }

    # Mostrar opciones disponibles
    Write-Host "Seleccione la versión a instalar:"
    $opciones = @{ }
    $index = 1

    foreach ($key in $tomcatVersions.Keys) {
        $versionInfo = $tomcatVersions[$key]
        Write-Host "$index) $key - Versión: $($versionInfo.Version)"
        $opciones["$index"] = $key
        $index++
    }

    # Solicitar selección del usuario
    do {
        $seleccion = Read-Host "Ingrese el número de la versión a instalar (o 's' para salir)"
        if ($seleccion -eq 's') {
            Write-Host "Cancelando instalación de Tomcat."
            return
        }
    } while (-not $opciones.ContainsKey($seleccion))

    # Obtener la versión seleccionada
    $seleccionada = $opciones[$seleccion]
    $seleccionTomcat = $tomcatVersions[$seleccionada]

    Write-Host "Instalando $seleccionada - Versión: $($seleccionTomcat.Version) desde: $($seleccionTomcat.Url)"

    # Verificar si Java está instalado
    if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
        Write-Host "Java no está instalado. Es necesario para ejecutar Tomcat."
        
        # Preguntar si el usuario quiere instalar Java
        $respuesta = Read-Host "¿Desea instalar Java automáticamente? (s/n)"
        if ($respuesta -eq "s") {
            Install-Java
        }
        else {
            Write-Host "No se puede continuar sin Java. Abortando instalación de Tomcat."
            return
        }

        # Verificar nuevamente si Java se instaló correctamente
        if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
            Write-Host "Hubo un error instalando Java. Inténtelo manualmente."
            return
        }
    }

    # Definir ruta de instalación
    $tomcatPath = "C:\Tomcat"

    # Eliminar instalación previa si existe
    if (Test-Path $tomcatPath) {
        Remove-Item -Recurse -Force $tomcatPath
    }
    New-Item -ItemType Directory -Force -Path $tomcatPath | Out-Null

    # Descargar Tomcat desde FTP
    $zipFile = "$env:TEMP\tomcat.zip"
    Write-Host "Descargando Tomcat versión $($seleccionTomcat.Version) desde el servidor FTP..."
    
    try {
        $request = [System.Net.FtpWebRequest]::Create($seleccionTomcat.Url)
        $request.Credentials = $seleccionTomcat.FtpCredentials
        $request.Method = [System.Net.WebRequestMethods+Ftp]::DownloadFile
        $request.UseBinary = $true
        
        $response = $request.GetResponse()
        $stream = $response.GetResponseStream()
        $fileStream = [System.IO.File]::Create($zipFile)
        $stream.CopyTo($fileStream)
        
        $fileStream.Close()
        $stream.Close()
        $response.Close()
    } catch {
        Write-Host "Error al descargar el archivo desde FTP: $_"
        return
    }

    # Extraer archivos
    Write-Host "Extrayendo archivos..."
    Expand-Archive -Path $zipFile -DestinationPath $tomcatPath -Force
    Remove-Item $zipFile

    # Mover archivos si el ZIP contiene un subdirectorio
    $subdirs = Get-ChildItem -Path $tomcatPath | Where-Object { $_.PSIsContainer }
    if ($subdirs.Count -eq 1) {
        Move-Item -Path "$($subdirs[0].FullName)\*" -Destination $tomcatPath -Force
        Remove-Item -Recurse -Force $subdirs[0].FullName
    }

    # Modificar server.xml para actualizar el puerto
    $serverXml = Join-Path $tomcatPath "conf\server.xml"
    if (Test-Path $serverXml) {
        (Get-Content $serverXml) -replace 'port="8080"', "port=`"$puerto`"" | Set-Content $serverXml
        Write-Host "Puerto configurado en server.xml a $puerto."
    }
    else {
        Write-Host "No se encontró server.xml para configurar el puerto."
    }

    # Configurar SSL si se solicitó
    if ($ssl) {
        Configurar-SSL-Tomcat -tomcatPath $tomcatPath -sslPort $sslPort
    }

    # Definir la ruta del script de inicio de Tomcat
    $startupBat = Join-Path $tomcatPath "bin\startup.bat"

    # Verificar si existe startup.bat y ejecutarlo
    if (Test-Path $startupBat) {
        Write-Host "Iniciando Tomcat manualmente con startup.bat..."
        $env:CATALINA_HOME = $tomcatPath
        Start-Process -FilePath $startupBat -NoNewWindow
        Write-Host "Tomcat iniciado con startup.bat."
    }
    else {
        Write-Host "No se encontró startup.bat. No se pudo iniciar Tomcat."
    }
}