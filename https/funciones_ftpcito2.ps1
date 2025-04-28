.\funciones_http.ps1
.\funciones_ftpcito1.ps1
# ======================================================
# Funciones de Conexión, Descarga e Instalación vía FTP
# ======================================================


$global:siteName = "FTPServer"
$global:iftpPath = "C:\inetpub\ftproot\$($global:siteName)"
# Definir variables para carpetas de descargas (si se usan en otros procesos)
$TARGET_DIR  = "$($global:iftpPath)\http\windows\Tomcat"
$NTARGET_DIR = "$($global:iftpPath)\http\windows\Nginx"

function Connect-FTP {
    param (
        [string]$DefaultServer = "localhost",
        [string]$BaseDir = "/FTPServer/http/Windows"
    )

    do {
        $ftpServer = Read-Host "Ingrese el servidor FTP (por defecto '$DefaultServer')"
        if ([string]::IsNullOrWhiteSpace($ftpServer)) { $ftpServer = $DefaultServer }
        # Probar conexión genérica; se usa un método que no requiere credenciales.
        try {
            $req = [System.Net.FtpWebRequest]::Create("ftp://$ftpServer")
            $req.Method = [System.Net.WebRequestMethods+Ftp]::PrintWorkingDirectory
            $req.Timeout = 5000
            $resp = $req.GetResponse()
            $resp.Close()
            $serverConectado = $true
        }
        catch {
            Write-Host "Error al conectar con el servidor FTP ($ftpServer). Verifique la IP/dominio e intente nuevamente."
            $serverConectado = $false
        }
    } while (-not $serverConectado)

    do {
        $ftpUser = Read-Host "Ingrese el usuario FTP"
        $ftpPassSecure = Read-Host "Ingrese la contraseña FTP" -AsSecureString
        # Convertir contraseña a cadena (ten en cuenta que puede requerir mayor seguridad en producción)
        $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ftpPassSecure)
        $ftpPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
        $cred = New-Object System.Net.NetworkCredential($ftpUser, $ftpPass)
        # Probar autenticación listando el directorio base
        try {
            $baseUri = "ftp://$ftpServer$BaseDir"
            $req = [System.Net.FtpWebRequest]::Create($baseUri)
            $req.Credentials = $cred
            $req.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectory
            $req.Timeout = 5000
            $resp = $req.GetResponse()
            $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
            $listing = $reader.ReadToEnd()
            $reader.Close()
            $resp.Close()
            $authOK = $true
        }
        catch {
            Write-Host "Error de autenticacion. Verifique usuario y contraseña e intente nuevamente."
            $authOK = $false
        }
    } while (-not $authOK)

    return [PSCustomObject]@{
        Server      = $ftpServer
        Credentials = $cred
    }
}

function Invoke-FTPDirectoryListing {
    param (
        [Parameter(Mandatory)]
        [string]$FtpUri,
        [Parameter(Mandatory)]
        [System.Net.NetworkCredential]$Cred
    )
    try {
        $req = [System.Net.FtpWebRequest]::Create($FtpUri)
        $req.Credentials = $Cred
        $req.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectory
        $resp = $req.GetResponse()
        $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $content = $reader.ReadToEnd().Trim()
        $reader.Close()
        $resp.Close()
        return $content -split "\r?\n"
    }
    catch {
        Write-Host "Error al listar $FtpUri : $_"
        return @()
    }
}

function Invoke-FTPDownloadFile {
    param (
        [Parameter(Mandatory)]
        [string]$RemoteUri,
        [Parameter(Mandatory)]
        [string]$LocalPath,
        [Parameter(Mandatory)]
        [System.Net.NetworkCredential]$Cred
    )
    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.Credentials = $Cred
        $webClient.DownloadFile($RemoteUri, $LocalPath)
        Write-Host "Archivo descargado a $LocalPath"
    }
    catch {
        Write-Host "Error al descargar $RemoteUri : $_"
    }
}

function ConnectAndInstallFromFTP {
    # Conectar al FTP y obtener credenciales
    $ftpData = Connect-FTP -DefaultServer "localhost" -BaseDir "/FTPServer/http/Ubuntu"
    $ftpServer = $ftpData.Server
    $cred = $ftpData.Credentials

    # Establecer la ruta base donde se listarán las carpetas.
    # En este ejemplo se asume que las carpetas representan distintos software (por ejemplo, Tomcat, Nginx, Caddy).
    $baseFtpUri = "ftp://$ftpServer/FTPServer/http/"
    $dirList = Invoke-FTPDirectoryListing -FtpUri $baseFtpUri -Cred $cred

    if ($dirList.Count -eq 0) {
        Write-Host "No se encontraron carpetas via FTP en $baseFtpUri"
        return
    }

    Write-Host "`nCarpetas disponibles en $baseFtpUri :"
    for ($i = 0; $i -lt $dirList.Count; $i++) {
        Write-Host "$($i + 1)) $($dirList[$i])"
    }
    $dirChoice = Read-Host "Seleccione el numero de la carpeta a utilizar"
    if (-not ([int]::TryParse($dirChoice, [ref]$null)) -or $dirChoice -lt 1 -or $dirChoice -gt $dirList.Count) {
        Write-Host "Opcion invalida. Abortando."
        return
    }
    $selectedFolder = $dirList[$dirChoice - 1]
    Write-Host "Ha seleccionado: $selectedFolder"

    # Listar archivos dentro de la carpeta seleccionada
    $fileFtpUri = "ftp://$ftpServer/FTPServer/http/$selectedFolder/"
    $fileList = Invoke-FTPDirectoryListing -FtpUri $fileFtpUri -Cred $cred
    if ($fileList.Count -eq 0) {
        Write-Host "No se encontraron archivos en $fileFtpUri"
        return
    }
    Write-Host "nArchivos disponibles en $fileFtpUri :"
    for ($j = 0; $j -lt $fileList.Count; $j++) {
        Write-Host "$($j + 1)) $($fileList[$j])"
    }
    Write-Host "0) TODOS"
    $fileChoice = Read-Host "Seleccione el numero del archivo a descargar (0 para todos)"
    if ($fileChoice -eq "0") {
        $selectedFiles = $fileList
    }
    elseif ([int]::TryParse($fileChoice, [ref]$null) -and $fileChoice -ge 1 -and $fileChoice -le $fileList.Count) {
        $selectedFiles = @($fileList[$fileChoice - 1])
    }
    else {
        Write-Host "Opcion invalida. Abortando."
        return
    }
    Write-Host "Ha seleccionado: $($selectedFiles -join ', ')"

    # Directorio local de descarga
    $destDir = Join-Path -Path $env:USERPROFILE -ChildPath "Downloads"
    if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir | Out-Null }

    foreach ($file in $selectedFiles) {
        $remoteFileUri = "$fileFtpUri$file"
        $localFile = Join-Path -Path $destDir -ChildPath $file
        Write-Host "Descargando $file..."
        Invoke-FTPDownloadFile -RemoteUri $remoteFileUri -LocalPath $localFile -Cred $cred
    }

    # Preguntar si se desea instalar el software descargado
    $installResponse = Read-Host "Desea instalar el software descargado? (s/n)"
    if ($installResponse -match '^(s|S)') {
        switch ($selectedFolder) {
            "Tomcat" {
                $portInput = Read-Host "Ingrese el puerto para Tomcat (por defecto 8080)"
                if ([string]::IsNullOrWhiteSpace($portInput)) { $portInput = 8080 }
                Install-Tomcat -InstallPath "C:\Tomcat" -Port $portInput
            }
            "Nginx" {
                $portInput = Read-Host "Ingrese el puerto para Nginx (por defecto 80)"
                if ([string]::IsNullOrWhiteSpace($portInput)) { $portInput = 80 }
                Install-Nginx -InstallPath "C:\Nginx" -Port $portInput
            }
            Default {
                Write-Host "No hay un proceso de instalacion definido para '$selectedFolder'"
            }
        }
    }
    else {
        Write-Host "Descarga completada sin instalar."
    }
}


function Get-Tomcat-Versions {
    $versions = @{}  # Inicializar el diccionario de versiones
    Write-Host "nObteniendo versiones de Tomcat..."

    try {
        # Definir URLs de Tomcat 10 y 11
        $urls = @{
            "Tomcat 10" = "https://tomcat.apache.org/download-10.cgi"
            "Tomcat 11" = "https://tomcat.apache.org/download-11.cgi"
        }

        # Expresión regular para encontrar la versión y el enlace de descarga
        $regexPattern = 'href="(https://dlcdn\.apache\.org/tomcat/tomcat-(\d+)/v([\d\.]+)/bin/apache-tomcat-[\d\.]+\.zip)"'

        foreach ($tomcat in $urls.Keys) {
            Write-Host "nProcesando $tomcat..."
            $url = $urls[$tomcat]

            # Intentar obtener la página con User-Agent
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing -Headers @{ "User-Agent" = "Mozilla/5.0" } -ErrorAction Stop
            Write-Host ("Codigo de estado HTTP para {0}: {1}" -f $tomcat, $response.StatusCode)

            # Obtener el contenido HTML
            $html = $response.Content

            # Verificar si el contenido está vacío
            if (-not $html) {
                Write-Host "No se obtuvo contenido del sitio web para $tomcat. Puede estar bloqueado o fuera de linea."
                continue
            }

            # Mostrar un fragmento del contenido recibido
            Write-Host "HTML recibido para $tomcat (primeros 500 caracteres):"
            Write-Host ($html.Substring(0, [math]::Min(500, $html.Length)))  # Evita error si el HTML es menor a 500 caracteres

            # Buscar versión de Tomcat
            Write-Host "Buscando la version de $tomcat..."
            $match = [regex]::Match($html, $regexPattern)

            if ($match.Success) {
                $versions["$tomcat LTS"] = @{ Version = $match.Groups[3].Value; Url = $match.Groups[1].Value }
                Write-Host "Version de $tomcat encontrada: $($match.Groups[3].Value)"
                Write-Host "URL de descarga: $($match.Groups[1].Value)"
            }
            else {
                Write-Host "No se encontro la version de $tomcat."
                Write-Host "Puede que la estructura HTML haya cambiado o la expresion regular no sea correcta."
                Write-Host "Mostrando enlaces encontrados:"

                # Extraer todos los enlaces para depuración
                $matches = [regex]::Matches($html, 'href="([^"]+)"')
                foreach ($m in $matches) {
                    Write-Host "$($m.Groups[1].Value)"
                }
            }
        }

        # Validar si se obtuvieron versiones antes de continuar
        if ($versions.Count -eq 0) {
            Write-Host "No se pudieron obtener versiones de Tomcat. Abortando."
            return $null
        }

    }
    catch {
        Write-Host "Error al obtener versiones de Tomcat: $_"
    }

    return $versions  # Retorna el diccionario con las versiones encontradas
}

function Download-Tomcat-Installers {
    param (
        [Parameter(Mandatory)]
        [string]$TargetDir
    )

    if (-not $TargetDir) {
        Write-Host "Debes especificar el directorio de destino."
        return 1
    }
    
    if (-not (Test-Path $TargetDir)) {
        New-Item -ItemType Directory -Path $TargetDir | Out-Null
    }

    # Obtener versiones usando la función que ya tienes
    $versions = Get-Tomcat-Versions
    if (-not $versions) {
        Write-Host "No se pudieron obtener versiones de Tomcat."
        return 1
    }

    foreach ($key in $versions.Keys) {
        $versionInfo = $versions[$key]
        $version = $versionInfo.Version
        $downloadUrl = $versionInfo.Url

        # Definir el nombre del archivo de salida
        $outputFile = Join-Path -Path $TargetDir -ChildPath "apache-tomcat-$version.zip"
        Write-Host "Descargando Tomcat ($key): Versión $version..."
        try {
            Invoke-WebRequest -Uri $downloadUrl -OutFile $outputFile -UseBasicParsing -ErrorAction Stop
            Write-Host "Descarga completada: $outputFile"
        }
        catch {
            Write-Host "Error al descargar Tomcat ($key): $_"
        }
    }
}



function Instalar-Chocolatey {
    Write-Host "Instalando Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}

function Instalar-OpenSSL {
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Instalar-Chocolatey
    }
    $chocoPath = "$env:ProgramData\chocolatey\bin\choco.exe"
    if (Test-Path $chocoPath) {
        Write-Host "Instalando openssl.light via Chocolatey..."
        & $chocoPath install openssl.light -y --no-progress
    }
    else {
        Write-Error "Chocolatey no se instalo correctamente. No se puede continuar."
        return $false
    }
    return $true
}

function Buscar-OpenSSL {
    $candidatos = @(
        "C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
        "C:\Program Files (x86)\OpenSSL-Win32\bin\openssl.exe",
        "C:\ProgramData\chocolatey\lib\openssl.light\tools\openssl.exe",
        "C:\ProgramData\chocolatey\lib\openssl.light\tools\bin\openssl.exe",
        "C:\ProgramData\chocolatey\bin\openssl.exe"
    )
    foreach ($path in $candidatos) {
        if (Test-Path $path) {
            return $path
        }
    }
    return $null
}


function Configurar-SSL-Tomcat {
    param(
        [string]$tomcatPath,
        [int]$sslPort
    )

    try {
        # Ubicación del archivo server.xml de Tomcat
        $serverXml = Join-Path $tomcatPath "conf\server.xml"
        if (-not (Test-Path $serverXml)) {
            Write-Host "No se encontro server.xml en $serverXml para configurar SSL."
            return
        }
        
        # Crear (o asegurar) la carpeta para los certificados SSL
        $sslDir = Join-Path $tomcatPath "conf\ssl"
        if (-not (Test-Path $sslDir)) {
            New-Item -ItemType Directory -Path $sslDir | Out-Null
        }
        
        # Generar certificado autofirmado usando New-SelfSignedCertificate
        Write-Host "Generando certificado autofirmado con New-SelfSignedCertificate..."
        $cert = New-SelfSignedCertificate -DnsName "localhost" -CertStoreLocation "cert:\LocalMachine\My" -NotAfter (Get-Date).AddYears(1)
        
        # Exportar el certificado a formato PKCS12 (.p12) para usarlo en Tomcat
        $pfxPath = Join-Path $sslDir "keystore.p12"
        $password = ConvertTo-SecureString -String "localhost" -Force -AsPlainText
        Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $password
        Write-Host "Certificado exportado a: $pfxPath"
        
        # Leer y limpiar el contenido de server.xml, eliminando cualquier conector SSL previo
        Write-Host "Leyendo y actualizando server.xml..."
        $contenido = Get-Content $serverXml -Raw
        $regexSSL = '(?s)<Connector[^>]SSLEnabled\s=\s*["'']true["''][^>](?:/?>.?<\/Connector>)?'
        $contenidoLimpio = [regex]::Replace($contenido, $regexSSL, '', 'IgnoreCase')
        
        # Definir el bloque de configuración SSL
        $sslConfig = @"
    <Connector port="$sslPort" protocol="org.apache.coyote.http11.Http11NioProtocol"
               maxThreads="150" SSLEnabled="true"
               scheme="https" secure="true" clientAuth="false"
               sslProtocol="TLS">
        <SSLHostConfig>
            <Certificate certificateKeystoreFile="conf/ssl/keystore.p12"
                         certificateKeystorePassword="localhost"
                         certificateKeystoreType="PKCS12" />
        </SSLHostConfig>
    </Connector>
"@
        # Insertar el bloque SSL antes de la etiqueta </Service>
        $nuevoContenido = $contenidoLimpio -replace '(</Service>)', "$sslConfig`n`$1"
        [System.IO.File]::WriteAllText($serverXml, $nuevoContenido, [System.Text.Encoding]::UTF8)
        
        # Crear regla en el firewall para el puerto HTTPS
        New-NetFirewallRule -DisplayName "Tomcat SSL Port $sslPort" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $sslPort -ErrorAction SilentlyContinue
        
        Write-Host "SSL configurado en Tomcat para el puerto $sslPort."
    }
    catch {
        Write-Host "Error al configurar SSL en Tomcat: $_"
    }
}



# ======================================================
# Funciones de Instalación para cada software

function Install-Tomcat-FTP {
     param(
        [int]$puerto
    )
    Write-Host "n=== Instalación de Tomcat ==="
    $tomcatVersions = Get-Tomcat-Versions
    if ($tomcatVersions.Count -eq 0) {
        Write-Host "No se pudieron obtener versiones de Tomcat. Abortando."
        return
    }
    Write-Host "Seleccione la versión a instalar:"
    $opciones = @{}
    $index = 1
    foreach ($key in $tomcatVersions.Keys) {
        $versionInfo = $tomcatVersions[$key]
        Write-Host "$index) $key - Versión: $($versionInfo.Version)"
        $opciones["$index"] = $key
        $index++
    }
    do { $seleccion = Read-Host "Ingrese el número de la versión a instalar (1 o 2)" } until ($opciones.ContainsKey($seleccion))
    $seleccionada = $opciones[$seleccion]
    $seleccionTomcat = $tomcatVersions[$seleccionada]
    Write-Host "Instalando $seleccionada - Versión: $($seleccionTomcat.Version) desde: $($seleccionTomcat.Url)"

    if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
        Write-Host "Java no está instalado. Es necesario para ejecutar Tomcat."
        $respuesta = Read-Host "¿Desea instalar Java automáticamente? (s/n)"
        if ($respuesta -eq "s") { Install-Java } else { Write-Host "Abortando instalación de Tomcat."; return }
        if (-not (Get-Command java -ErrorAction SilentlyContinue)) { Write-Host "Error en la instalación de Java."; return }
    }
    if (-not $env:JAVA_HOME) {
        Write-Host "La variable JAVA_HOME no está configurada. Intentando configurarla..."
        $javaCmd = Get-Command java -ErrorAction SilentlyContinue
        if ($javaCmd) {
            $javaPath = $javaCmd.Source
            $javaHome = Split-Path -Parent (Split-Path $javaPath -Parent)
            $env:JAVA_HOME = $javaHome
            Write-Host "JAVA_HOME configurado en: $env:JAVA_HOME"
        }
        else { Write-Host "No se pudo determinar JAVA_HOME." }
    }
    $tomcatPath = "C:\Tomcat"
    if (Test-Path $tomcatPath) {
        Write-Host "Se encontró una instalación previa de Tomcat en $tomcatPath. Procediendo a reinstalar."
        Remove-Item -Recurse -Force $tomcatPath
    }
    New-Item -ItemType Directory -Force -Path $tomcatPath | Out-Null
    $zipFile = "$env:TEMP\tomcat.zip"
    Write-Host "Descargando Tomcat versión $($seleccionTomcat.Version)..."
    Invoke-WebRequest -Uri $seleccionTomcat.Url -OutFile $zipFile -UseBasicParsing
    Write-Host "Extrayendo archivos..."
    Expand-Archive -Path $zipFile -DestinationPath $tomcatPath -Force
    Remove-Item $zipFile
    $subdirs = Get-ChildItem -Path $tomcatPath | Where-Object { $_.PSIsContainer }
    if ($subdirs.Count -eq 1) {
        Move-Item -Path "$($subdirs[0].FullName)\*" -Destination $tomcatPath -Force
        Remove-Item -Recurse -Force $subdirs[0].FullName
    }
    $serverXml = Join-Path $tomcatPath "conf\server.xml"
    if (Test-Path $serverXml) {
        (Get-Content $serverXml) -replace 'port="8080"', "port=`"$puerto`"" | Set-Content $serverXml
        Write-Host "Puerto HTTP configurado en server.xml a $puerto."
    }
    else { Write-Host "No se encontró server.xml para configurar el puerto HTTP." }
    New-NetFirewallRule -DisplayName "Tomcat HTTP Port $puerto" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $puerto -ErrorAction SilentlyContinue
    $sslRespuesta = Read-Host "¿Desea configurar HTTPS (SSL) para Tomcat? (s/n)"
    if ($sslRespuesta.ToLower() -eq "s") {
        $sslPort = Read-Host "Ingrese el puerto HTTPS para Tomcat (por defecto 8443)"
        if (-not $sslPort) { $sslPort = 8443 }
        Configurar-SSL-Tomcat -tomcatPath $tomcatPath -sslPort $sslPort
    }
    else { Write-Host "Continuando sin HTTPS (SSL) en Tomcat." }
    $startupBat = Join-Path $tomcatPath "bin\startup.bat"
    if (Test-Path $startupBat) {
        Write-Host "Iniciando Tomcat con startup.bat..."
        $env:CATALINA_HOME = $tomcatPath
        Start-Process -FilePath $startupBat -NoNewWindow
        Write-Host "Tomcat iniciado."
    }
    else { Write-Host "No se encontró startup.bat. No se pudo iniciar Tomcat." }
}

# Función para instalar Java automáticamente
function Install-Java {
    # Script para instalar Java JDK en Windows Server 2025 usando Chocolatey

    Write-Host "n=== Instalacion de Java JDK en Windows Server 2025 ==="

    # Asegurar que Chocolatey está instalado
    if (-not (Test-Path "C:\ProgramData\chocolatey")) {
        Write-Host "Chocolatey no esta instalado. Procediendo con la instalacion..."

        # Descargar e instalar Chocolatey
        Set-ExecutionPolicy Bypass -Scope Process -Force
        $chocoInstallScript = "https://community.chocolatey.org/install.ps1"
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString($chocoInstallScript))

        # Verificar instalación de Chocolatey
        if (-not (Test-Path "C:\ProgramData\chocolatey")) {
            Write-Host "Error: No se pudo instalar Chocolatey. Intente manualmente."
            exit 1
        }
        Write-Host "Chocolatey instalado correctamente."
    }
    else {
        Write-Host "Chocolatey ya esta instalado."
    }

    # Asegurar que la variable de entorno de Chocolatey esté disponible
    $env:Path += ";C:\ProgramData\chocolatey\bin"

    # Actualizar Chocolatey
    Write-Host "Actualizando fuentes de Chocolatey..."
    choco upgrade chocolatey -y

    # Verificar si Java ya está instalado
    if (Get-Command java -ErrorAction SilentlyContinue) {
        Write-Host "Java ya esta instalado. Saliendo del script."
        exit 0
    }

    # Instalar Java JDK 17 con Chocolatey
    Write-Host "Instalando Java JDK..."
    choco install openjdk -y
    # Actualizar variables de entorno para que Tomcat detecte Java
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

    # Verificar si Java se instaló correctamente
    if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
        Write-Host "Error: No se pudo instalar Java. Intente manualmente."
        exit 1
    }

   
    # Mostrar versión de Java instalada
    Write-Host "nJava instalado correctamente. Version:"
    java -version

    Write-Host "nInstalacion completada."
}


# Función para configurar SSL en Nginx
function Configurar-SSL-Nginx {
    param (
        [string]$nginxPath,
        [int]$httpPort,
        [int]$sslPort
    )

    function Instalar-Chocolatey {
        Write-Host "Instalando Chocolatey..."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }

    function Instalar-OpenSSL {
        if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
            Instalar-Chocolatey
        }

        $chocoPath = "$env:ProgramData\chocolatey\bin\choco.exe"
        if (Test-Path $chocoPath) {
            & $chocoPath install openssl.light -y --no-progress
        }
        else {
            Write-Error "Chocolatey no se instalo correctamente. No se puede continuar."
            exit 1
        }
    }

    function Buscar-OpenSSL {
        $candidatos = @(
            "C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
            "C:\Program Files (x86)\OpenSSL-Win32\bin\openssl.exe",
            "C:\ProgramData\chocolatey\lib\openssl.light\tools\openssl.exe"
        )

        foreach ($path in $candidatos) {
            if (Test-Path $path) {
                return $path
            }
        }

        $resultado = Get-ChildItem -Path "C:\" -Recurse -Filter "openssl.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($resultado) {
            return $resultado.FullName
        }

        return $null
    }

    try {
        $nginxConfPath = Join-Path $nginxPath "conf\nginx.conf"
        $sslPath = Join-Path $nginxPath "conf\ssl"
        $crtPath = Join-Path $sslPath "localhost.crt"
        $keyPath = Join-Path $sslPath "localhost.key"

        if (-not (Test-Path $nginxConfPath)) {
            Write-Host "No se encontro nginx.conf para configurar SSL."
            return
        }

        # Verificar OpenSSL
        $openssl = Get-Command openssl -ErrorAction SilentlyContinue
        if (-not $openssl) {
            Instalar-OpenSSL
            $openssl = Buscar-OpenSSL
            if (-not $openssl) {
                Write-Error "No se pudo instalar OpenSSL o no se encuentra openssl.exe. Cancela el script."
                return
            }
        }
        else {
            $openssl = "openssl"
        }

        # Crear carpeta SSL si no existe
        if (-not (Test-Path $sslPath)) {
            New-Item -ItemType Directory -Path $sslPath | Out-Null
        }

        # Generar certificado autofirmado
        & $openssl req -x509 -nodes -days 365 -newkey rsa:2048 
            -keyout "$keyPath" 
            -out "$crtPath" 
            -subj "/C=MX/ST=Sinaloa/L=Los Mochis/O=PruebaSSL/CN=localhost"

        # Generar contenido limpio para nginx.conf
        $nginxConfContenido = @"
worker_processes  1;

events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    server {
        listen       $httpPort;
        server_name  localhost;
    }

    server {
        listen       $sslPort ssl;
        server_name  localhost;

        ssl_certificate      C:/nginx/conf/ssl/localhost.crt;
        ssl_certificate_key  C:/nginx/conf/ssl/localhost.key;

        ssl_session_cache    shared:SSL:1m;
        ssl_session_timeout  5m;

        ssl_ciphers  HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers  on;

        location / {
            root   html;
            index  index.html index.htm;
        }
    }
}
"@

        [System.IO.File]::WriteAllText($nginxConfPath, $nginxConfContenido, (New-Object System.Text.UTF8Encoding $false))
        Write-Host "nginx.conf ha sido sobrescrito con configuracion limpia y funcional para SSL."

        # Reglas de firewall
        New-NetFirewallRule -DisplayName "Nginx HTTP $httpPort" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $httpPort -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "Nginx SSL $sslPort" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $sslPort -ErrorAction SilentlyContinue

        Write-Host "SSL configurado en el puerto $sslPort."
    }
    catch {
        Write-Host "Error al configurar SSL en Nginx: $_" 
    }
}


# ============================================================
# Función para obtener versiones de Nginx (estable y mainline)
function Obtener-Nginx-Versions {
    Write-Host "nObteniendo versiones de Nginx..."
    $html = Invoke-WebRequest -Uri "https://nginx.org/en/download.html" -UseBasicParsing
    $matches = [regex]::Matches($html.Content, "nginx-(\d+\.\d+\.\d+)")
    $versionList = @()
    foreach ($m in $matches) {
        $versionList += $m.Groups[1].Value
    }
    $versionList = $versionList | Sort-Object { [System.Version]$_ } -Unique
    if ($versionList.Count -eq 0) {
        Write-Host "ERROR: No se encontraron versiones de Nginx."
        return $null
    }
    $mainline = $versionList[-1]
    $stable = $versionList | Where-Object { $_ -ne $mainline } | Select-Object -Last 1
    if (-not $mainline) { $mainline = "No disponible" }
    return [PSCustomObject]@{
        stable   = $stable
        mainline = $mainline
    }
}


function Download-Nginx-Installers {
    param (
        [Parameter(Mandatory)]
        [string]$NTargetDir
    )

    if (-not $NTargetDir) {
        Write-Host "Debes especificar el directorio de destino."
        return 1
    }

    if (-not (Test-Path $NTargetDir)) {
        New-Item -ItemType Directory -Path $NTargetDir | Out-Null
    }

    # Obtener las versiones utilizando la función proporcionada
    $nginxVersions = Obtener-Nginx-Versions
    if (-not $nginxVersions) {
        Write-Host "No se pudieron obtener versiones de Nginx."
        return 1
    }

    # Descarga versión estable (generalmente mainline o la penúltima)
    $stableDownloadUrl = "https://nginx.org/download/nginx-$($nginxVersions.stable).tar.gz"
    $outputFileStable = Join-Path -Path $NTargetDir -ChildPath "nginx-$($nginxVersions.stable).tar.gz"
    Write-Host "Descargando Nginx estable (v$($nginxVersions.stable))..."
    try {
        Invoke-WebRequest -Uri $stableDownloadUrl -OutFile $outputFileStable -UseBasicParsing -ErrorAction Stop
        Write-Host "Descarga completada: $outputFileStable"
    }
    catch {
        Write-Host "Error al descargar Nginx estable: $_"
    }

    # Descarga versión de desarrollo (mainline)
    $devDownloadUrl = "https://nginx.org/download/nginx-$($nginxVersions.mainline).tar.gz"
    $outputFileDev = Join-Path -Path $NTargetDir -ChildPath "nginx-$($nginxVersions.mainline).tar.gz"
    Write-Host "Descargando Nginx en desarrollo (v$($nginxVersions.mainline))..."
    try {
        Invoke-WebRequest -Uri $devDownloadUrl -OutFile $outputFileDev -UseBasicParsing -ErrorAction Stop
        Write-Host "Descarga completada: $outputFileDev"
    }
    catch {
        Write-Host "Error al descargar Nginx en desarrollo: $_"
}
}


function Install-Nginx-FTP {
     param(
        [int]$puerto
    )
    Write-Host "n=== Instalación de Nginx ==="
    # Preguntar si se desea configurar SSL
    $ssl = Read-Host "¿Desea configurar HTTPS (SSL) para Nginx? (s/n)"
    if ($ssl.ToLower() -eq "s") {
        $sslPort = Read-Host "Ingrese el puerto HTTPS para Nginx (por defecto 9443)"
        if (-not $sslPort) { $sslPort = 9443 }
    }
    else { $ssl = $false }
    
    $versions = Obtener-Nginx-Versions
    if (-not $versions) { return }
    Write-Host "Seleccione la versión a instalar:"
    Write-Host "1) Estable: $($versions.stable)"
    Write-Host "2) Desarrollo (Mainline): $($versions.mainline)"
    $opcion = Read-Host "Ingrese 1 o 2"
    switch ($opcion) {
        "1" { $version = $versions.stable }
        "2" { $version = $versions.mainline }
        default { Write-Host "Opción no válida. Cancelando instalación de Nginx."; return }
    }
    $nginxPath = "C:\nginx"
    $nginxConfPath = "$nginxPath\conf\nginx.conf"
    if (Test-Path $nginxPath) {
        Write-Host "Se encontró una instalación previa de Nginx en $nginxPath. Procediendo a reinstalar."
        Remove-Item -Recurse -Force $nginxPath
    }
    $zipPath = "$env:TEMP\nginx.zip"
    $url = "http://nginx.org/download/nginx-$version.zip"
    Write-Host "Descargando Nginx versión $version desde $url..."
    # Política para omitir certificados (si fuese necesario)
    Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing
    Write-Host "Extrayendo Nginx..."
    Expand-Archive -Path $zipPath -DestinationPath "C:\" -Force
    Remove-Item $zipPath
    $extractedFolder = "C:\nginx-$version"
    if (Test-Path $extractedFolder) {
        Rename-Item -Path $extractedFolder -NewName "nginx"
    }
    else { Write-Host "No se encontró la carpeta extraída de Nginx."; return }
    if (Test-Path $nginxConfPath) {
        (Get-Content $nginxConfPath) -replace "listen\s+80;", "listen       $puerto;" | Set-Content $nginxConfPath
        Write-Host "Puerto configurado en nginx.conf a $puerto."
    }
    else { Write-Host "No se encontró nginx.conf para configurar el puerto." }
    if ($ssl -and $sslPort) { Configurar-SSL-Nginx -nginxPath $nginxPath -httpPort $puerto -sslPort $sslPort }
    Write-Host "Iniciando Nginx..."
    Start-Process -FilePath "$nginxPath\nginx.exe" -WorkingDirectory $nginxPath
    Start-Sleep -Seconds 2
    if (Get-Process -Name nginx -ErrorAction SilentlyContinue) {
        Write-Host "Nginx se está ejecutando en el puerto $puerto."
    }
    else { Write-Host "No se pudo iniciar Nginx." }
    New-NetFirewallRule -DisplayName "Nginx $puerto" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $puerto -ErrorAction SilentlyContinue
    if ($ssl -and $sslPort) {
        New-NetFirewallRule -DisplayName "Nginx SSL $sslPort" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $sslPort -ErrorAction SilentlyContinue
    }
}