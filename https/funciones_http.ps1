# Lista de puertos permitidos en Windows Server 2025.
$global:ports_allowed = @(80, 1024, 3000, 5000, 8000, 8080, 8081, 8888, 9000, 9090)
$global:ports_https_allowed = @(443, 8443, 9443)


# Función para solicitar puerto con validaciones, valor por defecto y lista de puertos permitidos
function Solicitar-Puerto {
    param (
        [string]$mensaje,
        [int]$defaultPort = $null,
        [int[]]$allowedPorts = $global:ports_allowed
    )
    
    while ($true) {
        if ($defaultPort -ne $null) {
            $entrada = Read-Host "$mensaje [Default: $defaultPort]"
        }
        else {
            $entrada = Read-Host $mensaje
        }
        
        if ([string]::IsNullOrWhiteSpace($entrada)) {
            if ($defaultPort -ne $null) {
                $port = $defaultPort
                Write-Host "Usando puerto por defecto: $port"
            }
            else {
                return $null
            }
        }
        else {
            if ($entrada -match '^\d+$') {
                $port = [int]$entrada
            }
            else {
                Write-Host "Ingresa un puerto valido (solo numeros)."
                continue
            }
        }
        
        # Verificar si el puerto está en uso (buscando en netstat)
        if (netstat -an | Select-String ":$port\s" | Where-Object { $_ -match "LISTENING" }) {
            Write-Host "El puerto $port ya esta en uso."
            continue
        }
        
        # Verificar que el puerto esté en la lista de puertos permitidos
        if (-not ($allowedPorts -contains $port)) {
            Write-Host "El puerto $port no esta en la lista de puertos permitidos: $($allowedPorts -join ', ')"
            continue
        }
        
        return $port
    }
}

function Preguntar-SSL {
    $respuesta = Read-Host "Desea configurar SSL para este servicio? ('S' para 'Si', 'N' o cualquier otra cosa para 'No')"
    return ($respuesta.ToLower() -eq "s")
}

# Función para configurar SSL en IIS
function Configurar-SSL-IIS {
    param (
        [int]$port
    )
    
    try {
        # Verificar si el módulo de IIS está disponible
        Import-Module WebAdministration -ErrorAction Stop
        
        # Crear binding HTTPS
        New-WebBinding -Name "Default Web Site" -Protocol "https" -Port $port -IPAddress "*"
        
        # Crear certificado autofirmado (esto es solo para pruebas)
        $cert = New-SelfSignedCertificate -DnsName "localhost" -CertStoreLocation "cert:\LocalMachine\My"
        
        # Asociar certificado al binding
        $binding = Get-WebBinding -Name "Default Web Site" -Protocol "https" -Port $port
        $binding.AddSslCertificate($cert.Thumbprint, "My")
        
        Write-Host "SSL configurado correctamente en el puerto $port."
    }
    catch {
        Write-Host "Error al configurar SSL: $_"
    }
}


# ============================================================
# Función para configurar IIS (instala si es necesario)
function Conf-IIS {
    param (
        [int]$port
    )

	Write-Host "`n=== Instalacion/Configuracion de IIS ==="

    # Preguntar si se quiere SSL
    $ssl = Preguntar-SSL
    $sslPort = $null

    if ($ssl) {
        $sslPort = Solicitar-Puerto -mensaje "Ingrese el puerto HTTPS para IIS" -defaultPort 443 -allowedPorts $global:ports_https_allowed
        if (-not $sslPort) {
            Write-Host "No se configurara SSL."
            $ssl = $false
        }
    }

    # Install IIS si no está instalado
    if (-not (Get-WindowsFeature -Name Web-Server).Installed) {
        Write-Host "Instalando IIS..."
        Install-WindowsFeature -Name Web-Server -IncludeManagementTools -ErrorAction Stop
    }

    # Habilitar el puerto en el firewall para HTTP
    New-NetFirewallRule -DisplayName "IIS Port $port" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port -ErrorAction SilentlyContinue

    # Importar módulo de administración de IIS
    Import-Module WebAdministration -ErrorAction SilentlyContinue

    # Remover binding en el puerto 80 (si existe) y agregar uno nuevo en el puerto elegido
    Remove-WebBinding -Name "Default Web Site" -Protocol "http" -Port 80 -ErrorAction SilentlyContinue
    New-WebBinding -Name "Default Web Site" -Protocol "http" -Port $port -IPAddress "*"

    # Configurar SSL si se solicitó
    if ($ssl) {
        Configurar-SSL-IIS -port $sslPort
        New-NetFirewallRule -DisplayName "IIS SSL Port $sslPort" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $sslPort -ErrorAction SilentlyContinue
    }

    # Reiniciar IIS para aplicar cambios
    iisreset | Out-Null
    Write-Host "IIS configurado correctamente en el puerto $port."
    if ($ssl) {
        Write-Host "SSL configurado en el puerto $sslPort."
    }
}


# ============================================================
# Función para verificar e Install Visual C++ Redistributable (usado por Nginx)
function Dependencias {
    Write-Host "`nVerificando Visual C++ Redistributable..."
    $vcInstalled = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" | 
    Get-ItemProperty | 
    Where-Object { $_.DisplayName -match "Visual C\+\+ (2015|2017|2019|2022) Redistributable" }
    if ($vcInstalled) {
        Write-Host "Visual C++ Redistributable ya esta instalado."
    }
    else {
        Write-Host "Falta Visual C++. Descargando e instalando..."
        $vcUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
        $vcInstaller = "$env:TEMP\vc_redist.x64.exe"
        Invoke-WebRequest -Uri $vcUrl -OutFile $vcInstaller -UseBasicParsing
        Start-Process -FilePath $vcInstaller -ArgumentList "/install /quiet /norestart" -NoNewWindow -Wait
        Write-Host "Visual C++ Redistributable instalado correctamente."
    }
}


# ============================================================
function Get-Tomcat-Versions {
    $versions = @{}  # Inicializar el diccionario de versiones
    Write-Host "`nObteniendo versiones de Tomcat..."

    try {
        # Definir URLs de Tomcat 10 y 11
        $urls = @{
            "Tomcat 10" = "https://tomcat.apache.org/download-10.cgi"
            "Tomcat 11" = "https://tomcat.apache.org/download-11.cgi"
        }

        # Expresión regular para encontrar la versión y el enlace de descarga
        $regexPattern = 'href="(https://dlcdn\.apache\.org/tomcat/tomcat-(\d+)/v([\d\.]+)/bin/apache-tomcat-[\d\.]+\.zip)"'

        foreach ($tomcat in $urls.Keys) {
            Write-Host "`nProcesando $tomcat..."
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


function Install-Chocolatey {
    Write-Host "Instalando Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}

function Install-OpenSSL {
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Install-Chocolatey
    }
    $chocoPath = "$env:ProgramData\chocolatey\bin\choco.exe"
    if (Test-Path $chocoPath) {
        Write-Host "Instalando openssl.light via Chocolatey..."
        & $chocoPath install openssl.light -y --no-progress
    }
    else {
        Write-Error "Chocolatey no se instaló correctamente. No se puede continuar."
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


# ============================================================
# Función para Install Tomcat con opción de HTTPS
function Install-Tomcat {
    param(
        [int]$puerto
    )

    Write-Host "`n=== Instalacion de Tomcat ==="

    # Obtener las versiones disponibles (función previamente definida)
    $tomcatVersions = Get-Tomcat-Versions
    if ($tomcatVersions.Count -eq 0) {
        Write-Host "No se pudieron obtener versiones de Tomcat. Abortando."
        return
    }

    Write-Host "Seleccione la version a Install:"
    $opciones = @{}
    $index = 1
    foreach ($key in $tomcatVersions.Keys) {
        $versionInfo = $tomcatVersions[$key]
        Write-Host "$index) $key - Version: $($versionInfo.Version)"
        $opciones["$index"] = $key
        $index++
    }

    do {
        $seleccion = Read-Host "Ingrese el número de la versión a Install (1 o 2)"
    } while (-not $opciones.ContainsKey($seleccion))

    $seleccionada = $opciones[$seleccion]
    $seleccionTomcat = $tomcatVersions[$seleccionada]

    Write-Host "Instalando $seleccionada - Version: $($seleccionTomcat.Version) desde: $($seleccionTomcat.Url)"

    # Verificar que Java esté instalado (si no, se invoca Install-Java)
    if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
        Write-Host "Java no esta instalado. Es necesario para ejecutar Tomcat."
        $respuesta = Read-Host "¿Desea Install Java automáticamente? (s/n)"
        if ($respuesta -eq "s") {
            Install-Java
        }
        else {
            Write-Host "No se puede continuar sin Java. Abortando instalacion de Tomcat."
            return
        }
        if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
            Write-Host "Hubo un error instalando Java. Intentelo manualmente."
            return
        }
    }

    # Configurar JAVA_HOME si no está definida
    if (-not $env:JAVA_HOME) {
        Write-Host "La variable JAVA_HOME no esta configurada. Intentando configurarla..."
        $javaCmd = Get-Command java -ErrorAction SilentlyContinue
        if ($javaCmd) {
            $javaPath = $javaCmd.Source
            $javaHome = Split-Path -Parent (Split-Path $javaPath -Parent)
            $env:JAVA_HOME = $javaHome
            Write-Host "JAVA_HOME configurado en: $env:JAVA_HOME"
        }
        else {
            Write-Host "No se pudo determinar JAVA_HOME."
        }
    }

    # Definir ruta de instalación de Tomcat
    $tomcatPath = "C:\Tomcat"
    if (Test-Path $tomcatPath) {
        Write-Host "Se encontro una instalación previa de Tomcat en $tomcatPath. Se procedera a reInstall."
        Remove-Item -Recurse -Force $tomcatPath
    }
    New-Item -ItemType Directory -Force -Path $tomcatPath | Out-Null

    # Descargar Tomcat
    $zipFile = "$env:TEMP\tomcat.zip"
    Write-Host "Descargando Tomcat version $($seleccionTomcat.Version)..."
    Invoke-WebRequest -Uri $seleccionTomcat.Url -OutFile $zipFile -UseBasicParsing

    # Extraer archivos
    Write-Host "Extrayendo archivos..."
    Expand-Archive -Path $zipFile -DestinationPath $tomcatPath -Force
    Remove-Item $zipFile

    # Mover archivos en caso de que el ZIP contenga un subdirectorio
    $subdirs = Get-ChildItem -Path $tomcatPath | Where-Object { $_.PSIsContainer }
    if ($subdirs.Count -eq 1) {
        Move-Item -Path "$($subdirs[0].FullName)\*" -Destination $tomcatPath -Force
        Remove-Item -Recurse -Force $subdirs[0].FullName
    }

    # Modificar server.xml para actualizar el puerto HTTP
    $serverXml = Join-Path $tomcatPath "conf\server.xml"
    if (Test-Path $serverXml) {
        (Get-Content $serverXml) -replace 'port="8080"', "port=`"$puerto`"" | Set-Content $serverXml
        Write-Host "Puerto HTTP configurado en server.xml a $puerto."
    }
    else {
        Write-Host "No se encontro server.xml para configurar el puerto HTTP."
    }

    # Agregar regla en el firewall para el puerto HTTP
    New-NetFirewallRule -DisplayName "Tomcat HTTP Port $puerto" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $puerto -ErrorAction SilentlyContinue

    # Preguntar si se desea configurar HTTPS (SSL)
    $sslRespuesta = Read-Host "¿Desea configurar HTTPS (SSL) para Tomcat? (s/n)"
    if ($sslRespuesta.ToLower() -eq "s") {
        $sslPort = Read-Host "Ingrese el puerto HTTPS para Tomcat (por defecto 8443)"
        if (-not $sslPort) { $sslPort = 8443 }
        Configurar-SSL-Tomcat -tomcatPath $tomcatPath -sslPort $sslPort
    }
    else {
        Write-Host "Se continuara sin HTTPS (SSL) en Tomcat."
    }

    # Iniciar Tomcat mediante startup.bat
    $startupBat = Join-Path $tomcatPath "bin\startup.bat"
    if (Test-Path $startupBat) {
        Write-Host "Iniciando Tomcat manualmente con startup.bat..."
        $env:CATALINA_HOME = $tomcatPath
        Start-Process -FilePath $startupBat -NoNewWindow
        Write-Host "Tomcat iniciado con startup.bat."
    }
    else {
        Write-Host "No se encontro startup.bat. No se pudo iniciar Tomcat."
    }
}


# Función para Install Java automáticamente
function Install-Java {
    # Script para Install Java JDK en Windows Server 2025 usando Chocolatey

    Write-Host "`n=== Instalacion de Java JDK en Windows Server 2025 ==="

    # Asegurar que Chocolatey está instalado
    if (-not (Test-Path "C:\ProgramData\chocolatey")) {
        Write-Host "Chocolatey no esta instalado. Procediendo con la instalacion..."

        # Descargar e Install Chocolatey
        Set-ExecutionPolicy Bypass -Scope Process -Force
        $chocoInstallScript = "https://community.chocolatey.org/install.ps1"
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString($chocoInstallScript))

        # Verificar instalación de Chocolatey
        if (-not (Test-Path "C:\ProgramData\chocolatey")) {
            Write-Host "Error: No se pudo Install Chocolatey. Intente manualmente."
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

    # Install Java JDK 17 con Chocolatey
    Write-Host "Instalando Java JDK..."
    choco install openjdk -y
    # Actualizar variables de entorno para que Tomcat detecte Java
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

    # Verificar si Java se instaló correctamente
    if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
        Write-Host "Error: No se pudo Install Java. Intente manualmente."
        exit 1
    }

   
    # Mostrar versión de Java instalada
    Write-Host "`nJava instalado correctamente. Version:"
    java -version

    Write-Host "`nInstalacion completada."
}

# Función para configurar SSL en Nginx
function Configurar-SSL-Nginx {
    param (
        [string]$nginxPath,
        [int]$httpPort,
        [int]$sslPort
    )

    function Install-Chocolatey {
        Write-Host "Instalando Chocolatey..."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }

    function Install-OpenSSL {
        if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
            Install-Chocolatey
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
            Install-OpenSSL
            $openssl = Buscar-OpenSSL
            if (-not $openssl) {
                Write-Error "No se pudo Install OpenSSL o no se encuentra openssl.exe. Cancela el script."
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
        & $openssl req -x509 -nodes -days 365 -newkey rsa:2048 `
            -keyout "$keyPath" `
            -out "$crtPath" `
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
    Write-Host "`nObteniendo versiones de Nginx..."
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

# ============================================================
# Función para Install Nginx.
# Se ha modificado para solicitar el puerto primero (se recibe como parámetro)
function Install-Nginx {
    param(
        [int]$puerto
    )
    Write-Host "`n=== Instalacion de Nginx ==="

    # Preguntar si se quiere SSL
    $ssl = Preguntar-SSL
    $sslPort = $null
    
    
    
    # Obtener versiones de Nginx y seleccionar versión
    $versions = Obtener-Nginx-Versions
    if (-not $versions) { return }
    Write-Host "Seleccione la version a Install:"
    Write-Host "1) Estable: $($versions.stable)"
    Write-Host "2) Desarrollo (Mainline): $($versions.mainline)"
    $opcion = Read-Host "Ingrese 1 o 2"
    switch ($opcion) {
        "1" { $version = $versions.stable }
        "2" { $version = $versions.mainline }
        default { Write-Host "Opcion no valida. Cancelando instalacion de Nginx."; return }
    }
    
    $nginxPath = "C:\nginx"
    $nginxConfPath = "$nginxPath\conf\nginx.conf"

if ($ssl) {
        $sslPort = Solicitar-Puerto -mensaje "Ingrese el puerto HTTPS para Nginx" -defaultPort 9443 -allowedPorts $global:ports_https_allowed

        if (-not $sslPort) {
            Write-Host "No se configurara SSL."
            $ssl = $false
        }
    }

    
    # Si ya existe una instalación, se elimina para reInstall
    if (Test-Path $nginxPath) {
        Write-Host "Se encontro una instalacion previa de Nginx en $nginxPath. Se procedera a reInstall."
        Remove-Item -Recurse -Force $nginxPath
    }
    
    $zipPath = "$env:TEMP\nginx.zip"
    $url = "http://nginx.org/download/nginx-$version.zip"
    Write-Host "Descargando Nginx version $version desde $url..."
    
    # Agregar política para certificados (para evitar problemas en la descarga)
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
    
    # La carpeta extraída suele llamarse "nginx-[version]"; renombrarla a "nginx"
    $extractedFolder = "C:\nginx-$version"
    if (Test-Path $extractedFolder) {
        Rename-Item -Path $extractedFolder -NewName "nginx"
    }
    else {
        Write-Host "No se encontro la carpeta extraida de Nginx."
        return
    }
    
    # Actualizar el archivo de configuración (nginx.conf) para usar el puerto especificado
    if (Test-Path $nginxConfPath) {
        (Get-Content $nginxConfPath) -replace "listen\s+80;", "listen       $puerto;" | Set-Content $nginxConfPath
        Write-Host "Puerto configurado en nginx.conf a $puerto."
    }
    else {
        Write-Host "No se encontro nginx.conf para configurar el puerto."
    }

# Configurar SSL si se solicitó
    if ($ssl) {
        Configurar-SSL-Nginx -nginxPath $nginxPath -httpPort $puerto -sslPort $sslPort
    }
    
    # Iniciar Nginx
    Write-Host "Iniciando Nginx..."
    Start-Process -FilePath "$nginxPath\nginx.exe" -WorkingDirectory $nginxPath
    Start-Sleep -Seconds 2
    if (Get-Process -Name nginx -ErrorAction SilentlyContinue) {
        Write-Host "Nginx se esta ejecutando en el puerto $puerto."
    }
    else {
        Write-Host "No se pudo iniciar Nginx."
    }
    
    # Agregar regla en el firewall
    New-NetFirewallRule -DisplayName "Nginx $puerto" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $puerto -ErrorAction SilentlyContinue
    if ($ssl) {
        New-NetFirewallRule -DisplayName "Nginx SSL $sslPort" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $sslPort -ErrorAction SilentlyContinue
    }
}