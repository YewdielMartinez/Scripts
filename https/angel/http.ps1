# ================================================
# Script para instalar/configurar servicios HTTP
# en Windows: IIS, Tomcat y Nginx.
# ================================================
. .\ftphttp.ps1

# Lista de puertos permitidos en Windows Server 2025
$global:ports_allowed = @(80, 443, 1024, 3000, 5000, 8000, 8080, 8081, 8443, 8888, 9000, 9090)

# Función para solicitar puerto con validaciones y valor por defecto (si se especifica)
function Solicitar-Puerto {
    param (
        [string]$mensaje,
        [int]$defaultPort = $null
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
        if (-not ($global:ports_allowed -contains $port)) {
            Write-Host "El puerto $port no esta en la lista de puertos permitidos: $($global:ports_allowed -join ', ')"
            continue
        }
        
        return $port
    }
}

# Función para preguntar si instalar certificado SSL
function Preguntar-SSL {
    $respuesta = Read-Host "¿Desea configurar SSL para este servicio? (s/n)"
    return ($respuesta -eq "s")
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
        Write-Host "Error al configurar SSL: $_" -ForegroundColor Red
    }
}

# ============================================================
# Función para configurar IIS (instala si es necesario)
function Conf-IIS {
    param (
        [int]$port
    )
    
    # Preguntar si se quiere SSL
    $ssl = Preguntar-SSL
    $sslPort = $null
    
    if ($ssl) {
        $sslPort = Solicitar-Puerto -mensaje "Ingrese el puerto HTTPS para IIS" -defaultPort 443
        if (-not $sslPort) {
            Write-Host "No se configurará SSL."
            $ssl = $false
        }
    }
    
    # Instalar IIS si no está instalado
    if (-not (Get-WindowsFeature -Name Web-Server).Installed) {
        Write-Host "Instalando IIS..."
        Install-WindowsFeature -Name Web-Server -IncludeManagementTools -ErrorAction Stop
    }
    
    # Habilitar el puerto en el firewall
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
    Write-Host "IIS configurado correctamente en el puerto $port." -ForegroundColor Green
    if ($ssl) {
        Write-Host "SSL configurado en el puerto $sslPort." -ForegroundColor Green
    }
}

function Instalar-FTP_IIS {
    $ftpRuta = "C:\inetpub\ftproot\FTPServer\http\IIS"
    $descargaRuta = "C:\Download\IIS"
    $archivo = "Instalar-IIS.ps1"
    $rutaFinal = Join-Path $descargaRuta $archivo
    $rutaEnFTP = Join-Path $ftpRuta $archivo

    # Crear archivo Instalar-IIS.ps1 si no existe en FTP
    if (-not (Test-Path $rutaEnFTP)) {
        Write-Host "Creando script Instalar-IIS.ps1 en el servidor FTP..."

        $contenido = @'
$global:ports_allowed = @(80, 443, 1024, 3000, 5000, 8000, 8080, 8081, 8443, 8888, 9000, 9090)

function Solicitar-Puerto {
    param ([string]$mensaje, [int]$defaultPort = $null)
    while ($true) {
        if ($defaultPort -ne $null) {
            $entrada = Read-Host "$mensaje [Default: $defaultPort]"
        } else {
            $entrada = Read-Host $mensaje
        }

        if ([string]::IsNullOrWhiteSpace($entrada)) {
            if ($defaultPort -ne $null) {
                $port = $defaultPort
                Write-Host "Usando puerto por defecto: $port"
            } else {
                return $null
            }
        } else {
            if ($entrada -match '^\d+$') {
                $port = [int]$entrada
            } else {
                Write-Host "Ingresa un puerto valido (solo numeros)."
                continue
            }
        }

        if (netstat -an | Select-String ":$port\s" | Where-Object { $_ -match "LISTENING" }) {
            Write-Host "El puerto $port ya esta en uso."
            continue
        }

        if (-not ($global:ports_allowed -contains $port)) {
            Write-Host "El puerto $port no esta en la lista permitida: $($global:ports_allowed -join ', ')"
            continue
        }

        return $port
    }
}

function Preguntar-SSL {
    $respuesta = Read-Host "¿Desea configurar SSL para este servicio? (s/n)"
    return ($respuesta -eq "s")
}

function Configurar-SSL-IIS {
    param ([int]$port)
    try {
        Import-Module WebAdministration -ErrorAction Stop
        New-WebBinding -Name "Default Web Site" -Protocol "https" -Port $port -IPAddress "*"
        $cert = New-SelfSignedCertificate -DnsName "localhost" -CertStoreLocation "cert:\LocalMachine\My"
        $binding = Get-WebBinding -Name "Default Web Site" -Protocol "https" -Port $port
        $binding.AddSslCertificate($cert.Thumbprint, "My")
        Write-Host "SSL configurado correctamente en el puerto $port."
    } catch {
        Write-Host "Error al configurar SSL: $_" -ForegroundColor Red
    }
}

function Conf-IIS {
    param ([int]$port)
    $ssl = Preguntar-SSL
    $sslPort = $null

    if ($ssl) {
        $sslPort = Solicitar-Puerto -mensaje "Ingrese el puerto HTTPS para IIS" -defaultPort 443
        if (-not $sslPort) {
            Write-Host "No se configurará SSL."
            $ssl = $false
        }
    }

    if (-not (Get-WindowsFeature -Name Web-Server).Installed) {
        Write-Host "Instalando IIS..."
        Install-WindowsFeature -Name Web-Server -IncludeManagementTools -ErrorAction Stop
    }

    New-NetFirewallRule -DisplayName "IIS Port $port" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port -ErrorAction SilentlyContinue
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    Remove-WebBinding -Name "Default Web Site" -Protocol "http" -Port 80 -ErrorAction SilentlyContinue
    New-WebBinding -Name "Default Web Site" -Protocol "http" -Port $port -IPAddress "*"

    if ($ssl) {
        Configurar-SSL-IIS -port $sslPort
        New-NetFirewallRule -DisplayName "IIS SSL Port $sslPort" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $sslPort -ErrorAction SilentlyContinue
    }

    iisreset | Out-Null
    Write-Host "IIS configurado correctamente en el puerto $port." -ForegroundColor Green
    if ($ssl) {
        Write-Host "SSL configurado en el puerto $sslPort." -ForegroundColor Green
    }
}

# Iniciar proceso
$puerto = Solicitar-Puerto -mensaje "¿En qué puerto desea instalar IIS?" -defaultPort 80
if ($puerto) {
    Conf-IIS -port $puerto
}
'@

        if (-not (Test-Path $ftpRuta)) {
            New-Item -ItemType Directory -Path $ftpRuta -Force | Out-Null
        }

        Set-Content -Path $rutaEnFTP -Value $contenido -Encoding UTF8
        Write-Host "Script generado exitosamente en $rutaEnFTP." -ForegroundColor Green
    }

    # Crear carpeta de destino local
    if (-not (Test-Path $descargaRuta)) {
        New-Item -ItemType Directory -Path $descargaRuta -Force | Out-Null
    }

    # Copiar archivo a descarga local
    Copy-Item -Path $rutaEnFTP -Destination $rutaFinal -Force
    Write-Host "Descarga realizada con éxito: $rutaFinal" -ForegroundColor Green

    # Ejecutar script descargado
    Write-Host "Ejecutando el script para instalar IIS..." -ForegroundColor Yellow
    & $rutaFinal
}

# ============================================================
# Función para verificar e instalar Visual C++ Redistributable (usado por Nginx)
function Dependencias {
    Write-Host "`nVerificando Visual C++ Redistributable..."
    $vcInstalled = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" | 
    Get-ItemProperty | 
    Where-Object { $_.DisplayName -match "Visual C\+\+ (2015|2017|2019|2022) Redistributable" }
    if ($vcInstalled) {
        Write-Host "Visual C++ Redistributable ya está instalado."
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
    Write-Host "`nObteniendo versiones de Apache Tomcat..."

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

            # Obtener el contenido HTML
            $html = $response.Content

            # Verificar si el contenido está vacío
            if (-not $html) {
                Write-Host "No se obtuvo contenido del sitio web para $tomcat. Puede estar bloqueado o fuera de línea." -ForegroundColor Red
                continue
            }

            # Buscar versión de Tomcat
            Write-Host "Buscando la versión de $tomcat..."
            $match = [regex]::Match($html, $regexPattern)

            if ($match.Success) {
                $versions["$tomcat LTS"] = @{ Version = $match.Groups[3].Value; Url = $match.Groups[1].Value }
            }
            else {
                Write-Host "No se encontró la versión de $tomcat."
                Write-Host "Puede que la estructura HTML haya cambiado o la expresión regular no sea correcta."
            }
        }

        # Validar si se obtuvieron versiones antes de continuar
        if ($versions.Count -eq 0) {
            Write-Host "No se pudieron obtener versiones de Tomcat. Abortando."
            return $null
        }

    }
    catch {
        Write-Host "Error al obtener versiones de Tomcat: $_" -ForegroundColor Red
    }

    return $versions  # Retorna el diccionario con las versiones encontradas
}

# Función para configurar SSL en Tomcat
function Configurar-SSL-Tomcat {
    param (
        [string]$tomcatPath,
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
            Write-Error "Chocolatey no se instaló correctamente. No se puede continuar."
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
        $serverXml = Join-Path $tomcatPath "conf\server.xml"
        $sslDir = Join-Path $tomcatPath "conf\ssl"
        $crtPath = Join-Path $sslDir "localhost.crt"
        $keyPath = Join-Path $sslDir "localhost.key"
        $keystorePath = Join-Path $sslDir "keystore.p12"

        if (-not (Test-Path $serverXml)) {
            Write-Host "No se encontró server.xml para configurar SSL." -ForegroundColor Red
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
        if (-not (Test-Path $sslDir)) {
            New-Item -ItemType Directory -Path $sslDir | Out-Null
        }

        # Generar certificado autofirmado
        & $openssl req -x509 -nodes -days 365 -newkey rsa:2048 `
            -keyout "$keyPath" `
            -out "$crtPath" `
            -subj "/C=MX/ST=Sinaloa/L=Los Mochis/O=PruebaSSL/CN=localhost"

        # Generar keystore.p12
        & $openssl pkcs12 -export -in "$crtPath" -inkey "$keyPath" `
            -out "$keystorePath" -name tomcat -passout pass:localhost

        # Leer contenido original
        $contenido = Get-Content $serverXml -Raw

        # Crear bloque SSL actualizado
        $sslConfig = @"
<Connector port="$sslPort" protocol="org.apache.coyote.http11.Http11NioProtocol"
           maxThreads="150" SSLEnabled="true"
           scheme="https" secure="true">
    <SSLHostConfig>
        <Certificate certificateKeystoreFile="conf/ssl/keystore.p12"
                     certificateKeystorePassword="localhost"
                     type="RSA"
                     certificateKeystoreType="PKCS12" />
    </SSLHostConfig>
</Connector>
"@
        

        # Si hay un bloque SSL comentado, lo reemplazamos
        if ($contenido -match '<!--\s*<Connector[^>]+SSLEnabled="true"[\s\S]+?</Connector>\s*-->') {
            $nuevoContenido = $contenido -replace '<!--\s*<Connector[^>]+SSLEnabled="true"[\s\S]+?</Connector>\s*-->', $sslConfig
            Write-Host "Se ha reemplazado el bloque SSL comentado en server.xml." -ForegroundColor Green
        }
        # Si no hay, lo insertamos antes de </Service>
        elseif ($contenido -notmatch 'SSLEnabled\s*=\s*["'']true["'']') {
            $nuevoContenido = $contenido -replace '(<\/Service>)', "$sslConfig`n`$1"
            Write-Host "Se ha agregado el bloque SSL antes de </Service>." -ForegroundColor Green
        }
        else {
            Write-Host "Ya hay un conector SSL habilitado. No se insertó duplicado." -ForegroundColor Yellow
            return
        }

        # Guardar server.xml sin BOM
        [System.IO.File]::WriteAllText($serverXml, $nuevoContenido, (New-Object System.Text.UTF8Encoding $false))

        # Reglas de firewall
        New-NetFirewallRule -DisplayName "Tomcat SSL Port $sslPort" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $sslPort -ErrorAction SilentlyContinue
        Write-Host "SSL configurado en Tomcat para el puerto $sslPort." -ForegroundColor Green
    }
    catch {
        Write-Host "Error al configurar SSL en Tomcat: $_" -ForegroundColor Red
    }
}

# ============================================================
# Función para instalar Apache Tomcat
function Install-Tomcat {
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

    # Obtener las versiones disponibles
    $tomcatVersions = Get-Tomcat-Versions
    if ($tomcatVersions.Count -eq 0) {
        Write-Host "No se pudieron obtener versiones de Tomcat. Abortando."
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

    # Verificar si hay opciones antes de solicitar entrada
    if ($opciones.Count -eq 0) {
        Write-Host "No hay versiones disponibles para instalar. Abortando."
        return
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

    # Descargar Tomcat
    $zipFile = "$env:TEMP\tomcat.zip"
    Write-Host "Descargando Tomcat versión $($seleccionTomcat.Version)..."
    Invoke-WebRequest -Uri $seleccionTomcat.Url -OutFile $zipFile -UseBasicParsing

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

# Función para instalar Java automáticamente
function Install-Java {
    Write-Host "`n=== Instalación de Java JDK en Windows Server 2025 ==="

    # Asegurar que Chocolatey está instalado
    if (-not (Test-Path "C:\ProgramData\chocolatey")) {
        Write-Host "Chocolatey no está instalado. Procediendo con la instalación..."

        # Descargar e instalar Chocolatey
        Set-ExecutionPolicy Bypass -Scope Process -Force
        $chocoInstallScript = "https://community.chocolatey.org/install.ps1"
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString($chocoInstallScript))

        # Verificar instalación de Chocolatey
        if (-not (Test-Path "C:\ProgramData\chocolatey")) {
            Write-Host "Error: No se pudo instalar Chocolatey. Intente manualmente." -ForegroundColor Red
            exit 1
        }
        Write-Host "Chocolatey instalado correctamente."
    }
    else {
        Write-Host "Chocolatey ya está instalado."
    }

    # Asegurar que la variable de entorno de Chocolatey esté disponible
    $env:Path += ";C:\ProgramData\chocolatey\bin"

    # Actualizar Chocolatey
    Write-Host "Actualizando fuentes de Chocolatey..."
    choco upgrade chocolatey -y

    # Instalar Java JDK 17 con Chocolatey
    Write-Host "Instalando Java JDK..."
    choco install openjdk -y
    # Actualizar variables de entorno para que Tomcat detecte Java
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

    # Verificar si Java se instaló correctamente
    if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
        Write-Host "Error: No se pudo instalar Java. Intente manualmente." -ForegroundColor Red
        exit 1
    }

    # Mostrar versión de Java instalada
    Write-Host "`nJava instalado correctamente. Versión:"
    java -version

    Write-Host "`nInstalación completada."
}

function Download-Tomcat {
    param (
        [string]$ftpPath = "C:\inetpub\ftproot\FTPServer\http\Tomcat"
    )
    
    # Definir URLs de las versiones de Tomcat
    $tomcatVersions = @{
        "Tomcat10" = "https://dlcdn.apache.org/tomcat/tomcat-11/v11.0.5/bin/apache-tomcat-11.0.5-windows-x64.zip"
        "Tomcat11" = "https://dlcdn.apache.org/tomcat/tomcat-10/v10.1.39/bin/apache-tomcat-10.1.39-windows-x64.zip"
    }
    
    # Crear la carpeta si no existe
    if (-not (Test-Path $ftpPath)) {
        New-Item -ItemType Directory -Path $ftpPath -Force | Out-Null
        Write-Host "Carpeta creada: $ftpPath"
    }
    
    # Descargar archivos si no existen
    foreach ($version in $tomcatVersions.Keys) {
        $fileName = $tomcatVersions[$version] -split "/" | Select-Object -Last 1
        $filePath = Join-Path $ftpPath $fileName
        
        if (Test-Path $filePath) {
            Write-Host "$fileName ya existe en $ftpPath. Omitiendo descarga."
        }
        else {
            Write-Host "Descargando $fileName..."
            Invoke-WebRequest -Uri $tomcatVersions[$version] -OutFile $filePath -UseBasicParsing
            Write-Host "$fileName descargado correctamente."
        }
    }
    
    Write-Host "Descarga de Tomcat finalizada."
}

function FTPconect {
    # Configuración específica para tu entorno
    $ftpUser = "httpftp"  # Reemplaza con tu usuario FTP real
    $ftpPass = "P@ssw0rd123"  # Reemplaza con tu contraseña FTP real
    $specificPath = "/Tomcat"  # Ruta exacta que me indicaste
    
    # Obtener IP local (versión mejorada para IIS)
    $ipLocal = (Get-NetIPConfiguration | Where-Object {
        $_.IPv4DefaultGateway -ne $null -and 
        $_.NetAdapter.Status -eq "Up" -and
        $_.InterfaceAlias -notlike "*Loopback*"
    }).IPv4Address.IPAddress | Select-Object -First 1

    if (-not $ipLocal) { $ipLocal = "127.0.0.1" }

    try {
        Write-Host "`nConectando a: ftp://${ipLocal}${specificPath}/" -ForegroundColor Cyan
        
        # Configurar conexión FTP
        $ftpRequest = [System.Net.FtpWebRequest]::Create("ftp://${ipLocal}${specificPath}/")
        $ftpRequest.Credentials = New-Object System.Net.NetworkCredential($ftpUser, $ftpPass)
        $ftpRequest.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectoryDetails
        $ftpRequest.UseBinary = $true
        $ftpRequest.UsePassive = $true  # Importante para servidores detrás de firewall/NAT
        $ftpRequest.KeepAlive = $false

        # Obtener respuesta
        $response = $ftpRequest.GetResponse()
        $responseStream = $response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($responseStream)
        
        Write-Host "`nContenido del directorio Tomcat:`n" -ForegroundColor Green
        $fileList = $reader.ReadToEnd()
        
        if ([string]::IsNullOrWhiteSpace($fileList)) {
            Write-Host "El directorio está vacío" -ForegroundColor Yellow
        } else {
            # Formateo mejorado para IIS FTP
            $fileList -split "`r`n" | ForEach-Object {
                if ($_ -match "^(\d{2}-\d{2}-\d{2}\s+\d{2}:\d{2}(?:AM|PM))\s+(<DIR>|\d+)\s+(.+)$") {
                    $type = if ($matches[2] -eq "<DIR>") { "DIR " } else { "FILE" }
                    $size = if ($type -eq "FILE") { "{0,15:N0} bytes" -f [int]$matches[2] } else { "              " }
                    $date = $matches[1]
                    $name = $matches[3]
                    
                    Write-Host ("{0} {1} {2} {3}" -f $type, $date, $size, $name)
                } else {
                    Write-Host $_  # Muestra línea si no coincide con el formato
                }
            }
        }
        
        Write-Host "`nConexión completada exitosamente!" -ForegroundColor Green
    }
    catch [System.Net.WebException] {
        if ($_.Exception.Response.StatusCode -eq 550) {
            Write-Host "`nError 550 - Posibles causas:" -ForegroundColor Red
            Write-Host "1. La ruta '${specificPath}' no existe en el servidor FTP" -ForegroundColor Yellow
            Write-Host "2. El usuario '${ftpUser}' no tiene permisos para esta ruta" -ForegroundColor Yellow
            Write-Host "3. El servicio FTP no está configurado correctamente" -ForegroundColor Yellow
            
            # Verificación adicional
            Write-Host "`nVerificando acceso al directorio raíz..." -ForegroundColor Cyan
            try {
                $rootRequest = [System.Net.FtpWebRequest]::Create("ftp://${ipLocal}/")
                $rootRequest.Credentials = $ftpRequest.Credentials
                $rootRequest.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectoryDetails
                $rootResponse = $rootRequest.GetResponse()
                $rootReader = New-Object System.IO.StreamReader($rootResponse.GetResponseStream())
                
                Write-Host "`nContenido del directorio raíz (/):" -ForegroundColor Green
                $rootReader.ReadToEnd() -split "`r`n" | ForEach-Object { Write-Host "   $_" }
                
                $rootReader.Close()
                $rootResponse.Close()
            }
            catch {
                Write-Host "Error al acceder al directorio raíz: $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            Write-Host "`nError en la conexión FTP: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "`nError inesperado: $($_.Exception.Message)" -ForegroundColor Red
    }
    finally {
        if ($reader) { $reader.Close() }
        if ($response) { $response.Close() }
    }
}

function InstallTomcatFtp {
    param(
        [int]$puerto
    )

    Write-Host "`n=== Instalación de Apache Tomcat desde FTP ==="

    $ssl = Preguntar-SSL
    $sslPort = $null

    if ($ssl) {
        $sslPort = Solicitar-Puerto -mensaje "Ingrese el puerto HTTPS para Tomcat" -defaultPort 8443
        if (-not $sslPort) {
            Write-Host "No se configurará SSL."
            $ssl = $false
        }
    }

    $ftpUser = "httpftp"
    $ftpPass = "P@ssw0rd123"
    $ftpPath = "/Tomcat"
    $ipLocal = (Get-NetIPConfiguration | Where-Object {
        $_.IPv4DefaultGateway -ne $null -and 
        $_.NetAdapter.Status -eq "Up" -and
        $_.InterfaceAlias -notlike "*Loopback*"
    }).IPv4Address.IPAddress | Select-Object -First 1
    if (-not $ipLocal) { $ipLocal = "127.0.0.1" }

    $archivosTomcat = @()
    try {
        $ftpRequest = [System.Net.FtpWebRequest]::Create("ftp://${ipLocal}${ftpPath}/")
        $ftpRequest.Credentials = New-Object System.Net.NetworkCredential($ftpUser, $ftpPass)
        $ftpRequest.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectoryDetails
        $ftpRequest.UseBinary = $true
        $ftpRequest.UsePassive = $true
        $ftpRequest.KeepAlive = $false

        $response = $ftpRequest.GetResponse()
        $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
        $fileList = $reader.ReadToEnd()

        $fileList -split "`r`n" | ForEach-Object {
            if ($_ -match "^(\d{2}-\d{2}-\d{2}\s+\d{2}:\d{2}(?:AM|PM))\s+(<DIR>|\d+)\s+(.+)$") {
                $name = $matches[3]
                $isDir = $matches[2] -eq "<DIR>"
                if (-not $isDir -and $name -match "apache-tomcat.*\.zip") {
                    $version = $name -replace "apache-tomcat-|\.zip",""
                    $archivosTomcat += @{
                        "Nombre" = $name
                        "Version" = $version
                        "RutaFTP" = "${ftpPath}/${name}"
                    }
                }
            }
        }

        $reader.Close()
        $response.Close()
    }
    catch {
        Write-Host "Error al conectar al servidor FTP: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if ($archivosTomcat.Count -eq 0) {
        Write-Host "No se encontraron archivos de Tomcat (.zip) en el servidor FTP." -ForegroundColor Red
        return
    }

    Write-Host "`nVersiones de Tomcat disponibles en el servidor FTP:" -ForegroundColor Green
    $opciones = @{}
    for ($i = 0; $i -lt $archivosTomcat.Count; $i++) {
        $index = $i + 1
        $opciones[$index] = $archivosTomcat[$i]
        Write-Host "$index) $($archivosTomcat[$i].Nombre) - Versión: $($archivosTomcat[$i].Version)"
    }

    do {
        $seleccion = Read-Host "`nIngrese el número de la versión a instalar (o 's' para salir)"
        if ($seleccion -eq 's') {
            Write-Host "Cancelando instalación de Tomcat."
            return
        }
    } while (-not ($seleccion -match "^\d+$" -and [int]$seleccion -ge 1 -and [int]$seleccion -le $archivosTomcat.Count))

    $seleccionada = $opciones[[int]$seleccion]
    $urlFTP = "ftp://${ipLocal}$($seleccionada.RutaFTP)"
    $downloadPath = "C:\Download\Tomcat"

    if (-not (Test-Path $downloadPath)) {
        New-Item -ItemType Directory -Path $downloadPath | Out-Null
    }

    $zipFile = Join-Path $downloadPath $seleccionada.Nombre

    try {
        Write-Host "`nDescargando $($seleccionada.Nombre) desde FTP a $downloadPath..."
        $ftpDownloadRequest = [System.Net.FtpWebRequest]::Create($urlFTP)
        $ftpDownloadRequest.Credentials = New-Object System.Net.NetworkCredential($ftpUser, $ftpPass)
        $ftpDownloadRequest.Method = [System.Net.WebRequestMethods+Ftp]::DownloadFile
        $ftpDownloadRequest.UseBinary = $true
        $ftpDownloadRequest.UsePassive = $true

        $response = $ftpDownloadRequest.GetResponse()
        $responseStream = $response.GetResponseStream()
        $fileStream = [System.IO.File]::Create($zipFile)
        $responseStream.CopyTo($fileStream)

        $fileStream.Close()
        $response.Close()

        Write-Host "Descarga realizada con éxito" -ForegroundColor Green
    }
    catch {
        Write-Host "Error al descargar el archivo desde FTP: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Continuar instalación normalmente
    $tomcatPath = "C:\Tomcat"
    if (Test-Path $tomcatPath) {
        Remove-Item -Recurse -Force $tomcatPath
    }
    New-Item -ItemType Directory -Force -Path $tomcatPath | Out-Null

    Write-Host "Extrayendo archivos..."
    Expand-Archive -Path $zipFile -DestinationPath $tomcatPath -Force

    $subdirs = Get-ChildItem -Path $tomcatPath | Where-Object { $_.PSIsContainer }
    if ($subdirs.Count -eq 1) {
        Move-Item -Path "$($subdirs[0].FullName)\*" -Destination $tomcatPath -Force
        Remove-Item -Recurse -Force $subdirs[0].FullName
    }

    $serverXml = Join-Path $tomcatPath "conf\server.xml"
    if (Test-Path $serverXml) {
        (Get-Content $serverXml) -replace 'port="8080"', "port=`"$puerto`"" | Set-Content $serverXml
        Write-Host "Puerto configurado en server.xml a $puerto."
    }

    if ($ssl) {
        Configurar-SSL-Tomcat -tomcatPath $tomcatPath -sslPort $sslPort
    }

    $startupBat = Join-Path $tomcatPath "bin\startup.bat"
    if (Test-Path $startupBat) {
        Write-Host "Iniciando Tomcat manualmente con startup.bat..."
        $env:CATALINA_HOME = $tomcatPath
        Start-Process -FilePath $startupBat -NoNewWindow
        Write-Host "Tomcat iniciado con startup.bat."
    }

    Write-Host "`nInstalación completada exitosamente!" -ForegroundColor Green
}


function Descargar-Nginx {
    param(
        [string]$ftpPath = "C:\inetpub\ftproot\FTPServer\http\Nginx"
    )
    
    Write-Host "\n=== Descargando Nginx ==="
    
    # Obtener las versiones disponibles
    $nginxVersions = Obtener-Nginx-Versions
    if (-not $nginxVersions) {
        Write-Host "No se pudieron obtener versiones de Nginx. Abortando."
        return
    }
    
    # Crear la carpeta de destino si no existe
    if (-not (Test-Path $ftpPath)) {
        New-Item -ItemType Directory -Path $ftpPath -Force | Out-Null
    }
    
    # Definir URLs de descarga
    $baseUrl = "https://nginx.org/download"
    $stableUrl = "$baseUrl/nginx-$($nginxVersions.stable).zip"
    $mainlineUrl = "$baseUrl/nginx-$($nginxVersions.mainline).zip"
    
    # Definir rutas de guardado
    $stablePath = "$ftpPath\nginx-$($nginxVersions.stable).zip"
    $mainlinePath = "$ftpPath\nginx-$($nginxVersions.mainline).zip"
    
    # Descargar versiones si no existen
    if (-not (Test-Path $stablePath)) {
        Write-Host "Descargando Nginx Stable: $stableUrl"
        Invoke-WebRequest -Uri $stableUrl -OutFile $stablePath -UseBasicParsing
    }
    else {
        Write-Host "Nginx Stable ya existe, omitiendo descarga."
    }
    
    if (-not (Test-Path $mainlinePath)) {
        Write-Host "Descargando Nginx Mainline: $mainlineUrl"
        Invoke-WebRequest -Uri $mainlineUrl -OutFile $mainlinePath -UseBasicParsing
    }
    else {
        Write-Host "Nginx Mainline ya existe, omitiendo descarga."
    }
    
    Write-Host "Descarga de Nginx completada."
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
            Write-Error "Chocolatey no se instaló correctamente. No se puede continuar."
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
            Write-Host "No se encontró nginx.conf para configurar SSL." -ForegroundColor Red
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
        Write-Host "nginx.conf ha sido sobrescrito con configuración limpia y funcional para SSL." -ForegroundColor Green

        # Reglas de firewall
        New-NetFirewallRule -DisplayName "Nginx HTTP $httpPort" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $httpPort -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "Nginx SSL $sslPort" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $sslPort -ErrorAction SilentlyContinue

        Write-Host "SSL configurado en el puerto $sslPort." -ForegroundColor Green
    }
    catch {
        Write-Host "Error al configurar SSL en Nginx: $_" -ForegroundColor Red
    }
}

# ============================================================
# Función para instalar Nginx.
function Install-Nginx {
    param(
        [int]$puerto
    )
    Write-Host "`n=== Instalacion de Nginx ==="
    
    # Preguntar si se quiere SSL
    $ssl = Preguntar-SSL
    $sslPort = $null
    
    if ($ssl) {
        $sslPort = Solicitar-Puerto -mensaje "Ingrese el puerto HTTPS para Nginx" -defaultPort 443
        if (-not $sslPort) {
            Write-Host "No se configurará SSL."
            $ssl = $false
        }
    }
    
    # Obtener versiones de Nginx y seleccionar versión
    $versions = Obtener-Nginx-Versions
    if (-not $versions) { return }
    Write-Host "Seleccione la version a instalar:"
    Write-Host "1) Estable: $($versions.stable)"
    Write-Host "2) Desarrollo (Mainline): $($versions.mainline)"
    $opcion = Read-Host "Ingrese 1 o 2 (o 's' para salir)"
    switch ($opcion) {
        "1" { $version = $versions.stable }
        "2" { $version = $versions.mainline }
        default { Write-Host "Opcion no valida. Cancelando instalacion de Nginx."; return }
    }
    
    $nginxPath = "C:\nginx"
    $nginxConfPath = "$nginxPath\conf\nginx.conf"
    
    # Si ya existe una instalación, se elimina para reinstalar
    if (Test-Path $nginxPath) {
        Write-Host "Se encontro una instalacion previa de Nginx en $nginxPath. Se procedera a reinstalar."
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
        Write-Host "Nginx se esta ejecutando en el puerto $puerto." -ForegroundColor Green
        if ($ssl) {
            Write-Host "SSL configurado en el puerto $sslPort." -ForegroundColor Green
        }
    }
    else {
        Write-Host "No se pudo iniciar Nginx." -ForegroundColor Red
    }
    
    # Agregar regla en el firewall
    New-NetFirewallRule -DisplayName "Nginx $puerto" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $puerto -ErrorAction SilentlyContinue
    if ($ssl) {
        New-NetFirewallRule -DisplayName "Nginx SSL $sslPort" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $sslPort -ErrorAction SilentlyContinue
    }
}

function InstallNginxFTP {
    param(
        [int]$puerto
    )

    Write-Host "`n=== Instalación de Nginx desde FTP ==="

    # Preguntar si se quiere SSL
    $ssl = Preguntar-SSL
    $sslPort = $null
    
    if ($ssl) {
        $sslPort = Solicitar-Puerto -mensaje "Ingrese el puerto HTTPS para Nginx" -defaultPort 443
        if (-not $sslPort) {
            Write-Host "No se configurará SSL."
            $ssl = $false
        }
    }

    # Conexión FTP para obtener archivos disponibles
    $ftpUser = "httpftp"
    $ftpPass = "P@ssw0rd123"
    $ftpPath = "/Nginx"
    $ipLocal = (Get-NetIPConfiguration | Where-Object {
        $_.IPv4DefaultGateway -ne $null -and 
        $_.NetAdapter.Status -eq "Up" -and
        $_.InterfaceAlias -notlike "*Loopback*"
    }).IPv4Address.IPAddress | Select-Object -First 1
    if (-not $ipLocal) { $ipLocal = "127.0.0.1" }

    # Obtener archivos disponibles en el directorio FTP
    $archivosNginx = @()
    try {
        $ftpRequest = [System.Net.FtpWebRequest]::Create("ftp://${ipLocal}${ftpPath}/")
        $ftpRequest.Credentials = New-Object System.Net.NetworkCredential($ftpUser, $ftpPass)
        $ftpRequest.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectoryDetails
        $ftpRequest.UseBinary = $true
        $ftpRequest.UsePassive = $true
        $ftpRequest.KeepAlive = $false

        $response = $ftpRequest.GetResponse()
        $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
        $fileList = $reader.ReadToEnd()
        $reader.Close()
        $response.Close()

        $fileList -split "`r`n" | ForEach-Object {
            if ($_ -match "^(\d{2}-\d{2}-\d{2}\s+\d{2}:\d{2}(?:AM|PM))\s+(<DIR>|\d+)\s+(.+)$") {
                $name = $matches[3]
                $isDir = $matches[2] -eq "<DIR>"
                if (-not $isDir -and $name -match "nginx-.+\.zip") {
                    $version = $name -replace "nginx-|\.zip",""
                    $archivosNginx += @{
                        "Nombre" = $name
                        "Version" = $version
                        "RutaFTP" = "${ftpPath}/${name}"
                    }
                }
            }
        }
    }
    catch {
        Write-Host "Error al conectar al servidor FTP: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if ($archivosNginx.Count -eq 0) {
        Write-Host "No se encontraron archivos de Nginx (.zip) en el servidor FTP." -ForegroundColor Red
        Write-Host "Archivos disponibles en el directorio FTP:" -ForegroundColor Yellow
        $fileList -split "`r`n" | ForEach-Object { Write-Host "   $_" }
        return
    }

    Write-Host "`nVersiones de Nginx disponibles en el servidor FTP:" -ForegroundColor Green
    $opciones = @{}
    for ($i = 0; $i -lt $archivosNginx.Count; $i++) {
        $index = $i + 1
        $opciones[$index] = $archivosNginx[$i]
        Write-Host "$index) $($archivosNginx[$i].Nombre) - Versión: $($archivosNginx[$i].Version)"
    }

    do {
        $seleccion = Read-Host "`nIngrese el número de la versión a instalar (o 's' para salir)"
        if ($seleccion -eq 's') {
            Write-Host "Cancelando instalación de Nginx."
            return
        }
    } while (-not ($seleccion -match "^\d+$" -and [int]$seleccion -ge 1 -and [int]$seleccion -le $archivosNginx.Count))

    $seleccionada = $opciones[[int]$seleccion]
    $urlFTP = "ftp://${ipLocal}$($seleccionada.RutaFTP)"

    Write-Host "`nInstalando $($seleccionada.Nombre) - Versión: $($seleccionada.Version)" -ForegroundColor Cyan

    # Ruta de descarga y descompresión
    $downloadPath = "C:\Download\Nginx"
    $zipFile = Join-Path $downloadPath "nginx.zip"
    $nginxPath = "C:\nginx"
    $nginxConfPath = "$nginxPath\conf\nginx.conf"

    # Crear carpeta de descarga si no existe
    if (-not (Test-Path $downloadPath)) {
        New-Item -Path $downloadPath -ItemType Directory | Out-Null
    }

    # Eliminar instalación anterior
    if (Test-Path $nginxPath) {
        Write-Host "Eliminando instalación previa de Nginx en $nginxPath..."
        try {
            Stop-Process -Name nginx -Force -ErrorAction SilentlyContinue
            Remove-Item -Recurse -Force $nginxPath
        }
        catch {
            Write-Host "Error al eliminar instalación previa: $_" -ForegroundColor Yellow
        }
    }

    # Descargar desde FTP
    try {
        Write-Host "Descargando $($seleccionada.Nombre) desde FTP..."
        $ftpDownloadRequest = [System.Net.FtpWebRequest]::Create($urlFTP)
        $ftpDownloadRequest.Credentials = New-Object System.Net.NetworkCredential($ftpUser, $ftpPass)
        $ftpDownloadRequest.Method = [System.Net.WebRequestMethods+Ftp]::DownloadFile
        $ftpDownloadRequest.UseBinary = $true
        $ftpDownloadRequest.UsePassive = $true

        $response = $ftpDownloadRequest.GetResponse()
        $responseStream = $response.GetResponseStream()
        $fileStream = [System.IO.File]::Create($zipFile)
        $responseStream.CopyTo($fileStream)

        $fileStream.Close()
        $response.Close()

        Write-Host "Descarga realizada con éxito." -ForegroundColor Green
    }
    catch {
        Write-Host "Error al descargar el archivo desde FTP: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Extraer archivos
    try {
        Write-Host "Extrayendo Nginx..."
        Expand-Archive -Path $zipFile -DestinationPath "C:\" -Force
        Remove-Item $zipFile -ErrorAction SilentlyContinue

        $extractedFolder = "C:\nginx-$($seleccionada.Version)"
        if (Test-Path $extractedFolder) {
            Rename-Item -Path $extractedFolder -NewName "nginx" -Force
        } else {
            $nginxFolders = Get-ChildItem -Path "C:\" -Directory | Where-Object { $_.Name -like "nginx-*" }
            if ($nginxFolders.Count -eq 1) {
                Rename-Item -Path $nginxFolders[0].FullName -NewName "nginx" -Force
            } else {
                Write-Host "No se pudo determinar la carpeta extraída de Nginx." -ForegroundColor Red
                return
            }
        }
    }
    catch {
        Write-Host "Error al extraer archivos: $_" -ForegroundColor Red
        return
    }

    # Configuración del puerto
    if (Test-Path $nginxConfPath) {
        try {
            (Get-Content $nginxConfPath) -replace "listen\s+80;", "listen       $puerto;" | Set-Content $nginxConfPath
            Write-Host "Puerto configurado en nginx.conf a $puerto." -ForegroundColor Green
        }
        catch {
            Write-Host "Error al modificar nginx.conf: $_" -ForegroundColor Yellow
        }
    }

    # Configurar SSL si se solicitó
    if ($ssl) {
        Configurar-SSL-Nginx -nginxPath $nginxPath -httpPort $puerto -sslPort $sslPort
    }

    # Iniciar Nginx
    try {
        Write-Host "Iniciando Nginx..."
        Start-Process -FilePath "$nginxPath\nginx.exe" -WorkingDirectory $nginxPath
        Start-Sleep -Seconds 2

        if (Get-Process -Name nginx -ErrorAction SilentlyContinue) {
            Write-Host "Nginx se está ejecutando en el puerto $puerto." -ForegroundColor Green
            if ($ssl) {
                Write-Host "SSL configurado en el puerto $sslPort." -ForegroundColor Green
            }

            # Reglas de firewall
            try {
                New-NetFirewallRule -DisplayName "Nginx HTTP $puerto" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $puerto -ErrorAction SilentlyContinue
                if ($ssl) {
                    New-NetFirewallRule -DisplayName "Nginx HTTPS $sslPort" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $sslPort -ErrorAction SilentlyContinue
                }
                Write-Host "Reglas de firewall agregadas." -ForegroundColor Green
            }
            catch {
                Write-Host "Advertencia: No se pudieron agregar reglas de firewall." -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "No se pudo iniciar Nginx. Verifique los logs en $nginxPath\logs\error.log" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "Error al iniciar Nginx: $_" -ForegroundColor Red
    }

    Write-Host "`nInstalación completada!" -ForegroundColor Green
}


# ============================================================
# Función para mostrar el menú principal
function configureHttp {
    function Menu-HTTP {
        Write-Host "`n==================================="
        Write-Host "        Menu de Instalacion        "
        Write-Host "==================================="
        Write-Host "1) IIS"
        Write-Host "2) Tomcat"
        Write-Host "3) Nginx"
        Write-Host "4) Salir"
    }

    function Solicitar-MetodoInstalacion {
        Write-Host "`nSeleccione el método de instalación:"
        Write-Host "1) HTTP"
        Write-Host "2) FTP"
        $opcion = Read-Host "Seleccione una opcion (1-2)"
        return $opcion
    }

    # ============================================================
    # Bucle principal del menú
    while ($true) {
        Menu-HTTP
        $opcion = Read-Host "Seleccione una opcion (1-4)"
        
        switch ($opcion) {
            "1" {
                $metodo = Solicitar-MetodoInstalacion
                $puerto = Solicitar-Puerto -mensaje "Ingrese el puerto para IIS" -defaultPort 80
                
                if ($puerto) {
                    if ($metodo -eq "1") {
                        Conf-IIS -port $puerto
                    }
                    elseif ($metodo -eq "2") {
                        Instalar-FTP_IIS 

                    }
                    else {
                        Write-Host "Opción no válida."
                    }
                }
            }
            "2" {
                $metodo = Solicitar-MetodoInstalacion
                $puerto = Solicitar-Puerto -mensaje "Ingrese el puerto para Tomcat" -defaultPort 8080
                
                if ($puerto) {
                    if ($metodo -eq "1") {
                        Install-Tomcat -puerto $puerto
                    }
                    elseif ($metodo -eq "2") {
                        Install-Tomcat-FTP -puerto $puerto
                    }
                    else {
                        Write-Host "Opción no válida."
                    }
                }
            }
            "3" { 
                $metodo = Solicitar-MetodoInstalacion
                $puerto = Solicitar-Puerto -mensaje "Ingrese el puerto para Nginx" -defaultPort 80
                
                if ($puerto) {
                    if ($metodo -eq "1") {
                        Dependencias
                        Install-Nginx -puerto $puerto
                    }
                    elseif ($metodo -eq "2") {
                        Dependencias
                        Install-Nginx-FTP -puerto $puerto
                    }
                    else {
                        Write-Host "Opción no válida."
                    }
                }
            }
            "4" {
                Write-Host "Saliendo..."
                return
            }
            default { Write-Host "Opcion no válida. Intente nuevamente." }
        }
        Write-Host "`nPresione Enter para continuar..."
        Read-Host
    }
}