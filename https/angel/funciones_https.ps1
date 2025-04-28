# ================================================
# Script para instalar/configurar servicios HTTP
# en Windows: IIS, Tomcat y Nginx.
# ================================================

# Lista de puertos permitidos en Windows Server 2025
$global:ports_allowed = @(80, 1024, 3000, 5000, 8000, 8080, 8081, 8443, 8888, 9000, 9090)

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

# ============================================================
# Función para configurar IIS (instala si es necesario)
function Conf-IIS {
    Write-Host "`n=== Configurando IIS con puertos fijos ==="
    Write-Host "HTTP: $($global:ports_config.IIS_HTTP), HTTPS: $($global:ports_config.IIS_HTTPS)"
    
    # Verificar puertos
    if (Test-PortInUse $global:ports_config.IIS_HTTP) {
        Write-Host "ERROR: El puerto HTTP $($global:ports_config.IIS_HTTP) está en uso" -ForegroundColor Red
        return
    }
    if (Test-PortInUse $global:ports_config.IIS_HTTPS) {
        Write-Host "ERROR: El puerto HTTPS $($global:ports_config.IIS_HTTPS) está en uso" -ForegroundColor Red
        return
    }

    # Instalar IIS si no está instalado
    if (-not (Get-WindowsFeature -Name Web-Server).Installed) {
        Write-Host "Instalando IIS..."
        Install-WindowsFeature -Name Web-Server -IncludeManagementTools -ErrorAction Stop
    }

    # Configurar bindings HTTP
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    
    # Eliminar bindings por defecto
    Remove-WebBinding -Name "Default Web Site" -Protocol "http" -Port 80 -ErrorAction SilentlyContinue
    Remove-WebBinding -Name "Default Web Site" -Protocol "https" -Port 443 -ErrorAction SilentlyContinue
    
    # Crear nuevos bindings
    New-WebBinding -Name "Default Web Site" -Protocol "http" -Port $global:ports_config.IIS_HTTP -IPAddress "*"
    New-WebBinding -Name "Default Web Site" -Protocol "https" -Port $global:ports_config.IIS_HTTPS -IPAddress "*"
    
    # Configurar certificado SSL
    $cert = New-SelfSignedCertificate -DnsName "localhost" -CertStoreLocation "cert:\LocalMachine\My"
    $binding = Get-WebBinding -Name "Default Web Site" -Protocol "https" -Port $global:ports_config.IIS_HTTPS
    $binding.AddSslCertificate($cert.Thumbprint, "My")

    # Configurar firewall
    New-NetFirewallRule -DisplayName "IIS HTTP $($global:ports_config.IIS_HTTP)" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $global:ports_config.IIS_HTTP
    New-NetFirewallRule -DisplayName "IIS HTTPS $($global:ports_config.IIS_HTTPS)" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $global:ports_config.IIS_HTTPS

    # Reiniciar IIS
    iisreset | Out-Null
    
    Write-Host "IIS configurado correctamente:" -ForegroundColor Green
    Write-Host " - HTTP disponible en: http://localhost:$($global:ports_config.IIS_HTTP)" -ForegroundColor Cyan
    Write-Host " - HTTPS disponible en: https://localhost:$($global:ports_config.IIS_HTTPS)" -ForegroundColor Cyan
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
            # Write-Host ("Código de estado HTTP para {0}: {1}" -f $tomcat, $response.StatusCode)

            # Obtener el contenido HTML
            $html = $response.Content

            # Verificar si el contenido está vacío
            if (-not $html) {
                Write-Host "No se obtuvo contenido del sitio web para $tomcat. Puede estar bloqueado o fuera de línea." -ForegroundColor Red
                continue
            }

            # Mostrar un fragmento del contenido recibido
            # Write-Host "HTML recibido para $tomcat (primeros 500 caracteres):"
            # Write-Host ($html.Substring(0, [math]::Min(500, $html.Length)))  # Evita error si el HTML es menor a 500 caracteres

            # Buscar versión de Tomcat
            Write-Host "Buscando la versión de $tomcat..."
            $match = [regex]::Match($html, $regexPattern)

            if ($match.Success) {
                $versions["$tomcat LTS"] = @{ Version = $match.Groups[3].Value; Url = $match.Groups[1].Value }
                # Write-Host "Versión de $tomcat encontrada: $($match.Groups[3].Value)"
                # Write-Host "URL de descarga: $($match.Groups[1].Value)"
            }
            else {
                Write-Host "No se encontró la versión de $tomcat."
                Write-Host "Puede que la estructura HTML haya cambiado o la expresión regular no sea correcta."
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
        Write-Host "Error al obtener versiones de Tomcat: $_" -ForegroundColor Red
    }

    return $versions  # Retorna el diccionario con las versiones encontradas
}




# ============================================================
# Función para instalar Apache Tomcat
function Install-Tomcat {
    param(
        [int]$puerto
    )

    Write-Host "`n=== Instalación de Apache Tomcat ==="

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
        # Write-Host "Se encontró una instalación previa de Tomcat en $tomcatPath. Se procederá a reinstalar."
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
    # Script para instalar Java JDK en Windows Server 2025 usando Chocolatey

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

    # Verificar si Java ya está instalado
    if (Get-Command java -ErrorAction SilentlyContinue) {
        Write-Host "Java ya está instalado. Saliendo del script."
        exit 0
    }

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
# Función para instalar Nginx.
# Se ha modificado para solicitar el puerto primero (se recibe como parámetro)
function Install-Nginx {
    param(
        [int]$puerto
    )
    Write-Host "`n=== Instalacion de Nginx ==="
    
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
}
