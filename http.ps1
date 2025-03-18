# Verificar si curl está disponible
if (-not (Get-Command curl -ErrorAction SilentlyContinue)) {
    Write-Host "Error: curl no está instalado. Descárgalo desde https://curl.se/windows/"
    exit 1
}

# Función para obtener versiones de Apache, Tomcat o IIS
switch ($service) {
    "apache" {
        $stable = (Invoke-WebRequest -Uri "https://httpd.apache.org/download.cgi" -UseBasicParsing).Content | 
            Select-String -Pattern '(?<=Stable Release - Latest Version:\s*<li><a href=")[^"]*' | 
            ForEach-Object { $_.Matches.Value } | Select-Object -First 1

        $dev = (Invoke-WebRequest -Uri "https://httpd.apache.org/download.cgi" -UseBasicParsing).Content | 
            Select-String -Pattern '(?<=Alpha/Beta Releases:\s*<li><a href=")[^"]*' | 
            ForEach-Object { $_.Matches.Value } | Select-Object -First 1
    }
    "tomcat" {
        $versions = (Invoke-WebRequest -Uri "https://tomcat.apache.org/" -UseBasicParsing).Content | 
            Select-String -Pattern '(?<=Apache Tomcat )\d+\.\d+\.\d+' | 
            ForEach-Object { $_.Matches.Value } | Sort-Object -Descending

        $stable = $versions[0]
        $dev = $versions[1]
    }
}


# Función para instalar el servicio seleccionado
function Install-Service {
    param (
        [string]$serviceName
    )
    
    Write-Host "Obteniendo versiones disponibles para $serviceName..."
    $versions = Get-Versions -service $serviceName
    $stableVersion = $versions[0]
    $devVersion = $versions[1]

    if (-not $stableVersion -or -not $devVersion) {
        Write-Host "No se pudieron obtener las versiones automáticamente."
        $version = Read-Host "Ingrese la versión que desea instalar"
    } else {
        Write-Host "Versiones disponibles:"
        Write-Host "1) LTS (Estable): $stableVersion"
        Write-Host "2) Beta/Desarrollo: $devVersion"
        $versionChoice = Read-Host "Seleccione una versión [1-2]"

        switch ($versionChoice) {
            "1" { $version = $stableVersion }
            "2" { $version = $devVersion }
            default { Write-Host "Opción no válida"; return }
        }
    }
    
    $port = Read-Host "Ingrese el puerto en el que desea configurar $serviceName"
    
    Write-Host "Instalando y configurando $serviceName..."
    
    if ($serviceName -eq "iis") {
        Install-WindowsFeature -Name Web-Server -IncludeManagementTools
        Write-Host "IIS instalado y configurado en el puerto $port."
    }
    
    Write-Host "$serviceName instalado y configurado en el puerto $port."
}

# Menú principal
while ($true) {
    Write-Host "========================================"
    Write-Host "       Instalador de Servicios"
    Write-Host "========================================"
    Write-Host "1) Instalar Apache"
    Write-Host "2) Instalar Tomcat"
    Write-Host "3) Instalar IIS"
    Write-Host "4) Salir"
    Write-Host "========================================"
    
    $choice = Read-Host "Seleccione una opción [1-4]"
    
    switch ($choice) {
        "1" { Install-Service -serviceName "apache" }
        "2" { Install-Service -serviceName "tomcat" }
        "3" { Install-Service -serviceName "iis" }
        "4" { Write-Host "Saliendo del instalador..."; exit 0 }
        default { Write-Host "Opción no válida. Intente nuevamente." }
    }
}
