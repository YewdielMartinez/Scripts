# Funcion para instalar el servicio DNS
Import-Module WebAdministration
Import-Module ServerManager
function Dependencias {
    Write-Host "`nVerificando Visual C++ Redistributable..."
    $vcInstalled = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" | 
    Get-ItemProperty | 
    Where-Object { $_.DisplayName -match "Visual C\+\+ (2015|2017|2019|2022) Redistributable" }
    if ($vcInstalled) {
        Write-Host "Visual C++ Redistributable ya está instalado."
    }
    else {
        Write-Host "No esta instalado Visual C++. Descargando e instalando..."
        $vcUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
        $vcInstaller = "$env:TEMP\vc_redist.x64.exe"
        Invoke-WebRequest -Uri $vcUrl -OutFile $vcInstaller -UseBasicParsing
        Start-Process -FilePath $vcInstaller -ArgumentList "/install /quiet /norestart" -NoNewWindow -Wait
        Write-Host "Visual C++ Redistributable instalado correctamente."
    }
}
function Instalar-Chocolatey {
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Host "🍫 Instalando Chocolatey..." -ForegroundColor Cyan
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        if ($?) {
            Write-Host "✅ Chocolatey instalado correctamente." -ForegroundColor Green
        } else {
            Write-Host "[ERROR] Falló la instalación de Chocolatey." -ForegroundColor Red
        }
    } else {
        Write-Host "🍫 Chocolatey ya está instalado." -ForegroundColor Yellow
    }
}


function Conectar-hMail {
    param([string]$adminPassword)

    try {
        $hMail = New-Object -ComObject "hMailServer.Application"
        $hMail.Authenticate("Administrator", $adminPassword)
        return $hMail
    } catch {
        Write-Host "[ERROR] No se pudo conectar a hMailServer. Verifica la contraseña." -ForegroundColor Red
        return $null
    }
}


function Validar-Usuario($usuario) {
    if ($usuario -match '^[a-z_][a-z0-9_-]{2,15}$') {
        return $true
    } else {
        Write-Host "[ERROR] Nombre de usuario inválido." -ForegroundColor Red
        return $false
    }
}

function Validar-Password($password) {
    if ($password.Length -ge 8 -and 
        $password -match '[A-Z]' -and 
        $password -match '[a-z]' -and 
        $password -match '\d') {
        return $true
    } else {
        Write-Host "[ERROR] La contraseña debe tener al menos 8 caracteres, incluir una letra mayúscula, una minúscula y un número." -ForegroundColor Red
        return $false
    }
}
function Agregar-Usuario {
    param (
        [string]$domain,
        [string]$adminPassword
    )

    $hMail = Conectar-hMail -adminPassword $adminPassword
if (-not $hMail) { return }

$dominioObj = $hMail.Domains.ItemByName($domain)
if (-not $dominioObj) {
    Write-Host "[ERROR] El dominio $domain no existe en hMailServer." -ForegroundColor Red
    return
}

    $dominioObj = $hMail.Domains.ItemByName($domain)

    do {
        $usuario = Read-Host "Ingrese el nombre del usuario (sin @$domain)"
    } while (-not (Validar-Usuario $usuario))

    do {
        $password = Read-Host "Ingrese la contraseña del usuario" -AsSecureString
        $passwordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
        )
    } while (-not (Validar-Password $passwordPlain))

    # Revisar si ya existe
    $correo = "$usuario@$domain"
    $existe = $false
    foreach ($cuenta in $dominioObj.Accounts) {
        if ($cuenta.Address -eq $correo) { $existe = $true; break }
    }

    if ($existe) {
        Write-Host "[!] La cuenta $correo ya existe." -ForegroundColor Yellow
    } else {
        $cuenta = $dominioObj.Accounts.Add()
        $cuenta.Address = $correo
        $cuenta.Password = $passwordPlain
        $cuenta.Active = $true
        $cuenta.Save()
        Write-Host "[+] Cuenta $correo creada en hMailServer." -ForegroundColor Green
    }
}

function Listar-Usuarios {
    param (
        [string]$domain,
        [string]$adminPassword
    )

    $hMail = Conectar-hMail -adminPassword $adminPassword
    $dominioObj = $hMail.Domains.ItemByName($domain)

    Write-Host "Cuentas de correo en $domain :`n" -ForegroundColor Cyan
    foreach ($cuenta in $dominioObj.Accounts) {
        Write-Host "- $($cuenta.Address)"
    }
}


function Eliminar-Usuario {
    param (
        [string]$domain,
        [string]$adminPassword
    )

    $correo = Read-Host "Ingrese la cuenta de correo a eliminar (sin @$domain)"
    $correoCompleto = "$correo@$domain"

    $hMail = Conectar-hMail -adminPassword $adminPassword
    $dominioObj = $hMail.Domains.ItemByName($domain)

    $found = $false
    for ($i = 0; $i -lt $dominioObj.Accounts.Count; $i++) {
        $cuenta = $dominioObj.Accounts.Item($i)
        if ($cuenta.Address -eq $correoCompleto) {
            $cuenta.Delete()
            Write-Host "[+] Cuenta $correoCompleto eliminada correctamente." -ForegroundColor Green
            $found = $true
            break
        }
    }

    if (-not $found) {
        Write-Host "[-] No se encontró la cuenta $correoCompleto." -ForegroundColor Yellow
    }
}

function Verificar-Usuario {
    param (
        [string]$domain,
        [string]$adminPassword
    )

    $correo = Read-Host "Ingrese el nombre del usuario (sin @$domain)"
    $correoCompleto = "$correo@$domain"

    $hMail = Conectar-hMail -adminPassword $adminPassword
    $dominioObj = $hMail.Domains.ItemByName($domain)

    $existe = $false
    foreach ($cuenta in $dominioObj.Accounts) {
        if ($cuenta.Address -eq $correoCompleto) {
            $existe = $true
            break
        }
    }

    if ($existe) {
        Write-Host "[+] El usuario $correoCompleto existe." -ForegroundColor Green
    } else {
        Write-Host "[-] El usuario $correoCompleto no existe." -ForegroundColor Yellow
    }
}

Function Install-DNS {
    Write-Host "Instalando servicio DNS..."
    Install-WindowsFeature -Name DNS -IncludeManagementTools
    Enable-FirewallRules
    Write-Host "El servicio DNS ha sido instalado con exito."
}

# Funcion para crear la zona directa
Function Create-DNSZone {
    param (
        [string]$Domain
    )
    Write-Host "Creando zona directa para $Domain..."
    Add-DnsServerPrimaryZone -Name $Domain -ZoneFile "$Domain.dns"
    Write-Host "Zona directa $Domain creada con exito."
}


# Funcion para crear los registros A
Function Create-DNSRecords {
    param (
        [string]$Domain,
        [string]$IpAddress
    )
    Write-Host "Creando registros A para el dominio $Domain..."
    
    # Crear el registro para el dominio principal
    Add-DnsServerResourceRecordA -Name "@" -ZoneName $Domain -IPv4Address $IpAddress

    # Crear el registro para www
    Add-DnsServerResourceRecordA -Name "www" -ZoneName $Domain -IPv4Address $IpAddress
    
    Enable-FirewallRules
    Write-Host "Registros A creados con exito para $Domain."
}

# Funcion para habilitar reglas especificas en el Firewall de Windows
Function Enable-FirewallRules {
    $rulesToEnable = @(
	"Core Networking Diagnostics - ICMP Echo Request (ICMPv4-In)",
        "Virtual Machine Monitoring (Echo Request - ICMPv4-In)",
        "Virtual Machine Monitoring (Echo Request - ICMPv6-In)",
        "File and Printer Sharing (Echo Request - ICMPv4-In)",
        "File and Printer Sharing (Echo Request - ICMPv6-In)",
        "File and Printer Sharing (Restrictive) (Echo Request - ICMPv4-In)",
        "File and Printer Sharing (Restrictive) (Echo Request - ICMPv6-In)"
    )

    foreach ($rule in $rulesToEnable) {
        Set-NetFirewallRule -DisplayName $rule -Enabled True -ErrorAction SilentlyContinue
    }
}



function Crear-Cuenta-hMail {
    param (
        [string]$Dominio,
        [string]$AdminPass,
        [string]$Usuario,
        [string]$Password
    )

    $email = "$Usuario@$Dominio"

    $script = @"
Dim app
Set app = CreateObject("hMailServer.Application")
Call app.Authenticate("Administrator", "$AdminPass")

Dim domain
Set domain = app.Domains.ItemByName("$Dominio")

' Verificar si ya existe la cuenta
Dim account
On Error Resume Next
Set account = domain.Accounts.ItemByAddress("$email")
If Err.Number = 0 Then
    WScript.Echo "La cuenta ya existe."
    WScript.Quit
End If
Err.Clear
On Error GoTo 0

Set account = domain.Accounts.Add()
account.Address = "$email"
account.Password = "$Password"
account.Active = True
account.MaxSize = 100
account.Save
"@

    $vbsPath = "$env:TEMP\crear_usuario_hmail.vbs"
    Set-Content -Path $vbsPath -Value $script -Encoding ASCII
    cscript //nologo $vbsPath
}
function Instalar-NET35 { 
    Write-Host "Instalando .NET Framework 3.5..."
    Add-WindowsFeature NET-Framework-Core -ErrorAction SilentlyContinue
    if ($?) {
        Write-Host ".NET Framework 3.5 instalado correctamente."
    } else {
        Write-Host "ERROR al instalar .NET Framework 3.5."
    }
}

function Instalar-IIS {
    Write-Host "Instalando IIS y componentes necesarios..."
    Install-WindowsFeature -Name Web-Server, Web-WebServer, Web-Common-Http, Web-Default-Doc, Web-Static-Content, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Mgmt-Console, Web-Scripting-Tools, Web-Http-Errors, Web-CGI -IncludeManagementTools
    Write-Host "IIS instalado correctamente."
}
function Instalar-PHP {
    $phpInstallPath = "C:\PHP"
    $phpZipUrl = "https://windows.php.net/downloads/releases/archives/php-7.4.33-nts-Win32-vc15-x64.zip"
    $phpZipPath = "$env:TEMP\php74.zip"
    $phpVersion = "7.4.33"
    $appCmd = "$env:WinDir\System32\inetsrv\appcmd.exe"

    Write-Host "🍫 Instalando PHP 8.2 con Chocolatey para preparar estructura..." -ForegroundColor Cyan
    choco install php --version=8.2 --params '"/InstallDir:C:\PHP"' -y

    if (-Not (Test-Path $phpInstallPath)) {
        Write-Host "[ERROR] La instalación de PHP 8.2 con Chocolatey falló o no se creó C:\PHP." -ForegroundColor Red
        return
    }

    Write-Host "🔽 Descargando PHP $phpVersion..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $phpZipUrl -OutFile $phpZipPath -UseBasicParsing

    Write-Host "🔁 Reemplazando archivos de PHP 8.2 con versión $phpVersion..." -ForegroundColor Cyan
    Expand-Archive -Path $phpZipPath -DestinationPath "$env:TEMP\php74" -Force

    Get-ChildItem -Path $phpInstallPath -Recurse | Remove-Item -Force -Recurse
    Copy-Item -Path "$env:TEMP\php74\*" -Destination $phpInstallPath -Recurse -Force

    # Configurar php.ini
    $iniDevPath = Join-Path $phpInstallPath "php.ini-development"
    $iniPath = Join-Path $phpInstallPath "php.ini"
    if (Test-Path $iniDevPath) {
        Write-Host "⚙️ Configurando php.ini..." -ForegroundColor Cyan
        Copy-Item $iniDevPath $iniPath -Force
        (Get-Content $iniPath) | ForEach-Object {
            $_ -replace ';extension_dir = "ext"', 'extension_dir = "ext"' `
               -replace ';extension=mbstring', 'extension=mbstring' `
               -replace ';extension=openssl', 'extension=openssl' `
               -replace ';extension=curl', 'extension=curl' `
               -replace ';date.timezone =', 'date.timezone = "America/Mexico_City"'
        } | Set-Content $iniPath -Encoding ASCII
    } else {
        Write-Host "[ERROR] No se encontró php.ini-development." -ForegroundColor Red
        return
    }

    # Registrar FastCGI en IIS
    $phpCgiPath = Join-Path $phpInstallPath "php-cgi.exe"
    Write-Host "🧩 Registrando PHP en IIS como FastCGI..." -ForegroundColor Cyan
    & $appCmd set config /section:system.webServer/fastCgi /+"[fullPath='$phpCgiPath']"

    Write-Host "📄 Registrando handler para PHP (*.php)..." -ForegroundColor Cyan
    & $appCmd set config /section:system.webServer/handlers /+"[name='PHP_via_FastCGI',path='*.php',verb='GET,HEAD,POST',modules='FastCgiModule',scriptProcessor='$phpCgiPath',resourceType='Either']"

    Write-Host "📃 Estableciendo index.php como documento por defecto..." -ForegroundColor Cyan
    & $appCmd set config /section:defaultDocument /+files.[value='index.php']

    Write-Host "🔁 Reiniciando IIS..." -ForegroundColor Cyan
    iisreset

    Write-Host "✅ PHP $phpVersion instalado correctamente con estructura de PHP 8.2." -ForegroundColor Green
}

function Instalar-RainLoop {
    Write-Host "Descargando e instalando RainLoop..."
    $rainloopUrl = "https://www.rainloop.net/repository/webmail/rainloop-latest.zip"
    $rainloopZip = "$env:TEMP\rainloop.zip"
    $rainloopPath = "C:\inetpub\rainloop"
    $phpCgiPath = "C:\tools\php74\php-cgi.exe"  # Ajusta si usas otra versión o ruta

    if (Test-Path $rainloopPath) {
        Remove-Item -Recurse -Force $rainloopPath
    }

    Invoke-WebRequest $rainloopUrl -OutFile $rainloopZip
    Expand-Archive -Path $rainloopZip -DestinationPath $rainloopPath -Force
    Remove-Item $rainloopZip

    # Permisos
    icacls $rainloopPath /grant "IIS_IUSRS:(OI)(CI)F" /T
    icacls $rainloopPath /grant "Everyone:(OI)(CI)F" /T

    # Crear sitio en IIS
    if (-not (Get-Website | Where-Object { $_.Name -eq "RainLoop" })) {
        New-Website -Name "RainLoop" -Port 80 -PhysicalPath $rainloopPath -ApplicationPool "DefaultAppPool"
    }

    # Crear web.config compatible con IIS y FastCGI
    $webConfigContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <defaultDocument>
            <files>
                <add value="index.php" />
            </files>
        </defaultDocument>
        <handlers>
            <add name="PHP_via_FastCGI"
                 path="*.php"
                 verb="GET,HEAD,POST"
                 modules="FastCgiModule"
                 scriptProcessor="$phpCgiPath"
                 resourceType="Either"
                 requireAccess="Script" />
        </handlers>
    </system.webServer>
</configuration>
"@
    $webConfigPath = Join-Path $rainloopPath "web.config"
    Set-Content -Path $webConfigPath -Value $webConfigContent -Encoding UTF8

    Write-Host "RainLoop instalado y configurado en IIS correctamente."
}

function Configurar-RainLoop {
    param (
        [string]$domainName
    )

    $mailIP = Read-Host "Ingrese la IP del servidor de correo"
    $configPath = "C:\inetpub\rainloop\data\_data_\_default_\domains\$domainName.ini"

    $configContent = @"
imap_host = $mailIP
imap_port = 143
imap_secure = none
smtp_host = $mailIP
smtp_port = 25
smtp_secure = none
smtp_auth = On
white_list = 
use_short_login = On
"@
    New-Item -ItemType Directory -Path (Split-Path $configPath) -Force
    Set-Content -Path $configPath -Value $configContent -Encoding UTF8
    Write-Host "Dominio $domainName configurado en RainLoop."
}

function Instalar-hMailServer {
    $hmailUrl = "https://www.hmailserver.com/files/hMailServer-5.6.7-B2425.exe"
    $hmailInstaller = "$env:TEMP\hmailserver.exe"
    Write-Host "Descargando hMailServer..."
    Invoke-WebRequest $hmailUrl -OutFile $hmailInstaller

    Write-Host "Instalando hMailServer en modo silencioso..."
    Start-Process -FilePath $hmailInstaller -ArgumentList "/SILENT" -Wait
    Start-Sleep -Seconds 5
    Write-Host "hMailServer instalado silenciosamente."
}

function Configurar-Dominio-hMail {
    param(
        [string]$Dominio,
        [string]$AdminPass
    )

    $script = @"
Dim app
Set app = CreateObject("hMailServer.Application")
Call app.Authenticate("Administrator", "$AdminPass")

' Crear dominio
Dim domain
Set domain = app.Domains.Add()
domain.Name = "$Dominio"
domain.Active = True
domain.Save

' Configurar SMTP
domain.SMTPRelayer = ""
domain.SMTPRelayerRequiresAuth = False
domain.SMTPRelayerUseSSL = False
domain.Save

' Crear cuentas por defecto
Dim account
Set account = domain.Accounts.Add()
account.Address = "admin@$Dominio"
account.Password = "Admin123"
account.Active = True
account.MaxSize = 100
account.Save
"@

    $vbsPath = "$env:TEMP\configurar_hmail.vbs"
    Set-Content -Path $vbsPath -Value $script -Encoding ASCII
    cscript //nologo $vbsPath
}

# Asumiendo que tienes definidas funciones Install-DNS, Create-DNSZone, Create-DNSRecords
Install-DNS
$domain = Read-Host "Ingrese el dominio del correo (ej. midominio.com)"
$ipAddress = Read-Host "Ingrese la IP del servidor ($domain)"
if (-not [System.Net.IPAddress]::TryParse($ipAddress, [ref]$null)) {
    Write-Host "La IP ingresada no es válida. Intente nuevamente."
    break
}

Create-DNSZone -Domain $domain
Create-DNSRecords -Domain $domain -IpAddress $ipAddress

$adminPassword = Read-Host "Ingrese la contraseña del administrador de hMailServer"

Instalar-NET35
Instalar-IIS
Instalar-Chocolatey
Instalar-PHP
Instalar-RainLoop
Instalar-hMailServer
Configurar-Dominio-hMail -Dominio $domain -AdminPass $adminPassword
Configurar-RainLoop -domainName $domain

# Configurar reglas de firewall
New-NetFirewallRule -DisplayName "SMTP (25)" -Direction Inbound -Protocol TCP -LocalPort 25 -Action Allow
New-NetFirewallRule -DisplayName "IMAP (143)" -Direction Inbound -Protocol TCP -LocalPort 143 -Action Allow
New-NetFirewallRule -DisplayName "POP3 (110)" -Direction Inbound -Protocol TCP -LocalPort 110 -Action Allow
Set-ItemProperty "IIS:\Sites\RainLoop" -Name bindings -Value @{protocol="http"; bindingInformation="*:80:$domain"}

Write-Host "Instalación completada. Accede a http://$domain para usar RainLoop."

do {
    Write-Host "`n----- MENÚ -----"
    Write-Host "1. Agregar usuario de correo"
    Write-Host "2. Eliminar usuario de correo"
    Write-Host "3. Listar usuarios de correo"
    Write-Host "4. Verificar si un usuario existe"
    Write-Host "5. Salir"

    $opcion = Read-Host "Seleccione una opción"

    switch ($opcion) {
        1 { Agregar-Usuario -domain $domain -adminPassword $adminPassword }
        2 { Eliminar-Usuario -domain $domain -adminPassword $adminPassword }
        3 { Listar-Usuarios -domain $domain -adminPassword $adminPassword }
        4 { Verificar-Usuario -domain $domain -adminPassword $adminPassword }
        5 { Write-Host "Saliendo..."; break }
        default { Write-Host "Opción inválida" -ForegroundColor Red }
    }
} while ($true)
