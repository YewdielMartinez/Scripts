# Requiere ejecución como administrador

Import-Module WebAdministration




function Conectar-hMail {
    param(
        [string]$adminPassword
    )
    $hMail = New-Object -ComObject "hMailServer.Application"
    $hMail.Authenticate("Administrator", $adminPassword)
    return $hMail
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
        Write-Host "ERROR al instalar .NET Framework 3.5. Asegúrate de tener acceso al medio de instalación o Internet."
    }
}

function Instalar-Requisitos {
    Write-Host "Instalando IIS, PHP y hMailServer..."

    # IIS + CGI + PHP
    Install-WindowsFeature Web-Server, Web-CGI, Web-Common-Http, Web-Static-Content
    choco install php -y
    choco install unzip -y

    # hMailServer
    $hMailInstaller = "$env:TEMP\hMailServer.exe"
    Invoke-WebRequest "https://www.hmailserver.com/download/latest" -OutFile $hMailInstaller
    Start-Process $hMailInstaller -ArgumentList "/VERYSILENT" -Wait

    # PHP para IIS
    $phpPath = "${env:ProgramFiles(x86)}\PHP"
    $phpExe = Get-ChildItem -Recurse -Filter php-cgi.exe $phpPath | Select-Object -First 1
    if (-not $phpExe) {
        Write-Error "No se encontró PHP CGI."
        return
    }

    # IIS + Handler PHP
    New-WebHandler -Path "*.php" -Verb "*" -Modules "FastCgiModule" -ScriptProcessor $phpExe.FullName -Name "PHP_via_FastCGI"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/handlers" -name "." -value @{name='PHP_via_FastCGI'; path='*.php'; verb='*'; modules='FastCgiModule'; scriptProcessor=$phpExe.FullName; resourceType='Either'; requireAccess='Script'}

    # Crear sitio para RainLoop
    $rainPath = "C:\inetpub\rainloop"
    New-Item -ItemType Directory -Path $rainPath -Force
    Invoke-WebRequest "https://www.rainloop.net/repository/webmail/rainloop-latest.zip" -OutFile "$env:TEMP\rainloop.zip"
    Expand-Archive -Path "$env:TEMP\rainloop.zip" -DestinationPath $rainPath

    New-Website -Name "RainLoop" -PhysicalPath $rainPath -Port 80 -HostHeader $domainName
    Write-Host "Sitio RainLoop creado en http://$domainName"
}

function Configurar-RainLoop {
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

# INICIO
$domainName = Read-Host "Ingrese el nombre del dominio"

Instalar-Requisitos
Configurar-RainLoop

# MENÚ
while ($true) {
    Write-Host "`n--- MENÚ ---"
    Write-Host "1. Agregar usuario de correo"
    Write-Host "2. Eliminar usuario de correo"
    Write-Host "3. Listar usuarios de correo"
    Write-Host "4. Verificar usuario"
    Write-Host "5. Agregar nuevo dominio"
    Write-Host "6. Salir"
    $opcion = Read-Host "Seleccione una opción"
    switch ($opcion) {
        "1" { Agregar-Usuario }
        "2" { Eliminar-Usuario }
        "3" { Listar-Usuarios }
        "4" { Verificar-Usuario }
        "5" { Agregar-Dominio }
        "6" { Write-Host "Saliendo..."; break }
        default { Write-Host "Opción inválida" }
    }
}
