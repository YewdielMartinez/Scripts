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

function Agregar-Usuario {
    param (
        [string]$domain,
        [string]$adminPassword
    )

    $username = Read-Host "Ingrese el nombre del nuevo usuario (solo la parte antes de @)"
    $password = Read-Host "Ingrese la contraseña para $username@$domain"

    $script = @"
Dim app, i, dominio, cuenta
Set app = CreateObject("hMailServer.Application")
Call app.Authenticate("Administrator", "$adminPassword")

Set dominio = Nothing
For i = 0 To app.Domains.Count - 1
    If LCase(app.Domains.Item(i).Name) = LCase("$domain") Then
        Set dominio = app.Domains.Item(i)
        Exit For
    End If
Next

If dominio Is Nothing Then
    WScript.Echo "Dominio '$domain' no encontrado."
    WScript.Quit
End If

Set cuenta = dominio.Accounts.Add()
cuenta.Address = "$username@$domain"
cuenta.Password = "$password"
cuenta.Active = True
cuenta.Save

WScript.Echo "Usuario $username@$domain agregado correctamente."
"@

    $vbsPath = "$env:TEMP\agregar_usuario.vbs"
    Set-Content -Path $vbsPath -Value $script -Encoding ASCII
    cscript //nologo $vbsPath
}

function Listar-Usuarios {
    param (
        [string]$domain,
        [string]$adminPassword
    )

    $script = @"
Dim app, i, j, dominio
Set app = CreateObject("hMailServer.Application")
Call app.Authenticate("Administrator", "$adminPassword")

Set dominio = Nothing
For i = 0 To app.Domains.Count - 1
    If LCase(app.Domains.Item(i).Name) = LCase("$domain") Then
        Set dominio = app.Domains.Item(i)
        Exit For
    End If
Next

If dominio Is Nothing Then
    WScript.Echo "Dominio '$domain' no encontrado."
    WScript.Quit
End If

If dominio.Accounts.Count = 0 Then
    WScript.Echo "No hay usuarios registrados en el dominio '$domain'."
Else
    WScript.Echo "Usuarios en el dominio '$domain':"
    For j = 0 To dominio.Accounts.Count - 1
        WScript.Echo "- " & dominio.Accounts.Item(j).Address
    Next
End If
"@

    $vbsPath = "$env:TEMP\listar_usuarios.vbs"
    Set-Content -Path $vbsPath -Value $script -Encoding ASCII
    cscript //nologo $vbsPath
}


function Eliminar-Usuario {
    param (
        [string]$domain,
        [string]$adminPassword
    )

    $username = Read-Host "Ingrese el nombre del usuario a eliminar (solo la parte antes de @)"

    $script = @"
Dim app, i, j, dominio, cuenta
Set app = CreateObject("hMailServer.Application")
Call app.Authenticate("Administrator", "$adminPassword")

Set dominio = Nothing
For i = 0 To app.Domains.Count - 1
    If LCase(app.Domains.Item(i).Name) = LCase("$domain") Then
        Set dominio = app.Domains.Item(i)
        Exit For
    End If
Next

If dominio Is Nothing Then
    WScript.Echo "Dominio '$domain' no encontrado."
    WScript.Quit
End If

For j = 0 To dominio.Accounts.Count - 1
    If LCase(dominio.Accounts.Item(j).Address) = LCase("$username@$domain") Then
        dominio.Accounts.Item(j).Delete
        WScript.Echo "Usuario eliminado correctamente: $username@$domain"
        WScript.Quit
    End If
Next

WScript.Echo "El usuario $username@$domain no existe."
"@

    $vbsPath = "$env:TEMP\eliminar_usuario.vbs"
    Set-Content -Path $vbsPath -Value $script -Encoding ASCII
    cscript //nologo $vbsPath
}

function Verificar-Usuario {
    param (
        [string]$domain,
        [string]$adminPassword
    )

    $username = Read-Host "Ingrese el usuario a verificar (sin @dominio)"

    $script = @"
Dim app, i, j, dominio, encontrado
Set app = CreateObject("hMailServer.Application")
Call app.Authenticate("Administrator", "$adminPassword")

Set dominio = Nothing
For i = 0 To app.Domains.Count - 1
    If LCase(app.Domains.Item(i).Name) = LCase("$domain") Then
        Set dominio = app.Domains.Item(i)
        Exit For
    End If
Next

If dominio Is Nothing Then
    WScript.Echo "Dominio '$domain' no encontrado."
    WScript.Quit
End If

encontrado = False
For j = 0 To dominio.Accounts.Count - 1
    If LCase(dominio.Accounts.Item(j).Address) = LCase("$username@$domain") Then
        encontrado = True
        Exit For
    End If
Next

If encontrado Then
    WScript.Echo "El usuario $username@$domain SÍ existe."
Else
    WScript.Echo "El usuario $username@$domain NO existe."
End If
"@

    $vbsPath = "$env:TEMP\verificar_usuario.vbs"
    Set-Content -Path $vbsPath -Value $script -Encoding ASCII
    cscript //nologo $vbsPath
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

function Instalar-NET35 { 
    Write-Host "Instalando .NET Framework 3.5..."
    Add-WindowsFeature NET-Framework-Core -ErrorAction SilentlyContinue
    if ($?) {
        Write-Host ".NET Framework 3.5 instalado correctamente."
    } else {
        Write-Host "ERROR al instalar .NET Framework 3.5."
    }
}
function Instalar-XAMPP {
    #Seccion de instalacion de XAMPP
    New-Item -Path "C:\Installers" -ItemType Directory -Force | Out-Null

    # Descargar XAMPP (asegurate de tener curl en PowerShell v5+)
    $xamppUrl = "https://sourceforge.net/projects/xampp/files/XAMPP%20Windows/8.2.12/xampp-windows-x64-8.2.12-0-VS16-installer.exe/download"
    $outputPath = "C:\Installers\xampp-installer.exe"


    curl.exe -L $xamppUrl -o $outputPath

    # Ejecutar el instalador de XAMPP
    cd "C:\Installers"
    Start-Process -FilePath .\xampp-installer.exe
    Write-Host "XAMPP instalado correctamente." -ForegroundColor Green
    Write-Host "Iniciando XAMPP..." -ForegroundColor Cyan   

}

function Instalar-PHP {
    $phpInstallPath = "C:\xampp\php"

    if (-Not (Test-Path "$phpInstallPath\php.exe")) {
        Write-Host "[ERROR] No se encontró PHP en XAMPP. Asegúrese de que XAMPP esté instalado correctamente." -ForegroundColor Red
        return
    }

    # Agregar PHP al PATH del sistema si no está
    $currentPath = [Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::Machine)
    if ($currentPath -notlike "*$phpInstallPath*") {
        [Environment]::SetEnvironmentVariable("Path", "$currentPath;$phpInstallPath", [System.EnvironmentVariableTarget]::Machine)
    }

    Write-Host "PHP (XAMPP) registrado en PATH correctamente." -ForegroundColor Green
}


function Instalar-AfterLogic {
    Write-Host "Instalando AfterLogic WebMail Lite..." -ForegroundColor Cyan

    $afterlogicUrl = "https://afterlogic.org/download/webmail_php.zip"
    $afterlogicZip = "$env:TEMP\webmail-lite.zip"
    $afterlogicPath = "C:\xampp\htdocs\webmail"

    # Eliminar carpeta webmail si ya existe
    if (Test-Path $afterlogicPath) {
        Remove-Item $afterlogicPath -Recurse -Force
    }

    # Descargar archivo ZIP
    Invoke-WebRequest -Uri $afterlogicUrl -OutFile $afterlogicZip

    # Crear carpeta destino
    New-Item -ItemType Directory -Path $afterlogicPath -Force | Out-Null

    # Extraer contenido directamente en la carpeta deseada
    Expand-Archive -Path $afterlogicZip -DestinationPath $afterlogicPath -Force

    # Eliminar ZIP descargado
    Remove-Item $afterlogicZip

    Write-Host "AfterLogic WebMail Lite instalado en $afterlogicPath" -ForegroundColor Green
}


function Configurar-AfterLogic {
    param (
        [string]$domainName
    )

    Write-Host "Para configurar AfterLogic WebMail Lite, abra en su navegador:" -ForegroundColor Yellow
    Write-Host "http://localhost/webmail/adminpanel/" -ForegroundColor Green
    Write-Host "Usuario por defecto: superadmin" -ForegroundColor Green
    Write-Host "Contraseña por defecto: superadmin" -ForegroundColor Green
    Write-Host "`nDesde allí puede configurar IMAP y SMTP para el dominio $domainName." -ForegroundColor Cyan
}

function Configurar-PHP {
    $phpIniPath = "C:\xampp\php\php.ini"

    if (-Not (Test-Path $phpIniPath)) {
        Write-Host "[ERROR] No se encontró php.ini en $phpIniPath" -ForegroundColor Red
        return
    }

    Write-Host "Configurando php.ini..." -ForegroundColor Cyan
    $contenido = Get-Content $phpIniPath

    $cambios = @{
        ";extension=mbstring" = "extension=mbstring"
        ";extension=openssl" = "extension=openssl"
        ";extension=imap"    = "extension=imap"
        ";extension=zip"     = "extension=zip"
        ";extension=pdo_mysql" = "extension=pdo_mysql"
        "upload_max_filesize = 2M" = "upload_max_filesize = 20M"
        "post_max_size = 8M"       = "post_max_size = 40M"
        "memory_limit = 128M"      = "memory_limit = 256M"
        "max_execution_time = 30"  = "max_execution_time = 300"
    }

    foreach ($clave in $cambios.Keys) {
        $valor = $cambios[$clave]
        $contenido = $contenido -replace [regex]::Escape($clave), $valor
    }

    $contenido | Set-Content -Path $phpIniPath -Encoding UTF8
    Write-Host "php.ini configurado correctamente." -ForegroundColor Green
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
Dim app, domain, existingDomain
Set app = CreateObject("hMailServer.Application")
Call app.Authenticate("Administrator", "$AdminPass")

' Verificar si el dominio ya existe
Dim i
For i = 0 To app.Domains.Count - 1
    If LCase(app.Domains.Item(i).Name) = LCase("$Dominio") Then
        WScript.Echo "El dominio '$Dominio' ya está configurado."
        WScript.Quit
    End If
Next

' Crear dominio
Set domain = app.Domains.Add()
domain.Name = "$Dominio"
domain.Active = True
domain.Save

' Crear cuenta de administrador
Set account = domain.Accounts.Add()
account.Address = "admin@$Dominio"
account.Password = "Admin123"
account.Active = True
account.MaxSize = 100
account.Save

WScript.Echo "Dominio '$Dominio' y cuenta admin@$Dominio configurados correctamente."
"@

    $vbsPath = "$env:TEMP\configurar_hmail.vbs"
    Set-Content -Path $vbsPath -Value $script -Encoding ASCII
    cscript //nologo $vbsPath
}

function Mostrar-MenuUsuarios {
    param (
        [string]$domain,
        [string]$adminPassword,
        [string]$ipAddress
    )

    do {
        Write-Host "`n----- MENÚ DE USUARIOS DE CORREO -----"
        Write-Host "Dominio actual: $domain"
        Write-Host "Contraseña de administrador: $adminPassword"
        Write-Host "IP del servidor: $ipAddress"
        Write-Host "Acceso a AfterLogic WebMail: http://localhost/webmail"
        Write-Host "Acceso a AfterLogic Admin: http://localhost/webmail/adminpanel"
        Write-Host "-------------------------------------"
        Write-Host "1. Agregar usuario de correo"
        Write-Host "2. Eliminar usuario de correo"
        Write-Host "3. Listar usuarios de correo"
        Write-Host "4. Verificar si un usuario existe"
        Write-Host "5. Configurar nuevo dominio"
        Write-Host "6. Salir"

        $opcion = Read-Host "Seleccione una opción"

        switch ($opcion) {
            1 { Agregar-Usuario -domain $domain -adminPassword $adminPassword }
            2 { Eliminar-Usuario -domain $domain -adminPassword $adminPassword }
            3 { Listar-Usuarios -domain $domain -adminPassword $adminPassword }
            4 { Verificar-Usuario -domain $domain -adminPassword $adminPassword }
            5 {
                $nuevoDominio = Read-Host "Ingrese el nuevo dominio"
                Configurar-Dominio-hMail -Dominio $nuevoDominio -AdminPass $adminPassword
                $domain = $nuevoDominio  # Actualiza la variable local
            }
            6 { Write-Host "Saliendo..."; break }
            default { Write-Host "Opción inválida" -ForegroundColor Red }
        }
    } while ($true)
}

# Menú principal
do {
    Write-Host "`n----- MENÚ PRINCIPAL DEL SERVIDOR DE CORREO -----"
    Write-Host "1. Instalar y configurar DNS"
    Write-Host "2. Instalar .NET Framework 3.5"
    Write-Host "3. Instalar Chocolatey"
    Write-Host "4. Instalar hMailServer"
    Write-Host "5. Configurar dominio en hMailServer"
    Write-Host "6. Configurar reglas de firewall (SMTP, IMAP, POP3)"
    Write-Host "7. Instalar XAMPP"
    Write-Host "8. Instalar PHP"
    Write-Host "9. Instalar AfterLogic WebMail Lite"
    Write-Host "10. Configurar AfterLogic"
    Write-Host "11. Configurar php.ini"
    Write-Host "12. Salir al menú de usuarios"

    $opcion = Read-Host "Seleccione una opción"

    switch ($opcion) {
        1 {
            Install-DNS
            $global:domain = Read-Host "Ingrese el dominio del correo (ej. midominio.com)"
            $global:ipAddress = Read-Host "Ingrese la IP del servidor ($global:domain)"
            if (-not [System.Net.IPAddress]::TryParse($global:ipAddress, [ref]$null)) {
                Write-Host "La IP ingresada no es válida. Intente nuevamente." -ForegroundColor Red
                continue
            }
            Create-DNSZone -Domain $global:domain
            Create-DNSRecords -Domain $global:domain -IpAddress $global:ipAddress
        }
        2 { Instalar-NET35 }
        3 { Instalar-Chocolatey }
        4 { Instalar-hMailServer }
        5 {
            if (-not $global:domain) {
                $global:domain = Read-Host "Ingrese el dominio del correo"
            }
            $global:adminPassword = Read-Host "Ingrese la contraseña del administrador de hMailServer"
            Configurar-Dominio-hMail -Dominio $global:domain -AdminPass $global:adminPassword
        }
        6 {
            New-NetFirewallRule -DisplayName "SMTP (25)" -Direction Inbound -Protocol TCP -LocalPort 25 -Action Allow
            New-NetFirewallRule -DisplayName "IMAP (143)" -Direction Inbound -Protocol TCP -LocalPort 143 -Action Allow
            New-NetFirewallRule -DisplayName "POP3 (110)" -Direction Inbound -Protocol TCP -LocalPort 110 -Action Allow
            Write-Host "Reglas de firewall configuradas." -ForegroundColor Green
        }
        7 { Instalar-XAMPP }
        8 { Instalar-PHP }
        9 { Instalar-AfterLogic }
        10 {
            if (-not $global:domain) {
                $global:domain = Read-Host "Ingrese el dominio del correo"
            }
            Configurar-AfterLogic -domainName $global:domain
        }
        11 { Configurar-PHP }
        12 {
            if (-not $global:domain) {
                $global:domain = Read-Host "Ingrese el dominio del correo"
            }
            if (-not $global:adminPassword) {
                $global:adminPassword = Read-Host "Ingrese la contraseña del administrador de hMailServer"
            }
            if (-not $global:ipAddress) {
                $global:ipAddress = Read-Host "Ingrese la IP del servidor ($global:domain)"
            }

            # Llamada con variables correctas
            Mostrar-MenuUsuarios -domain $global:domain -adminPassword $global:adminPassword -ipAddress $global:ipAddress
            break
        }
        default { Write-Host "Opción inválida." -ForegroundColor Red }
    }
} while ($true)
