Function PrintMessage {
    param (
        [string]$MessageType,
        [string]$Message
    )
    switch ($MessageType) {
        "success" { Write-Host $Message -ForegroundColor Green }
        "error" { Write-Host $Message -ForegroundColor Red }
        "info" { Write-Host $Message -ForegroundColor Cyan }
        default { Write-Host $Message }
    }
}

# Función para limpiar la consola
Function ClearConsole {
    Clear-Host
}

# enable firewall rules
Function enableFirewallRules {
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

function Validate-PasswordComplexity {
    param (
        [string]$Password
    )

    # Verificar si la contraseña es nula o vacía
    if (-not $Password -or $Password.Length -lt 8) {
        Write-Output "Error: La contraseña debe tener al menos 8 caracteres."
        return $false
    }

    # Contadores para validar al menos 3 de las 4 categorías
    $categories = 0
    if ($Password -match "[A-Z]") { $categories++ }   # Mayúscula
    if ($Password -match "[a-z]") { $categories++ }   # Minúscula
    if ($Password -match "\d") { $categories++ }      # Número
    if ($Password -match "[^\w]") { $categories++ }   # Caracter especial

    if ($categories -ge 3) {
        return $true
    } else {
        Write-Output "Error: La contraseña debe contener al menos 3 de estas 4 categorias: mayusculas, minusculas, numeros o caracteres especiales."
        return $false
    }
}

function Validate-UserName {
    param (
        [string]$nombreUsuario
    )

    # Expresión regular para validar el nombre
    $regex = '^[a-zA-Z0-9_][a-zA-Z0-9_-]{2,18}$'


    # Validar si cumple con la expresión regular
    if ($nombreUsuario -match $regex) {
        return $true
    } else {
        PrintMessage "Error" "Nombre de usuario no valido. Usa solo letras, numeros y guiones bajos o medios. No debe comenzar con caracteres especiales."
        return $false
    }
}

function User-Exists {
    param (
        [string]$nombreUsuario
    )

    if (Get-LocalUser -Name $nombreUsuario -ErrorAction SilentlyContinue) {
        PrintMessage "Error" "El usuario '$nombreUsuario' ya existe en el sistema."
        return $true
    } else {
        return $false
    }
}

function Validate-FTP-Site {
    param (
        [string]$siteName,
        [string]$ftpPath
    )

    # Validar si el sitio FTP ya existe en IIS
    $siteExists = Get-WebSite -Name $siteName -ErrorAction SilentlyContinue
    if ($siteExists) {
        Write-Output "Error: El sitio FTP '$siteName' ya existe en IIS."
        return $false
    }

    # Validar si el directorio existe
    if (-not (Test-Path $ftpPath)) {
        Write-Output "Error: El directorio '$ftpPath' no existe. Creándolo..."
        New-Item -Path $ftpPath -ItemType Directory -Force | Out-Null
    }

    # Validar si el puerto 21 está en uso (o cualquier otro puerto que usarás)
    $portInUse = Get-NetTCPConnection -LocalPort 21 -ErrorAction SilentlyContinue
    if ($portInUse) {
        Write-Output "Error: El puerto 21 ya está en uso por otro servicio."
        return $false
    }

    return $true
}

function InputNumber {
    param (
        [string]$mensaje = "Ingrese un numero:"
    )

    do {
        $entrada = Read-Host $mensaje
        if ($entrada -match "^\d+(\.\d+)?$") {
            return [double]$entrada  # Devuelve el número convertido
        } else {
            Write-Host "Error: Debe ingresar un valor numerico valido." -ForegroundColor Red
        }
    } while ($true)
}

function InputText {
    param (
        [string]$mensaje = "Ingrese un texto:"
    )

    do {
        $entrada = Read-Host $mensaje
        if ($entrada -match "^\s*$") {
            PrintMessage "error" "No puede estar vacio. Intente nuevamente."
        } else {
            return $entrada  # Devuelve el texto ingresado
        }
    } while ($true)
}