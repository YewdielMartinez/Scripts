# Funcion para instalar el servicio DNS
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
# Submenu DNS
Function DNS-Menu {
    do {
        Clear-Host
        Write-Host "--- Submenu DNS ---"
        Write-Host "1. Instalar DNS"
        Write-Host "2. Configurar DNS"
        Write-Host "3. Volver al menu principal"
        $choice = Read-Host "Seleccione una opcion (1-4)"
        
        switch ($choice) {
            1 { Install-DNS }
            2 {
                $domain = Read-Host "Ingrese el dominio:"
                $ipAddress = Read-Host "Ingrese la IP del servidor para ligar al dominio ($domain)"
                
                if (-not [System.Net.IPAddress]::TryParse($ipAddress, [ref]$null)) {
                    Write-Host "La IP ingresada no es valida. Intente nuevamente."
                    break
                }
                
                Create-DNSZone -Domain $domain
                Create-DNSRecords -Domain $domain -IpAddress $ipAddress
            }
            3 { .\main.ps1 }
            default { Write-Host "Opcion no valida. Intente nuevamente." }
        }
        Pause
    } while ($choice -ne 3)
}
DNS-Menu