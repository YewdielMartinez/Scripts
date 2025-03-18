# Funcion para instalar el servicio DNS
Function Install-DNS {
    Write-Host "Instalando servicio DNS..."
    Install-WindowsFeature -Name DNS -IncludeManagementTools
    Enable-FirewallRules
    Write-Host "El servicio DNS ha sido instalado con exito."
}
# Funcion para instalar el servicio DHCP
Function Install-DHCP {
    Write-Host "Instalando servicio DHCP..."
    Install-WindowsFeature -Name DHCP -IncludeManagementTools
    Write-Host "Servicio DHCP instalado correctamente."
}

# Funcion para configurar DHCP
Function Configure-DHCP {
    param (
        [string]$ScopeName,
        [string]$StartRange,
        [string]$EndRange,
        [string]$SubnetMask,
        [string]$Gateway,
        [string]$ExclusionStart,
        [string]$ExclusionEnd,
        [string]$DnsServers,
        [string]$DomainName
    )
    
    Write-Host "Creando nuevo ámbito DHCP..."
    Add-DhcpServerV4Scope -Name $ScopeName -StartRange $StartRange -EndRange $EndRange -SubnetMask $SubnetMask -State Active
    Set-DhcpServerV4OptionValue -ScopeId $StartRange -Router $Gateway -DnsServer $DnsServers -DnsDomain $DomainName
    
    if ($ExclusionStart -and $ExclusionEnd) {
        Write-Host "Agregando exclusiones de IP desde $ExclusionStart hasta $ExclusionEnd..."
        Add-DhcpServerV4ExclusionRange -ScopeId $StartRange -StartRange $ExclusionStart -EndRange $ExclusionEnd
    }
    
    Write-Host "Ámbito DHCP configurado con éxito."
}
# Funcion para configurar la IP fija del servidor
Function Set-StaticIP {
    Write-Host "Configurando IP fija en el servidor..."
    $Interface = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

    if ($Interface) {
        $ipAddress = Read-Host "Ingrese la nueva IP del servidor"
        $subnetMask = Read-Host "Ingrese la submascara de red (ejemplo: 255.255.255.0)"
        $gateway = Read-Host "Ingrese la puerta de enlace"

        # Convertir la submascara en prefijo de red
        $prefixLength = (ConvertFrom-Cidr -SubnetMask $subnetMask)
        if ($prefixLength -eq $null) {
            Write-Host "Submascara invalida. Intente nuevamente."
            return
        }

        # Eliminar cualquier configuracion IP previa en la interfaz
        Remove-NetIPAddress -InterfaceIndex $Interface.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
        
        # Configurar IP, submascara y gateway
        New-NetIPAddress -InterfaceIndex $Interface.ifIndex -IPAddress $ipAddress -PrefixLength $prefixLength -DefaultGateway $gateway -ErrorAction Stop
        Set-DnsClientServerAddress -InterfaceIndex $Interface.ifIndex -ServerAddresses $gateway
        Enable-FirewallRules
        Write-Host "IP configurada correctamente: $ipAddress/$prefixLength con gateway $gateway."
    } else {
        Write-Host "No se encontro una interfaz de red activa."
    }
}

# Funcion para convertir submascara a prefijo CIDR
Function ConvertFrom-Cidr {
    param (
        [string]$SubnetMask
    )
    $octets = $SubnetMask -split "\."
    if ($octets.Length -ne 4) { return $null }

    $binaryMask = ($octets | ForEach-Object { [Convert]::ToString($_, 2).PadLeft(8, '0') }) -join ""
    return ($binaryMask -cmatch "1").Count
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
# Funcion para instalar el servidor SSH
Function Install-SSH {
    Write-Host "Instalando servicio SSH..."
    Add-WindowsFeature -Name OpenSSH-Server
    Write-Host "Servicio SSH instalado correctamente."
    Enable-SSH
}

# Funcion para habilitar y configurar SSH
Function Enable-SSH {
    Write-Host "Habilitando servicio SSH..."
    Set-Service -Name ssh-agent -StartupType Automatic
    Set-Service -Name sshd -StartupType Automatic
    Get-Service ssh* | Start-Service
    Write-Host "SSH ha sido habilitado."
    Enable-SSHFirewall
}

# Funcion para configurar reglas de firewall para SSH
Function Enable-SSHFirewall {
    Write-Host "Configurando reglas de firewall para SSH..."
    New-NetFirewallRule -Name "SSH" -DisplayName "SSH" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
    Write-Host "Reglas de firewall configuradas."
}

# Funcion para modificar configuracion SSH
Function Configure-SSH {
    Write-Host "Configurando SSH..."
    $configPath = "C:\ProgramData\ssh\sshd_config"
    if (Test-Path $configPath) {
        notepad $configPath
    } else {
        Write-Host "El archivo de configuracion no existe. Asegurese de que SSH esté instalado."
    }
}

# Funcion para reiniciar el servicio SSH
Function Restart-SSH {
    Write-Host "Reiniciando servicio SSH..."
    Restart-Service sshd
    Write-Host "Servicio SSH reiniciado."
}

# Funcion para verificar el estado de SSH
Function Check-SSHStatus {
    Write-Host "Estado del servicio SSH:"
    Get-Service sshd
}

# Funcion principal con el menu actualizado
Function MainMenu {
    do {
        Clear-Host
        Write-Host "----------------------------"
        Write-Host "Menu de Configuracion "
        Write-Host "1. Instalar DNS"
        Write-Host "2. Configurar IP Fija"
        Write-Host "3. Configurar DNS"
        Write-Host "4. Instalar DHCP"
        Write-Host "5. Configurar DHCP"
        Write-Host "6. Instalar SSH"
        Write-Host "7. Habilitar SSH"
        Write-Host "8. Configurar SSH"
        Write-Host "9. Reiniciar SSH"
        Write-Host "10. Ver estado de SSH"
        Write-Host "11. Salir"
        Write-Host "----------------------------"
        $choice = Read-Host "Seleccione una opcion (1-11)"
        
        switch ($choice) {
            1 { Install-DNS }
            2 { Set-StaticIP }
            3 {
                $domain = Read-Host "Ingrese el dominio:"
                $ipAddress = Read-Host "Ingrese la IP del servidor para ligar al dominio ($domain)"
                
                if (-not [System.Net.IPAddress]::TryParse($ipAddress, [ref]$null)) {
                    Write-Host "La IP ingresada no es valida. Intente nuevamente."
                    break
                }
                
                Create-DNSZone -Domain $domain
                Create-DNSRecords -Domain $domain -IpAddress $ipAddress
            }
            4 { Install-DHCP }
            5 {
                $Subred = Read-Host "Introduce la subred (ejemplo: 192.168.1.0)"
                $RangoInicio = Read-Host "Introduce el rango de inicio de IP (ejemplo: 192.168.1.100)"
                $RangoFinal = Read-Host "Introduce el rango final de IP (ejemplo: 192.168.1.200)"
                $Mascara = "255.255.255.0"
                $Gateway = Read-Host "Introduce la puerta de enlace (ejemplo: 192.168.1.1)"
                $DNS = Read-Host "Introduce los servidores DNS separados por comas (ejemplo: 8.8.8.8,8.8.4.4)"
                $ExclusionStart = Read-Host "Introduce la IP de inicio de exclusión (presiona Enter si no aplica)"
                $ExclusionEnd = Read-Host "Introduce la IP final de exclusión (presiona Enter si no aplica)"
                $DomainName = Read-Host "Introduce el nombre de dominio (opcional, presiona Enter si no aplica)"
                
                $ScopeName = "Scope_Local"
                
                # Llamar a la función con los parámetros ingresados
                Configure-DHCP -ScopeName $ScopeName -StartRange $RangoInicio -EndRange $RangoFinal -SubnetMask $Mascara `
                               -Gateway $Gateway -ExclusionStart $ExclusionStart -ExclusionEnd $ExclusionEnd `
                               -DnsServers $DNS -DomainName $DomainName
                
                # Reiniciar y configurar servicio DHCP
                Restart-Service DHCPServer
                Set-Service DHCPServer -StartupType Automatic
                
                Write-Host "Estado del servicio DHCP:" -ForegroundColor Cyan
                Get-Service DHCPServer
            }
            6 { Install-SSH }
            7 { Enable-SSH }
            8 { Configure-SSH }
            9 { Restart-SSH }
            10 { Check-SSHStatus }
            11 {
                Write-Host "Saliendo del programa..."
                break
            }
            default {
                Write-Host "Opcion no valida. Intente nuevamente."
            }
        }
        Pause
    } while ($choice -ne 11)
}

# Ejecutar el menu principal
MainMenu