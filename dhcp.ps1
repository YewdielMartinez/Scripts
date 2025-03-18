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
Function DHCP-Menu {
    do {
        Clear-Host
        Write-Host "--- Submenu DHCP ---"
        Write-Host "1. Instalar DHCP"
        Write-Host "2. Configurar DHCP"
        Write-Host "3. Volver al menu principal"
        $choice = Read-Host "Seleccione una opcion (1-3)"
        
        switch ($choice) {
            1 { Install-DHCP }
            2 {
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
            3 { .\main.ps1 }
            default { Write-Host "Opcion no valida. Intente nuevamente." }
        }
        Pause
    } while ($choice -ne 3)
}
DHCP-Menu