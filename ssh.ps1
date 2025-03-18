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
# Submenu SSH
Function SSH-Menu {
    do {
        Clear-Host
        Write-Host "--- Submenu SSH ---"
        Write-Host "1. Instalar SSH"
        Write-Host "2. Habilitar SSH"
        Write-Host "3. Configurar SSH"
        Write-Host "4. Reiniciar SSH"
        Write-Host "5. Ver estado de SSH"
        Write-Host "6. Volver al menu principal"
        $choice = Read-Host "Seleccione una opcion (1-6)"
        
        switch ($choice) {
            1 { Install-SSH }
            2 { Enable-SSH }
            3 { Configure-SSH }
            4 { Restart-SSH }
            5 { Check-SSHStatus }
            6 { .\main.ps1 }
            default { Write-Host "Opcion no valida. Intente nuevamente." }
        }
        Pause
    } while ($choice -ne 6)
}
SSH-Menu