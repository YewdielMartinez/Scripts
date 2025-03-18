
# Menu Principal
Function MainMenu {
    do {
        Clear-Host
        Write-Host "--- Menu Principal ---"
        Write-Host "1. Configurar IP Fija"
        Write-Host "2. Menu DHCP"
        Write-Host "3. Menu DNS"
        Write-Host "4. Menu SSH"
        Write-Host "5. Menu FTP"
        Write-Host "6. Salir"
        $choice = Read-Host "Seleccione una opcion (1-6)"
        
        switch ($choice) {
            1 { Set-StaticIP }
            2 { .\dhcp.ps1 }
            3 { .\dns.ps1}
            4 { .\ssh.ps1 }
            5 { .\ftp.ps1 }
            6 { Write-Host "Saliendo del programa..."; break }
            default { Write-Host "Opcion no valida. Intente nuevamente." }
        }
        Pause
    } while ($choice -ne 6)
}

# Ejecutar el menu principal
MainMenu
