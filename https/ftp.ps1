. .\Wfunciones\funciones_ftp.ps1



# Función para el menú FTP
Function MenuFTP {
	do {
		Clear-Host
		Write-Host "----------------------------"
        	Write-Host "Menu FTP"
		Write-Host "1. Instalar FTP."
        	Write-Host "2. Configurar FTP."
		Write-Host "3. Configurar usuarios."
        	Write-Host "4. Regresar al menu principal."
		Write-Host "----------------------------"
		$choice = Read-Host "Seleccione una opcion (1-4)"

		switch ($choice) {
		1 { Install-FTP }
		2 { Configure-FTP }
		3 { Configure-Users }
		4 { return }
		default { Write-Host "Opcion no valida. Intente nuevamente." }
	}
		Pause
	} while ($choice -ne 4)
}