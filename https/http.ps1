.\funciones_ftpcito1.ps1
.\funciones_ftpcito2.ps1
.\funciones_http.ps1



Function MenuMain {
    	do {
		Clear-Host
        	Write-Host "----------------------------"
        	Write-Host "Menu"
		Write-Host "Instalar servicio por: "
        	Write-Host "1. Web."
        	Write-Host "2. FTP."
        	Write-Host "3. Regresar al menu principal."
        	Write-Host "----------------------------"
		$choice = Read-Host "Seleccione una opcion (1-3)"

        	switch ($choice) {
            	1 { MenuHTTP }
        	2 { MenuFTPcito }
		3 { return }
        	default { Write-Host "Opcion no valida. Intente nuevamente." }
	}
		Pause
	} while ($choice -ne 3) 
}


# Función para el menú FTP
Function MenuFTPcito {
    	do {
		Clear-Host
        	Write-Host "----------------------------"
        	Write-Host "Menu FTP"
        	Write-Host "1. Instalar y configurar FTP."
        	Write-Host "2. Crear usuarios para FTP."
            Write-Host "3. Crear carpetas y descargar instaladores en carpetas asignadas."
		Write-Host "4. Conectar FTP."
        	Write-Host "5. Regresar al menu principal."
        	Write-Host "----------------------------"
		$choice = Read-Host "Seleccione una opcion (1-5)"

        	switch ($choice) {
            	1 {
    			Install-FTP
    			Configure-FTP
			}
		2 { 
			Configure-Users
		}
                	3 {
                                     Download-Tomcat-Installers -TargetDir $TARGET_DIR
                	            Download-Nginx-Installers -NTargetDir $NTARGET_DIR
			}
        	4 { ConnectAndInstallFromFTP }
		5 { return }
        	default { Write-Host "Opcion no valida. Intente nuevamente." }
	}
		Pause
	}while ($choice -ne 5) 
}


# Función para el menú HTTP
Function MenuHTTP {
    	do {
		Clear-Host
        	Write-Host "----------------------------"
        	Write-Host "Menu HTTP"
        	Write-Host "1. Instalar IIS."
        	Write-Host "2. Instalar Tomcat."
		Write-Host "3. Instalar Nginx"
        	Write-Host "4. Regresar al menu principal."
        	Write-Host "----------------------------"
		$choice = Read-Host "Seleccione una opcion (1-4)"

        	switch ($choice) {
            	1 {
            		$puerto = Solicitar-Puerto -mensaje "Ingrese el puerto HTTP para IIS" -defaultPort 80
            		if ($puerto) { Conf-IIS -port $puerto }
       			 }
        	2 {
            		$puerto = Solicitar-Puerto -mensaje "Ingrese el puerto HTTP para Tomcat" -defaultPort 8080
            		if ($puerto) {
                	Install-Tomcat -puerto $puerto 
            			}
        		}
        	3 { 
            		$puerto = Solicitar-Puerto -mensaje "Ingrese el puerto HTTP para Nginx" -defaultPort 80
            		if ($puerto) {
                	Dependencias    # Verificar Visual C++ (requisito para Nginx)
                	Install-Nginx -puerto $puerto 
            			}
        		}
		4 { return }
        	default { Write-Host "Opcion no valida. Intente nuevamente." }
	}
		Pause
	} while ($choice -ne 4) 
}