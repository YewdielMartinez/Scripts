function install_squirrel{
    
    #Seccion de instalacion de SquirrelMail
    # Ruta de instalación de Apache (htdocs)
    $htdocsPath = "C:\xampp\htdocs\squirrelmail"

    # Crear carpeta
    New-Item -Path $htdocsPath -ItemType Directory -Force | Out-Null

    # Descargar desde GitHub
    $zipUrl = "https://sourceforge.net/projects/squirrelmail/files/stable/1.4.22/squirrelmail-webmail-1.4.22.zip/download"
    $zipPath = "C:\Installers\squirrelmail.zip"

    curl.exe -L $zipUrl -o $zipPath

    # Descomprimir el archivo ZIP
    Expand-Archive -Path $zipPath -DestinationPath "C:\Installers" -Force

    # Copiar contenido a htdocs
    $extractedFolder = "C:\Installers\squirrelmail-webmail-1.4.22"
    Copy-Item -Path "$extractedFolder\*" -Destination $htdocsPath -Recurse -Force


    # Crear carpeta de configuración si no existe
    $configFolder = "$htdocsPath\config"
    New-Item -Path $configFolder -ItemType Directory -Force | Out-Null

    #Renombramos y editamos el archivo de configuracion
    Rename-Item -Path C:\xampp\htdocs\squirrelmail\config\config_default.php -NewName "config.php"            #Aqui el dominio que se configuro en la instalacion
    (Get-Content "C:\xampp\htdocs\squirrelmail\config\config.php") -replace '\$domain\s*=\s*''[^'']+'';', '$domain = ''localhost'';' | Set-Content "C:\xampp\htdocs\squirrelmail\config\config.php"
    (Get-Content "C:\xampp\htdocs\squirrelmail\config\config.php") -replace '\$data_dir\s*=\s*''[^'']+'';', '$data_dir = ''C:/xampp/htdocs/squirrelmail/data/'';' | Set-Content "C:\xampp\htdocs\squirrelmail\config\config.php"

    # Configurar permisos (IMPORTANTE)
    Write-Host "Configurando permisos..." -ForegroundColor Cyan
    try {
        $acl = Get-Acl $htdocsPath
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "Todos",  # O "IUSR" si usas IIS
            "FullControl",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )
        $acl.SetAccessRule($accessRule)
        Set-Acl -Path $htdocsPath -AclObject $acl
    } catch {
        Write-Warning "No se pudieron configurar los permisos: $_"
    }

}