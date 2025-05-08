function install_xampp{
    
    #Seccion de instalacion de XAMPP
    New-Item -Path "C:\Installers" -ItemType Directory -Force | Out-Null

    # Descargar XAMPP (asegurate de tener curl en PowerShell v5+)
    $xamppUrl = "https://sourceforge.net/projects/xampp/files/XAMPP%20Windows/5.6.40/xampp-windows-x64-5.6.40-1-VC11-installer.exe/download"
    $outputPath = "C:\Installers\xampp-installer.exe"


    curl.exe -L $xamppUrl -o $outputPath

    # Ejecutar el instalador de XAMPP
    cd "C:\Installers"
    Start-Process -FilePath .\xampp-installer.exe
}