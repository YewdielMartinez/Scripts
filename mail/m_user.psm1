function crear_usuario{
    param(
        [string]$nombre,
        [string]$contra
    )

    $mercuryMailPath = "C:\Mercury\Mail"
    $userPath = Join-Path $mercuryMailPath $nombre
    $pmFilePath = Join-Path $userPath "PASSWD.PM" # Nombre fijo del archivo PM

    if (Test-Path $userPath) {
        Write-Host "El usuario '$nombre' ya existe."
    } else {
        New-Item -Path $userPath -ItemType Directory -Force | Out-Null
        $pmFileContent = @"
# Mercury/32 User Information File
POP3_access: $contra
APOP_secret:
"@
        try {
            # Escribe el archivo PM con codificación ANSI
            $ansi = [System.Text.Encoding]::GetEncoding("Windows-1252")
            [System.IO.File]::WriteAllBytes($pmFilePath, $ansi.GetBytes($pmFileContent))
            Write-Host "Archivo 'PASSWD.PM' creado correctamente para el usuario '$nombre'."
        } catch {
            Write-Host "Error al crear el archivo 'PASSWD.PM': $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}