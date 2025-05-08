
function install_mercury{

    # Instalacion de mercury
    $downloadPath = "https://download-us.pmail.com/m32-480.exe"
    $downloadedPath = "$env:HOMEPATH\Downloads\mercury.exe"

    Invoke-WebRequest -Uri $downloadPath -Outfile $downloadedPath -UseBasicParsing -ErrorAction Stop
    cd $env:HOMEPATH\Downloads
    Start-Process .\mercury.exe

    New-NetFirewallRule -DisplayName "SMTP" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 25,110,143,587,993,995 -Profile Any -Enabled True
}

