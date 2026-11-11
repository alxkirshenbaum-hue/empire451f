[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
& ([scriptblock]::Create((Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/alxkirshenbaum-hue/empire451f/v0.2.10/bootstrap/windows.ps1').Content))
