[Setup]
Bits=32
AppName=Zebedee Secure Tunnel
AppVerName=Zebedee Secure Tunnel Version 2.5.1
AppCopyright=Copyright 1999-2003 by Neil Winton.
DefaultDirName={pf}\Zebedee
DefaultGroupName=Zebedee

LicenseFile=LICENCE.txt

[Files]
Source: "zebedee.exe"; DestDir: "{app}"
Source: "zebedee.ico"; DestDir: "{app}"
Source: "*.zbd"; DestDir: "{app}"
Source: "*.key"; DestDir: "{app}"
Source: "*.id"; DestDir: "{app}"
Source: "vncloopback.reg"; DestDir: "{app}"
Source: "*.html"; DestDir: "{app}"
Source: "ftpgw.tcl"; DestDir: "{app}"
Source: "passphrase.tcl"; DestDir: "{app}"
Source: "README.txt"; DestDir: "{app}"; Flags: isreadme
Source: "LICENCE.txt"; DestDir: "{app}"
Source: "GPL2.txt"; DestDir: "{app}"
Source: "CHANGES.txt"; DestDir: "{app}"

[Icons]
Name: "{group}\Run Zebedee Server"; Filename: "{app}\zebedee.exe"; Parameters: "-f server.zbd"; WorkingDir: "{app}"; IconFilename: "{app}\zebedee.ico"
Name: "{group}\Read Me"; Filename: "{app}\README.txt"
Name: "{group}\Documentation (English - 2.5)"; Filename: "{app}\zebedee.html"
Name: "{group}\Documentation (Japanese - 2.2)"; Filename: "{app}\zebedee.ja_JP.html"
Name: "{group}\Licence"; Filename: "{app}\LICENCE.txt"
Name: "{group}\Shortcut to Zebedee Directory"; Filename: "{app}"
Name: "{group}\Edit Server Configuration"; Filename: "notepad.exe"; Parameters: """{app}\server.zbd"""
Name: "{group}\Uninstall Zebedee Secure Tunnel"; Filename: "{uninstallexe}"

[Registry]
; Set up association with .zbd file type
Root: HKCR; Subkey: ".zbd"; ValueType: string; ValueName: ""; ValueData: "Zebedee"; Flags: uninsdeletevalue
Root: HKCR; Subkey: "Zebedee"; ValueType: string; ValueName: ""; ValueData: "Zebedee Config File"; Flags: uninsdeletekey
Root: HKCR; Subkey: "Zebedee\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\zebedee.ico" 
Root: HKCR; Subkey: "Zebedee\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\zebedee.exe"" -f ""%1""" 

