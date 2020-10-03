# NxCertDump
This program allows you to extract your Nintendo Switch's SSL client certificate from a PRODINFO dump (Atmosphère stores these as sd:/atmosphere/automatic_backups/SERIAL_PRODINFO.bin).

***DO NOT SHARE THIS FILE WITH ANYONE. THIS FILE WILL LET SOMEONE IMPERSONATE YOU ON NINTENDO SWITCH ONLINE AND POTENTIALLY GET YOU BANNED. KEEP IT SAFE.***

You will need `prod.keys`; this can be dumped with [Lockpick_RCM](https://github.com/shchmue/Lockpick_RCM) - it should be stored in ~/.switch/ or in the same directory as the program.

## Usage

This tool uses [.NET](https://dotnet.microsoft.com/download) - on Windows you'll need to use the EXE, and the DLL or main executable on macOS/Linux.

`NxCertDump.exe PATH_TO_PRODINFO` or `./NxCertDump PATH_TO_PRODINFO` - you may be able to drag and drop the PRODINFO bin onto the EXE on Windows.

The certificate will be dumped to `nx_tls_client_cert.pfx` - the password for the file will be `switch`.