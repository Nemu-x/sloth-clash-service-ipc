OutFile "SlothClashServiceInstaller.exe"

InstallDir "$PROGRAMFILES\SlothClashService"

Page directory
Page instfiles

Section "Install"
    SetOutPath $INSTDIR

    ;FILES_PLACEHOLDER

    WriteUninstaller "$INSTDIR\Uninstall.exe"

    ExecShell "" "$INSTDIR\sloth-clash-service-install.exe"
SectionEnd

Section "Uninstall"
    Delete "$INSTDIR\*.exe"
    Delete "$INSTDIR\Uninstall.exe"
    RMDir "$INSTDIR"
SectionEnd
