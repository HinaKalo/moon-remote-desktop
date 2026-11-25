; Moon Remote Desktop x64, with the host service and EasyTier companion.
#ifndef AppVersion
  #error AppVersion must be supplied by the release build
#endif
#define Bin "{app}\installed\" + AppVersion
#ifdef BaseVersion
  #define BaseBin "{app}\installed\" + BaseVersion
#endif

[Setup]
AppId={{7E4B6C9A-2F51-4B8E-9C3A-8D1A2B5E4F01}
AppName=Moon Remote Desktop
AppVersion={#AppVersion}
AppPublisher=Moon
AppPublisherURL=https://remote.moonl.cloud
DefaultDirName={autopf}\MoonRemote
DisableDirPage=yes
UsePreviousAppDir=no
DefaultGroupName=Moon Remote Desktop
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
OutputDir=..\artifacts\installer
#ifdef BaseVersion
OutputBaseFilename=MoonRemote-Setup-{#AppVersion}-from-{#BaseVersion}-x64
#else
OutputBaseFilename=MoonRemote-Setup-{#AppVersion}-x64
#endif
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupLogging=yes
SetupIconFile=..\app\src\MoonRemote\Assets\MoonRemote.ico
UninstallDisplayIcon={#Bin}\MoonRemote.exe
RestartApplications=no
SetupMutex=MoonRemoteDesktopSetup

[Files]
#ifdef BaseVersion
#include DeltaFiles
#else
Source: "..\artifacts\release-win-x64\*"; DestDir: "{#Bin}"; Flags: ignoreversion recursesubdirs createallsubdirs
#endif

[Icons]
Name: "{group}\Moon Remote Desktop"; Filename: "{#Bin}\MoonRemote.exe"
Name: "{autodesktop}\Moon Remote Desktop"; Filename: "{#Bin}\MoonRemote.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"
Name: "lanrule"; Description: "Allow direct LAN connections on private networks"; Flags: unchecked

[Run]
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""Moon Remote LAN Direct {#AppVersion}"" dir=in action=allow protocol=UDP localport=47000 profile=private program=""{#Bin}\moonrd-service.exe"""; Tasks: lanrule; Flags: runhidden waituntilterminated
Filename: "{#Bin}\MoonRemote.exe"; Description: "Launch Moon Remote Desktop"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{#Bin}\moonrd-service.exe"; Parameters: "uninstall"; Flags: runhidden waituntilterminated; Check: OwnsService; RunOnceId: "UninstallMoonRemoteHost"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Moon Remote LAN Direct {#AppVersion}"""; Tasks: lanrule; Flags: runhidden waituntilterminated

[Code]
#ifdef BaseVersion
procedure VerifyBaseFile(const RelativePath, Expected: String);
var
  Source: String;
begin
  Source := ExpandConstant('{#BaseBin}\') + RelativePath;
  if not FileExists(Source) or (CompareText(GetSHA256OfFile(Source), Expected) <> 0) then
    RaiseException('Base file missing or changed: ' + RelativePath + '. Use the full installer.');
end;

procedure VerifyDeltaFile(const RelativePath, Expected: String);
begin
  if CompareText(GetSHA256OfFile(ExpandConstant('{#Bin}\') + RelativePath), Expected) <> 0 then
    RaiseException('Copied file failed verification: ' + RelativePath + '. Use the full installer.');
end;

#include DeltaChecks
#endif

function OwnsService: Boolean;
var
  ImagePath, Expected: String;
begin
  Expected := '"' + ExpandConstant('{#Bin}\moonrd-service.exe') + '" run';
  Result := RegQueryStringValue(HKLM64, 'SYSTEM\CurrentControlSet\Services\MoonRemoteHost', 'ImagePath', ImagePath)
            and (CompareText(ImagePath, Expected) = 0);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
#ifdef BaseVersion
var
  InstalledVersion: String;
#endif
begin
  Result := '';
  if CompareText(ExpandConstant('{app}'), ExpandConstant('{autopf}\MoonRemote')) <> 0 then begin
    Result := 'Moon Remote Host requires its protected Program Files directory.';
    Exit;
  end;
#ifdef BaseVersion
  if not RegQueryStringValue(HKLM64, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{7E4B6C9A-2F51-4B8E-9C3A-8D1A2B5E4F01}_is1',
    'DisplayVersion', InstalledVersion) or (CompareText(InstalledVersion, '{#BaseVersion}') <> 0) then begin
    Result := 'This incremental installer requires Moon Remote {#BaseVersion}. Use the full installer.';
    Exit;
  end;
  try
    VerifyUpdateBase;
  except
    Result := GetExceptionMessage;
  end;
#endif
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ExitCode: Integer;
begin
  if CurStep = ssPostInstall then begin
    if not Exec(ExpandConstant('{#Bin}\MoonRemote.exe'), '--configure-installed-host',
                ExpandConstant('{#Bin}'), SW_HIDE, ewWaitUntilTerminated, ExitCode) or (ExitCode <> 0) then
      RaiseException(Format('Moon Remote Host configuration failed (exit %d).', [ExitCode]));
  end;
end;
