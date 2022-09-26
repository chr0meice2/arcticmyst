; Script generated by the Inno Setup Script Wizard.
; SEE THE DOCUMENTATION FOR DETAILS ON CREATING INNO SETUP SCRIPT FILES!

#define MyAppName "ArcticMyst Security"
#define MyAppVersion "20220925a"
#define MyAppPublisher "DeepTide, LLC"
#define MyAppURL "https://deeptide.com"

[Setup]
; NOTE: The value of AppId uniquely identifies this application. Do not use the same AppId value in installers for other applications.
; (To generate a new GUID, click Tools | Generate GUID inside the IDE.)
AppId={{04A2247B-D3A3-41D8-B47C-49D0CDDEDDB5}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
;AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName=c:\programdata\ArcticMyst
DisableDirPage=yes
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
; Uncomment the following line to run in non administrative install mode (install for current user only.)
;PrivilegesRequired=lowest
OutputBaseFilename=arcticsetup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
SetupIconFile=blue2.ico
UninstallDisplayIcon={app}\arcticmyst.exe,0
LicenseFile=LICENSE.txt
SetupMutex=MystMutexSetup,Global\MystMutexSetup
PrivilegesRequired=admin

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "T:\deeptide\mysthookproc\mysthookproc64.dll"; DestDir: "{app}"; Flags: ignoreversion uninsneveruninstall  
Source: "T:\deeptide\mysthookproc\mysthookproc32.dll"; DestDir: "{app}"; Flags: ignoreversion uninsneveruninstall 
Source: "T:\deeptide\mystsvc\mystsvc.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "T:\deeptide\arcticmyst.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "T:\deeptide\paexec.exe"; DestDir: "{app}"; Flags: ignoreversion
; NOTE: Don't use "Flags: ignoreversion" on any shared system files

[Run]
Filename: "taskkill.exe"; Parameters: "/IM mystsvc.exe /F" ; Flags: runhidden
//Filename: "taskkill.exe"; Parameters: "/IM mystinstaller.exe /F" ; Flags: runhidden
Filename: "taskkill.exe"; Parameters: "/IM arcticmyst.exe /F" ; Flags: runhidden
Filename: "sc.exe"; Parameters: "create ArcticMyst start= auto DisplayName= ArcticMyst binPath= {app}\mystsvc.exe" ; Flags: runhidden
Filename: "sc.exe"; Parameters: "start ArcticMyst"; Flags: runhidden

[UninstallRun]
Filename: "taskkill.exe"; Parameters: "/IM mystsvc.exe /F" ; Flags: runhidden; RunOnceId: "MystUninstall1"
//Filename: "taskkill.exe"; Parameters: "/IM mystinstaller.exe /F" ; Flags: runhidden; RunOnceId: "MystUninstall2"
Filename: "taskkill.exe"; Parameters: "/IM arcticmyst.exe /F" ; Flags: runhidden  ; RunOnceId: "MystUninstall3"
Filename: "sc.exe"; Parameters: "stop ArcticMyst" ; Flags: runhidden; RunOnceId: "MystUninstall4"
Filename: "sc.exe"; Parameters: "delete ArcticMyst" ; Flags: runhidden; RunOnceId: "MystUninstall5"


//[UninstallDelete]
//Type: files; Name: "{app}\mystinstaller.exe"



[Code]

{ ///////////////////////////////////////////////////////////////////// }
function GetUninstallString(): String;
var
  sUnInstPath: String;
  sUnInstallString: String;
begin
  sUnInstPath := ExpandConstant('Software\Microsoft\Windows\CurrentVersion\Uninstall\{#emit SetupSetting("AppId")}_is1');
  sUnInstallString := '';
  if not RegQueryStringValue(HKLM, sUnInstPath, 'UninstallString', sUnInstallString) then
    RegQueryStringValue(HKCU, sUnInstPath, 'UninstallString', sUnInstallString);
  Result := sUnInstallString;
end;


{ ///////////////////////////////////////////////////////////////////// }
function IsUpgrade(): Boolean;
begin
  Result := (GetUninstallString() <> '');
end;


{ ///////////////////////////////////////////////////////////////////// }
function UnInstallOldVersion(): Integer;
var
  sUnInstallString: String;
  iResultCode: Integer;
begin
{ Return Values: }
{ 1 - uninstall string is empty }
{ 2 - error executing the UnInstallString }
{ 3 - successfully executed the UnInstallString }

  { default return value }
  Result := 0;

  { get the uninstall string of the old app }
  sUnInstallString := GetUninstallString();
  if sUnInstallString <> '' then begin
    sUnInstallString := RemoveQuotes(sUnInstallString);
    if Exec(sUnInstallString, '/VERYSILENT /NORESTART /SUPPRESSMSGBOXES','', SW_HIDE, ewWaitUntilTerminated, iResultCode) then
      Result := 3
    else
      Result := 2;
  end else
    Result := 1;
end;


function InitializeSetup(): Boolean;
var
  ErrorCode: Integer;  
   WHandle: HWND;
  Sendl:  longint;
  a: Integer;
  begin        


    begin
    if (IsUpgrade()) then
    begin
      UnInstallOldVersion();
    end;
  end;



               for a := 1  to 60 do
             
             begin
                Sleep(1000);
                WHandle := FindWindowByClassName('TideSecOps');
                if WHandle <> 0 then begin
                      sendl:=SendMessage(WHandle,1026,0,0);
                end else 
                begin
                    break
                end;
             end;

 
 
 
          DeleteFile('c:\programdata\ArcticMyst\mysthookproc64.dll');
          DeleteFile('c:\programdata\ArcticMyst\mysthookproc32.dll');


        ShellExec('open',
          'taskkill.exe',
          '/IM mystsvc.exe /F','',SW_HIDE,ewNoWait,ErrorCode);
         ShellExec('open',
          'taskkill.exe',
          '/IM arcticmyst.exe /F','',SW_HIDE,ewNoWait,ErrorCode);
    //    ShellExec('open',
    //      'taskkill.exe',
    //      '/IM mystinstaller.exe /F','',SW_HIDE,ewNoWait,ErrorCode);
        result := True;
  end;

function InitializeUninstall(): Boolean;
var
  ErrorCode: Integer;  
  WHandle: HWND;
  Sendl:  longint;
  a: Integer;

  begin            
  
    
             for a := 1  to 60 do
             
             begin
                Sleep(1000);
                WHandle := FindWindowByClassName('TideSecOps');
                if WHandle <> 0 then begin
                      sendl:=SendMessage(WHandle,1026,0,0);
                end else 
                begin
                    break
                end;
             end;

 
 
 
          DeleteFile(ExpandConstant('{app}')+'\mysthookproc64.dll');
          DeleteFile(ExpandConstant('{app}')+'\mysthookproc32.dll');
        ShellExec('open',
          'taskkill.exe',
          '/IM mystsvc.exe /F','',SW_HIDE,ewNoWait,ErrorCode);
         ShellExec('open',
          'taskkill.exe',
          '/IM arcticmyst.exe /F','',SW_HIDE,ewNoWait,ErrorCode);
      //  ShellExec('open',
       //   'taskkill.exe',
        //  '/IM mystinstaller.exe /F','',SW_HIDE,ewNoWait,ErrorCode);
        result := True;
  end;


