# GEWIS Unlock tool
This is a simple Windows tool that allows (certain) users to sign off other users if [Fast User Switching](https://learn.microsoft.com/en-us/windows/win32/shell/fast-user-switching) is disabled.

The tool is tailored to the GEWIS use case (e.g. it includes a check if Multivers is running before signing out a user).

## Install
1. Compile the project
2. Copy the generated DLL (`GEWISUnlockV2CredentialProvider.dll`) to `C:\Windows\System32`
3. Register the DLL using the modifications in [register.reg](/blob/main/install/register.reg)

## Uninstall
1. Deregister the DLL using the modifications in [unregister.reg](/blob/main/install/unregister.reg)
2. Delete `C:\Windows\System32\GEWISUnlockV2CredentialProvider.dll`

## Configuration
Without code modification, there is one setting: the [SID](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers) of the group whose users may perform signouts. By default, this is the Power Users group.

Settings are stored in `HKLM\SOFTWARE\GEWISUnlock`. An example registry config can be found in [configure.reg](/blob/main/install/unregister.reg). 
