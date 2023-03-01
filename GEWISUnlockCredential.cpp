//
// GEWIS, 2020-2023
// 
// Previous work by: 
// - Microsoft Corporation, 2016
// This code is based on https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/Win7Samples/security/credentialproviders/samplecredentialprovider
// 

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>
#include "GEWISUnlockCredential.h"
#include "guid.h"
#include "helpers.h"

// The following is used for our direct sign in functions in the serialization
#include <atlstr.h>
#include <atlbase.h>
#include <atlsecurity.h>

// To allow signing off
#include <wtsapi32.h>
#pragma comment(lib, "wtsapi32.lib")

GEWISUnlockCredential::GEWISUnlockCredential() :
    _cRef(1),
    _pCredProvCredentialEvents(nullptr),
    _pszUserSid(nullptr),
    _pszQualifiedUserName(nullptr),
    _fIsLocalUser(false),
    _fChecked(false),
    _dwComboIndex(0)
{
    DllAddRef();

    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
}

GEWISUnlockCredential::~GEWISUnlockCredential()
{
    if (_rgFieldStrings[GFI_PASSWORD])
    {
        size_t lenPassword = wcslen(_rgFieldStrings[GFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[GFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[GFI_PASSWORD]));
    }
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }
    CoTaskMemFree(_pszUserSid);
    CoTaskMemFree(_pszQualifiedUserName);
    DllRelease();
}


// Initializes one credential with the field information passed in.
// Set the value of the GFI_HEADING field to pwzUsername.
HRESULT GEWISUnlockCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    _In_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR const* rgcpfd,
    _In_ FIELD_STATE_PAIR const* rgfsp,
    _In_ ICredentialProviderUser* pcpUser)
{
    HRESULT hr = S_OK;
    _cpus = cpus;

    GUID guidProvider;
    pcpUser->GetProviderID(&guidProvider);
    _fIsLocalUser = (guidProvider == Identity_LocalUserProvider);

    // Copy the field descriptors for each field. This is useful if you want to vary the field
    // descriptors based on what Usage scenario the credential was created for.
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

    // Initialize the String value of all the fields.
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Room Responsible Menu", &_rgFieldStrings[GFI_LABEL]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Room Responsible Unlock Form", &_rgFieldStrings[GFI_HEADING]);
    }
    if (SUCCEEDED(hr))
    {
        hr = pcpUser->GetStringValue(PKEY_Identity_QualifiedUserName, &_rgFieldStrings[GFI_USERNAME]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[GFI_PASSWORD]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Kick", &_rgFieldStrings[GFI_SUBMIT_BUTTON]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Kick user with Multivers open", &_rgFieldStrings[GFI_MULTIVERS_CHECKBOX]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"About GEWISUnlock", &_rgFieldStrings[GFI_MOREINFO_LINK]);
    }
    if (SUCCEEDED(hr))
    {
        hr = pcpUser->GetStringValue(PKEY_Identity_QualifiedUserName, &_pszQualifiedUserName);
    }

    if (SUCCEEDED(hr))
    {
        if (MultiversRunning())
        {
            hr = SHStrDupW(L"Warning: Multivers is running!", &_rgFieldStrings[GFI_MULTIVERS_TEXT]);
        }
        else
        {
            _rgFieldStatePairs[GFI_MULTIVERS_TEXT] = { CPFS_HIDDEN, CPFIS_NONE };
            _rgFieldStatePairs[GFI_MULTIVERS_CHECKBOX] = { CPFS_HIDDEN, CPFIS_NONE };
            hr = SHStrDupW(L"Multivers is not running (should not be shown)", &_rgFieldStrings[GFI_MULTIVERS_TEXT]);
        }
    }

    if (SUCCEEDED(hr))
    {
        hr = pcpUser->GetSid(&_pszUserSid);
    }

    return hr;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT GEWISUnlockCredential::Advise(_In_ ICredentialProviderCredentialEvents* pcpce)
{
    if (_pCredProvCredentialEvents != nullptr)
    {
        _pCredProvCredentialEvents->Release();
    }
    return pcpce->QueryInterface(IID_PPV_ARGS(&_pCredProvCredentialEvents));
}

// LogonUI calls this to tell us to release the callback.
HRESULT GEWISUnlockCredential::UnAdvise()
{
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = nullptr;
    return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed)
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the
// field definitions. But if you want to do something
// more complicated, like change the contents of a field when the tile is
// selected, you would do it here.
HRESULT GEWISUnlockCredential::SetSelected(_Out_ BOOL* pbAutoLogon)
{
    HRESULT hr = S_OK;

    // Do not automatically submit on selecting
    *pbAutoLogon = FALSE;

    return hr;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is. The most common thing to do here (which we do below)
// is to clear out the password field.
HRESULT GEWISUnlockCredential::SetDeselected()
{
    HRESULT hr = S_OK;
    if (_rgFieldStrings[GFI_PASSWORD])
    {
        size_t lenPassword = wcslen(_rgFieldStrings[GFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[GFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[GFI_PASSWORD]));

        CoTaskMemFree(_rgFieldStrings[GFI_PASSWORD]);
        hr = SHStrDupW(L"", &_rgFieldStrings[GFI_PASSWORD]);

        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, GFI_PASSWORD, _rgFieldStrings[GFI_PASSWORD]);
        }
    }

    return hr;
}

// Get info for a particular field of a tile. Called by logonUI to get information
// to display the tile.
HRESULT GEWISUnlockCredential::GetFieldState(DWORD dwFieldID,
    _Out_ CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
    _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
    HRESULT hr;

    // Validate our parameters.
    if ((dwFieldID < ARRAYSIZE(_rgFieldStatePairs)))
    {
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID
HRESULT GEWISUnlockCredential::GetStringValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ PWSTR* ppwsz)
{
    HRESULT hr;
    *ppwsz = nullptr;

    // Check to make sure dwFieldID is a legitimate index
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors))
    {
        // Make a copy of the string and return that. The caller
        // is responsible for freeing it.
        hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Get the image to show in the user tile
// Trial and error learns that it should be a A8R8G8B8 bitmap image (4*8 = 32 bits)
HRESULT GEWISUnlockCredential::GetBitmapValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ HBITMAP* phbmp)
{
    HRESULT hr;
    *phbmp = nullptr;

    if ((GFI_TILEIMAGE == dwFieldID))
    {
        HBITMAP hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
        if (hbmp != nullptr)
        {
            hr = S_OK;
            *phbmp = hbmp;
        }
        else
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be
// adjacent to. We recommend that the submit button is placed next to the last
// field which the user is required to enter information in. Optional fields
// should be below the submit button.
HRESULT GEWISUnlockCredential::GetSubmitButtonValue(DWORD dwFieldID, _Out_ DWORD* pdwAdjacentTo)
{
    HRESULT hr;

    if (GFI_SUBMIT_BUTTON == dwFieldID)
    {
        // pdwAdjacentTo is a pointer to the fieldID you want the submit button to
        // appear next to.
        *pdwAdjacentTo = GFI_PASSWORD;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets the value of a field which can accept a string as a value.
// This is called on each keystroke when a user types into an edit field
HRESULT GEWISUnlockCredential::SetStringValue(DWORD dwFieldID, _In_ PCWSTR pwz)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft ||
            CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        PWSTR* ppwszStored = &_rgFieldStrings[dwFieldID];
        CoTaskMemFree(*ppwszStored);
        hr = SHStrDupW(pwz, ppwszStored);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Returns whether a checkbox is checked or not as well as its label.
HRESULT GEWISUnlockCredential::GetCheckboxValue(DWORD dwFieldID, _Out_ BOOL* pbChecked, _Outptr_result_nullonfailure_ PWSTR* ppwszLabel)
{
    HRESULT hr;
    *ppwszLabel = nullptr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_CHECKBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        *pbChecked = _fChecked;
        hr = SHStrDupW(_rgFieldStrings[GFI_MULTIVERS_CHECKBOX], ppwszLabel);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets whether the specified checkbox is checked or not.
HRESULT GEWISUnlockCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_CHECKBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        _fChecked = bChecked;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Returns the number of items to be included in the combobox (pcItems), as well as the
// currently selected item (pdwSelectedItem).
HRESULT GEWISUnlockCredential::GetComboBoxValueCount(DWORD dwFieldID, _Out_ DWORD* pcItems, _Deref_out_range_(< , *pcItems) _Out_ DWORD* pdwSelectedItem)
{
    HRESULT hr;
    *pcItems = 0;
    *pdwSelectedItem = 0;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        *pcItems = ARRAYSIZE(s_rgComboBoxStrings);
        *pdwSelectedItem = 0;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called iteratively to fill the combobox with the string (ppwszItem) at index dwItem.
HRESULT GEWISUnlockCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, _Outptr_result_nullonfailure_ PWSTR* ppwszItem)
{
    HRESULT hr;
    *ppwszItem = nullptr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        hr = SHStrDupW(s_rgComboBoxStrings[dwItem], ppwszItem);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called when the user changes the selected item in the combobox.
HRESULT GEWISUnlockCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        _dwComboIndex = dwSelectedItem;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called when the user clicks a command link.
HRESULT GEWISUnlockCredential::CommandLinkClicked(DWORD dwFieldID)
{
    HRESULT hr = S_OK;

    // Validate parameter.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMMAND_LINK == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        HWND hwndOwner = nullptr;
        switch (dwFieldID)
        {
        case GFI_MOREINFO_LINK:
            if (_pCredProvCredentialEvents)
            {
                _pCredProvCredentialEvents->OnCreatingWindow(&hwndOwner);
            }

            // Pop a messagebox indicating the click.
            ::MessageBox(hwndOwner, L"Version: 2.0\r\nAuthor: GEWIS, 2020-2022\r\n\r\nGEWISUnlock is a tool to sign off other people when the PC is locked. Note that it is not possible to unlock a session using this credential provider unless you are trying to kick yourself.", L"About GEWISUnlock", MB_OK + MB_ICONINFORMATION + MB_SYSTEMMODAL);
            break;
        default:
            hr = E_INVALIDARG;
        }

    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Collect the username and password into a serialized credential for the correct usage scenario
// (logon/unlock is what's demonstrated in this sample).  LogonUI then passes these credentials
// back to the system to log on.
HRESULT GEWISUnlockCredential::GetSerialization(_Out_ CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    _Outptr_result_maybenull_ PWSTR* ppwszOptionalStatusText,
    _Out_ CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    HRESULT hr = E_UNEXPECTED;
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    ZeroMemory(pcpcs, sizeof(*pcpcs));

    // Store the Window owner so we can create message boxes later
    HWND hwndOwner = NULL;
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->OnCreatingWindow(&hwndOwner);
    }

    BOOL multiChecked;
    PWSTR multiLabel; //We don't use this
    GEWISUnlockCredential::GetCheckboxValue(GFI_MULTIVERS_CHECKBOX, &multiChecked, &multiLabel);
    if (!multiChecked && MultiversRunning())
    {
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        SHStrDupW(L"You are trying to sign out a user while Multivers is running.\r\nTo confirm, please check the box indicating that you understand the risks of doing that.", ppwszOptionalStatusText);
        return HRESULT(S_OK);
    }

    // For local user, the domain and user name can be split from _pszQualifiedUserName (domain\username).
    // CredPackAuthenticationBuffer() cannot be used because it doesn't work in the unlock scenario.
    if (_fIsLocalUser)
    {
        PWSTR pwzProtectedPassword;
        hr = ProtectIfNecessaryAndCopyPassword(_rgFieldStrings[GFI_PASSWORD], _cpus, &pwzProtectedPassword);
        if (SUCCEEDED(hr))
        {
            PWSTR pszDomain = L"";
            PWSTR pszUsername = L"";
            PWSTR currentUser = L"";
            hr = SplitDomainAndUsername(_pszQualifiedUserName, &pszDomain, &currentUser);
            if (wcschr(_rgFieldStrings[GFI_USERNAME], L'\\') == nullptr)
            {
                // The user did not specify a domain, so we have to assume they mean the same domain as the current user
                if (SUCCEEDED(hr))
                {
                    //We are able to get a domain from the current user
                    pszUsername = StrDupW(_rgFieldStrings[GFI_USERNAME]);
                }
            }

            // We don't have a username yet
            if (wcslen(pszUsername) == 0)
            {
                hr = SplitDomainAndUsername(_rgFieldStrings[GFI_USERNAME], &pszDomain, &pszUsername);
            }

            if (SUCCEEDED(hr))
            {
                if (currentUser != nullptr && wcscmp(currentUser, pszUsername) == 0)
                {
                    // The current user is the same one as the one trying to unlock the computer
                    // so we just open the session
                    // If this check fails, no harm done; Windows will return a "This computer is locked. Only the signed-in user can unlock the computer"

                    KERB_INTERACTIVE_UNLOCK_LOGON kiul;
                    hr = KerbInteractiveUnlockLogonInit(pszDomain, pszUsername, pwzProtectedPassword, _cpus, &kiul);
                    if (SUCCEEDED(hr))
                    {
                        hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);
                        if (SUCCEEDED(hr))
                        {
                            ULONG ulAuthPackage;
                            hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                            if (SUCCEEDED(hr))
                            {
                                // We set the credential and tell Windows we are done
                                // Any authentication failures will be handled by Windows (it is just a regular unlock anyway)
                                pcpcs->ulAuthenticationPackage = ulAuthPackage;
                                pcpcs->clsidCredentialProvider = CLSID_GEWUnlockv2;
                                *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                            }
                        }
                    }
                }
                else
                {
                    // We use a login session to verify the user before passing on serialization so we can also use another account
                    ATL::CAccessToken aToken;

                    // If there are cases where the user that is unlcoking the workstation does not have "Log on to this workstation interactively" permissions (e.g. admin accounts)
                    // You may decide to perform a LOGON32_LOGON_NETWORK login (but that will exclude users who can't "Access this computer over the network")
                    // https://learn.microsoft.com/en-us/windows/win32/secauthz/account-rights-constants
                    if (!aToken.LogonUserW(pszUsername, pszDomain, pwzProtectedPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT))
                    {
                        //Sleep(5000);
                        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
                        SHStrDupW(L"Incorrect password or username.", ppwszOptionalStatusText);
                        return HRESULT(S_OK);
                    }

                    ATL::CTokenGroups groups;
                    if (!aToken.GetGroups(&groups))
                    {
                        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
                        SHStrDupW(L"Unable to check group membership which is needed to determine if you can sign out other users.", ppwszOptionalStatusText);
                        return HRESULT(S_OK);
                    }

                    // Get the group of which users must be a member from that is stored in the registry
                    ATL::CSid::CSidArray groupSids;
                    ATL::CAtlArray<DWORD> groupAttribs;
                    ATL::CSid authorizedGroup;
                    GetAuthorizedGroup(&authorizedGroup);

                    // Iterate over all groups and check if the user is a member
                    // We use this because we can't easily determine membership of the authorizedGroup nor are we guaranteed the user has access to the group
                    // the code below may omit groups the user can't read, but sometimes these are also included. (If you happen to do this, please verify this in detail)
                    bool bIsAuthorized = false;
                    groups.GetSidsAndAttributes(&groupSids, &groupAttribs);
                    for (UINT i = 0; !bIsAuthorized && i < groupSids.GetCount(); ++i)
                        bIsAuthorized = groupSids.GetAt(i) == authorizedGroup;

                    // Check wheter the new user has permission
                    if (bIsAuthorized)
                    {
                        // https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtslogoffsession
                        if (WTSLogoffSession(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, true) != 0)
                        {
                            // It worked, we tell the user (they won't see it in Win10 and Win11, but we don't mind because it is clear what happened)
                            *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
                            SHStrDupW(L"The user was successfully signed out.", ppwszOptionalStatusText);
                            return HRESULT(S_OK);
                        }
                        else
                        {
                            *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
                            SHStrDupW(L"An error occured and the user could not be signed out.", ppwszOptionalStatusText);
                            return HRESULT(S_OK);
                        }
                    }
                    else
                    {
                        PWSTR errorMessage = static_cast<PWSTR>(CoTaskMemAlloc(sizeof(wchar_t) * 256));
                        if (errorMessage != nullptr)
                        {
                            ZeroMemory(errorMessage, sizeof(wchar_t) * 255);
                            StringCchCat(errorMessage, 255, L"It does not look like you are a member of '");
                            StringCchCat(errorMessage, 255, ATL::CSid(authorizedGroup).AccountName());
                            StringCchCat(errorMessage, 255, L"' which is required to sign off another user.\r\n\r\nPlease contact your system administrator if you think this is an error.");

                            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
                            SHStrDupW(errorMessage, ppwszOptionalStatusText);
                            return HRESULT(S_OK);
                        }
                    }

                }
            }
            else
            {
                *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
                SHStrDupW(L"Unable to split domain name and username. Perhaps the username was malformed.", ppwszOptionalStatusText);
                return HRESULT(S_OK);
            }
            CoTaskMemFree(pszDomain);
            CoTaskMemFree(pszUsername);
            CoTaskMemFree(currentUser);

        }
        CoTaskMemFree(pwzProtectedPassword);
    }
    else
    {
        //DWORD dwAuthFlags = CRED_PACK_PROTECTED_CREDENTIALS | CRED_PACK_ID_PROVIDER_CREDENTIALS;

        ::MessageBox(hwndOwner, L"This tile was never meant to be associated with a non-local user tile", L"An error has occured", 0);

    }
    return hr;
}

struct REPORT_RESULT_STATUS_INFO
{
    NTSTATUS ntsStatus;
    NTSTATUS ntsSubstatus;
    PWSTR     pwzMessage;
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi;
};

static const REPORT_RESULT_STATUS_INFO s_rgLogonStatusInfo[] =
{
    { STATUS_LOGON_FAILURE, STATUS_SUCCESS, L"Incorrect password or username.", CPSI_ERROR, },
    { STATUS_ACCOUNT_RESTRICTION, STATUS_ACCOUNT_DISABLED, L"Your account looks disabled. This can happen when you are no longer an active member and did not renew your account.", CPSI_WARNING },
};

// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure.  For example, we have chosen to
// customize the error shown in the case of bad username/password and in the case of the account
// being disabled.
HRESULT GEWISUnlockCredential::ReportResult(NTSTATUS ntsStatus,
    NTSTATUS ntsSubstatus,
    _Outptr_result_maybenull_ PWSTR* ppwszOptionalStatusText,
    _Out_ CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    DWORD dwStatusInfo = (DWORD)-1;

    // Look for a match on status and substatus.
    for (DWORD i = 0; i < ARRAYSIZE(s_rgLogonStatusInfo); i++)
    {
        if (s_rgLogonStatusInfo[i].ntsStatus == ntsStatus && s_rgLogonStatusInfo[i].ntsSubstatus == ntsSubstatus)
        {
            dwStatusInfo = i;
            break;
        }
    }

    if ((DWORD)-1 != dwStatusInfo)
    {
        if (SUCCEEDED(SHStrDupW(s_rgLogonStatusInfo[dwStatusInfo].pwzMessage, ppwszOptionalStatusText)))
        {
            *pcpsiOptionalStatusIcon = s_rgLogonStatusInfo[dwStatusInfo].cpsi;
        }
    }

    // If we failed the logon, try to erase the password field.
    if (FAILED(HRESULT_FROM_NT(ntsStatus)))
    {
        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, GFI_PASSWORD, L"");
        }
    }

    // Since nullptr is a valid value for *ppwszOptionalStatusText and *pcpsiOptionalStatusIcon
    // this function can't fail.
    return S_OK;
}

// Gets the SID of the user corresponding to the credential.
HRESULT GEWISUnlockCredential::GetUserSid(_Outptr_result_nullonfailure_ PWSTR* ppszSid)
{
    *ppszSid = nullptr;
    HRESULT hr = E_UNEXPECTED;
    if (_pszUserSid != nullptr)
    {
        hr = SHStrDupW(_pszUserSid, ppszSid);
    }
    // Return S_FALSE with a null SID in ppszSid for the
    // credential to be associated with an empty user tile.

    return hr;
}

// GetFieldOptions to enable the password reveal button and touch keyboard auto-invoke in the password field.
HRESULT GEWISUnlockCredential::GetFieldOptions(DWORD dwFieldID,
    _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS* pcpcfo)
{
    *pcpcfo = CPCFO_NONE;

    if (dwFieldID == GFI_PASSWORD)
    {
        *pcpcfo = CPCFO_ENABLE_PASSWORD_REVEAL;
    }
    else if (dwFieldID == GFI_TILEIMAGE)
    {
        *pcpcfo = CPCFO_ENABLE_TOUCH_KEYBOARD_AUTO_INVOKE;
    }

    return S_OK;
}
