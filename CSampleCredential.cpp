//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
//

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>
#include "atlstr.h"
#include "CSampleCredential.h"
#include "guid.h"
#include <atlbase.h>
#include <atlsecurity.h>
#include <wtsapi32.h>
#include <string>
#include <sstream>
#pragma comment(lib, "wtsapi32.lib")

// CSampleCredential ////////////////////////////////////////////////////////

CSampleCredential::CSampleCredential():
    _cRef(1),
    _pCredProvCredentialEvents(NULL)
{
    DllAddRef();

    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
}

CSampleCredential::~CSampleCredential()
{
    if (_rgFieldStrings[SFI_PASSWORD])
    {
        // CoTaskMemFree (below) deals with NULL, but StringCchLength does not.
        size_t lenPassword = lstrlen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));
    }
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }

    DllRelease();
}

// Initializes one credential with the field information passed in.
// Set the value of the SFI_USERNAME field to pwzUsername.
// Optionally takes a password for the SetSerialization case.
HRESULT CSampleCredential::Initialize(
    __in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    __in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
    __in const FIELD_STATE_PAIR* rgfsp,
    __in PCWSTR pwzUsername,
    __in PCWSTR pwzPassword
    )
{
    HRESULT hr = S_OK;

    _cpus = cpus;

    // Copy the field descriptors for each field. This is useful if you want to vary the 
    // field descriptors based on what Usage scenario the credential was created for.
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

    // Initialize the String values of all the fields.
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(pwzUsername, &_rgFieldStrings[SFI_USERNAME]);
    }
	if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_EDIT_TEXT]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(pwzPassword ? pwzPassword : L"", &_rgFieldStrings[SFI_PASSWORD]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Submit", &_rgFieldStrings[SFI_SUBMIT_BUTTON]);
    }

    return S_OK;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CSampleCredential::Advise(
    __in ICredentialProviderCredentialEvents* pcpce
    )
{
    if (_pCredProvCredentialEvents != NULL)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = pcpce;
    _pCredProvCredentialEvents->AddRef();
    return S_OK;
}

// LogonUI calls this to tell us to release the callback.
HRESULT CSampleCredential::UnAdvise()
{
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = NULL;
    return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed).
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the 
// field definitions.  But if you want to do something
// more complicated, like change the contents of a field when the tile is
// selected, you would do it here.
HRESULT CSampleCredential::SetSelected(__out BOOL* pbAutoLogon)  
{
    *pbAutoLogon = FALSE;  

    return S_OK;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is. The most common thing to do here (which we do below)
// is to clear out the password field.
HRESULT CSampleCredential::SetDeselected()
{
    HRESULT hr = S_OK;
    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t lenPassword = lstrlen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));
    
        CoTaskMemFree(_rgFieldStrings[SFI_PASSWORD]);
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, _rgFieldStrings[SFI_PASSWORD]);
        }
    }

    return hr;
}

// Gets info for a particular field of a tile. Called by logonUI to get information to 
// display the tile.
HRESULT CSampleCredential::GetFieldState(
    __in DWORD dwFieldID,
    __out CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
    __out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis
    )
{
    HRESULT hr;

    // Validate paramters.
    if ((dwFieldID < ARRAYSIZE(_rgFieldStatePairs)) && pcpfs && pcpfis)
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

// Sets ppwsz to the string value of the field at the index dwFieldID.
HRESULT CSampleCredential::GetStringValue(
    __in DWORD dwFieldID, 
    __deref_out PWSTR* ppwsz
    )
{
    HRESULT hr;

    // Check to make sure dwFieldID is a legitimate index.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && ppwsz) 
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

// Gets the image to show in the user tile.
HRESULT CSampleCredential::GetBitmapValue(
    __in DWORD dwFieldID, 
    __out HBITMAP* phbmp
    )
{
    HRESULT hr;
    if ((SFI_TILEIMAGE == dwFieldID) && phbmp)
    {
        HBITMAP hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
        if (hbmp != NULL)
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
HRESULT CSampleCredential::GetSubmitButtonValue(
    __in DWORD dwFieldID,
    __out DWORD* pdwAdjacentTo
    )
{
    HRESULT hr;

    // Validate parameters.
    if ((SFI_SUBMIT_BUTTON == dwFieldID) && pdwAdjacentTo)
    {
        // pdwAdjacentTo is a pointer to the fieldID you want the submit button to appear next to.
        *pdwAdjacentTo = SFI_PASSWORD;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets the value of a field which can accept a string as a value.
// This is called on each keystroke when a user types into an edit field.
HRESULT CSampleCredential::SetStringValue(
    __in DWORD dwFieldID, 
    __in PCWSTR pwz      
    )
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

//------------- 
// The following methods are for logonUI to get the values of various UI elements and then communicate
// to the credential about what the user did in that field.  However, these methods are not implemented
// because our tile doesn't contain these types of UI elements
HRESULT CSampleCredential::GetCheckboxValue(
    __in DWORD dwFieldID, 
    __out BOOL* pbChecked,
    __deref_out PWSTR* ppwszLabel
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pbChecked);
    UNREFERENCED_PARAMETER(ppwszLabel);

    return E_NOTIMPL;
}

HRESULT CSampleCredential::GetComboBoxValueCount(
    __in DWORD dwFieldID, 
    __out DWORD* pcItems, 
    __out_range(<,*pcItems) DWORD* pdwSelectedItem
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pcItems);
    UNREFERENCED_PARAMETER(pdwSelectedItem);
    return E_NOTIMPL;
}

HRESULT CSampleCredential::GetComboBoxValueAt(
    __in DWORD dwFieldID, 
    __in DWORD dwItem,
    __deref_out PWSTR* ppwszItem
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(dwItem);
    UNREFERENCED_PARAMETER(ppwszItem);
    return E_NOTIMPL;
}

HRESULT CSampleCredential::SetCheckboxValue(
    __in DWORD dwFieldID, 
    __in BOOL bChecked
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(bChecked);

    return E_NOTIMPL;
}

HRESULT CSampleCredential::SetComboBoxSelectedValue(
    __in DWORD dwFieldId,
    __in DWORD dwSelectedItem
    )
{
    UNREFERENCED_PARAMETER(dwFieldId);
    UNREFERENCED_PARAMETER(dwSelectedItem);
    return E_NOTIMPL;
}

HRESULT CSampleCredential::CommandLinkClicked(__in DWORD dwFieldID)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    return E_NOTIMPL;
}
//------ end of methods for controls we don't have in our tile ----//

// Collect the username and password into a serialized credential for the correct usage scenario 
// (logon/unlock is what's demonstrated in this sample).  LogonUI then passes these credentials 
// back to the system to log on.
HRESULT CSampleCredential::GetSerialization(
    __out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    __out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs, 
    __deref_out_opt PWSTR* ppwszOptionalStatusText, 
    __out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
    )
{		
	HWND hwndOwner = NULL;
	
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->OnCreatingWindow(&hwndOwner);
    }
	
	// Get Users Token and verify that it's an authorized account
	bool bIsAuthorized = false;
	ATL::CAccessToken aToken;
	CString Input = _rgFieldStrings[SFI_EDIT_TEXT];
	
	LPCWSTR Domain;
	LPCWSTR User = _rgFieldStrings[SFI_EDIT_TEXT];
	int BackslashPosition = Input.Find(L"\\", 0);
	if (BackslashPosition != -1)
	{
		Domain = Input.Mid(0, BackslashPosition);
		User = Input.Mid(BackslashPosition + 1);
	}
	else
		Domain = NULL;
	
	PWSTR pwzProtectedPassword;
	ProtectIfNecessaryAndCopyPassword(_rgFieldStrings[SFI_PASSWORD], _cpus, &pwzProtectedPassword);

	//::MessageBox(hwndOwner, Domain, User, 0);
	if (!aToken.LogonUserW(User, Domain, pwzProtectedPassword, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT))
	{
		::MessageBox(hwndOwner, L"De opgegeven gebuikersgegevens zijn onjuist.", L"Fout bij aanmelding", 0);
		*pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
		return (HRESULT(E_ACCESSDENIED));
	}
	ATL::CTokenGroups groups;
	if (!aToken.GetGroups(&groups))
	{
		::MessageBox(hwndOwner, L"Groepslidmaatschap kon niet gecontroleerd worden.", L"Fout bij aanmelding", 0);
		*pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
		return (HRESULT(E_UNEXPECTED));
	}
	// Iterate through the access token's groups        
	// looking for a match against the builtin admins group.
	ATL::CSid::CSidArray groupSids;        
	ATL::CAtlArray<DWORD> groupAttribs;     

	// Determine the Searchfor Group
	// By Default, the local Administrators Group is used
    ATL::CSid SearchFor = ATL::Sids::PowerUsers();
	
	// Check if the registry key for an alternative SID is set and if so, try to find a group matching that SID
	HKEY key;
	if (RegOpenKey(HKEY_LOCAL_MACHINE, TEXT("Software\\GEWISUnlock\\"), &key) == ERROR_SUCCESS)
	{
		WCHAR value[512];
		DWORD dataSize = sizeof(value);
		if (RegQueryValueEx(key, L"AuthorizedGroup_SID", 0, NULL, (LPBYTE)value, &dataSize) == ERROR_SUCCESS &&
			value != NULL &&
			wcslen(value) > 0)
		{
			//::MessageBox(hwndOwner, value, L"SIDinfo", 0);
			PSID outSid;
			ConvertStringSidToSid(value, &outSid);
			ATL::CSid FoundSid = ATL::CSid((const SID*)outSid);

			// Only replace the Administrators Group if a corresponding SID was found
			if (wcslen(FoundSid.AccountName()) > 0 &&
				wcslen(FoundSid.Domain()) > 0)
				SearchFor = FoundSid;

			LocalFree(outSid);
		}

		RegCloseKey(key);
	}

	groups.GetSidsAndAttributes(&groupSids, &groupAttribs);        
	for (UINT i = 0; !bIsAuthorized && i < groupSids.GetCount(); ++i)
		bIsAuthorized = groupSids.GetAt(i) == SearchFor;
		
	// Check wheter the credentials are Authorized or not
	if (bIsAuthorized)
	{											
		WTSLogoffSession(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, false);
		*pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
		::MessageBox(hwndOwner, L"De gebruiker wordt afgemeld...", L"Success", 0);
		return (HRESULT(S_OK));
	}		
	else
	{	
		LPCWSTR GroupName = SearchFor.AccountName();
		LPCWSTR GroupDomain = SearchFor.Domain();
		LPCWSTR message = L"Alleen bestuursleden en CBCers kunnen andere gebruikers afmelden. Overige openhouders moeten het speciale openhouder-account gebruiken (zie de WhatsApp-groep) om de huidige gebruiker af te melden en kunnen daarna met hun eigen account inloggen.\n\nJe moet lid zijn van de groep [";
		std::wstring cs = std::wstring(message) + GroupDomain + L"\\" + GroupName + L"] in het domein.";
		::MessageBox(hwndOwner, cs.c_str(), L"Onvoldoende rechten", 0);
		*pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
		return (HRESULT(E_ACCESSDENIED));
	}
	
	// Leaving the rest of the function intact. It won't ever be executed anyway
	
	HRESULT hr;		
	
	UNREFERENCED_PARAMETER(ppwszOptionalStatusText);
    UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);

    WCHAR wsz[MAX_COMPUTERNAME_LENGTH+1];
    DWORD cch = ARRAYSIZE(wsz);

    if (GetComputerNameW(wsz, &cch))
    {
        //PWSTR pwzProtectedPassword;

        hr = ProtectIfNecessaryAndCopyPassword(_rgFieldStrings[SFI_PASSWORD], _cpus, &pwzProtectedPassword);

        if (SUCCEEDED(hr))
        {
            KERB_INTERACTIVE_UNLOCK_LOGON kiul;

            // Initialize kiul with weak references to our credential.
            hr = KerbInteractiveUnlockLogonInit(wsz, _rgFieldStrings[SFI_EDIT_TEXT], pwzProtectedPassword, _cpus, &kiul);

            if (SUCCEEDED(hr))
            {
                // We use KERB_INTERACTIVE_UNLOCK_LOGON in both unlock and logon scenarios.  It contains a
                // KERB_INTERACTIVE_LOGON to hold the creds plus a LUID that is filled in for us by Winlogon
                // as necessary.
                hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);

                if (SUCCEEDED(hr))
                {
                    ULONG ulAuthPackage;
                    hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                    if (SUCCEEDED(hr))
                    {
                        pcpcs->ulAuthenticationPackage = ulAuthPackage;
                        pcpcs->clsidCredentialProvider = CLSID_CSample;
 
                        // At this point the credential has created the serialized credential used for logon
                        // By setting this to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
                        // that we have all the information we need and it should attempt to submit the 
                        // serialized credential.
                        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                    }
                }
            }

            CoTaskMemFree(pwzProtectedPassword);
        }
    }
    else
    {
        DWORD dwErr = GetLastError();
        hr = HRESULT_FROM_WIN32(dwErr);
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
    { STATUS_ACCOUNT_RESTRICTION, STATUS_ACCOUNT_DISABLED, L"The account is disabled.", CPSI_WARNING },
};

// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure.  For example, we have chosen to 
// customize the error shown in the case of bad username/password and in the case of the account
// being disabled.
HRESULT CSampleCredential::ReportResult(
    __in NTSTATUS ntsStatus, 
    __in NTSTATUS ntsSubstatus,
    __deref_out_opt PWSTR* ppwszOptionalStatusText, 
    __out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
    )
{
    *ppwszOptionalStatusText = NULL;
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
    if (!SUCCEEDED(HRESULT_FROM_NT(ntsStatus)))
    {
        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, L"");
        }
    }

    // Since NULL is a valid value for *ppwszOptionalStatusText and *pcpsiOptionalStatusIcon
    // this function can't fail.
    return S_OK;
}