//
// GEWIS, 2020-2023
// 
// Previous work by: 
// - Microsoft Corporation, 2016
// This code is based on https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/Win7Samples/security/credentialproviders/samplecredentialprovider
// 

#pragma once
#include "helpers.h"

// The indexes of each of the fields in our credential provider's tiles. Note that we're
// using each of the nine available field types here.
enum GEWISUNLOCK_FIELD_ID
{
    GFI_TILEIMAGE         = 0,
    GFI_LABEL             = 1,
    GFI_HEADING           = 2,
    GFI_USERNAME          = 3,
    GFI_PASSWORD          = 4,
    GFI_SUBMIT_BUTTON     = 5,
    GFI_MOREINFO_LINK     = 6,
    GFI_MULTIVERS_TEXT    = 7,
    GFI_MULTIVERS_CHECKBOX= 8,
    GFI_NUM_FIELDS        = 9,  // Note: if new fields are added, keep NUM_FIELDS last.  This is used as a count of the number of fields
};

// The first value indicates when the tile is displayed (selected, not selected)
// the second indicates things like whether the field is enabled, whether it has key focus, etc.
struct FIELD_STATE_PAIR
{
    CREDENTIAL_PROVIDER_FIELD_STATE cpfs;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
};

// These two arrays are seperate because a credential provider might
// want to set up a credential with various combinations of field state pairs
// and field descriptors.

// The field state value indicates whether the field is displayed
// in the selected tile, the deselected tile, or both.
// The Field interactive state indicates when
static const FIELD_STATE_PAIR s_rgFieldStatePairs[] =
{
    { CPFS_DISPLAY_IN_BOTH,            CPFIS_NONE    },    // GFI_TILEIMAGE
    { CPFS_HIDDEN,                     CPFIS_NONE    },    // GFI_LABEL
    { CPFS_DISPLAY_IN_BOTH,            CPFIS_NONE    },    // GFI_HEADING
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_FOCUSED },    // GFI_USERNAME
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // GFI_PASSWORD
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // GFI_SUBMIT_BUTTON
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // GFI_MOREINFO_LINK
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // GFI_MULTIVERS_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // GFI_MULTIVERS_CHECKBOX
};

// Field descriptors
// These look complicated, because they are
// Docs on https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/ns-credentialprovider-credential_provider_field_descriptor
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgCredProvFieldDescriptors[] =
{
    { GFI_TILEIMAGE,         CPFT_TILE_IMAGE,    L"Image",                      CPFG_CREDENTIAL_PROVIDER_LOGO  },
    { GFI_LABEL,             CPFT_SMALL_TEXT,    L"Tooltip",                    CPFG_CREDENTIAL_PROVIDER_LABEL },
    { GFI_HEADING,           CPFT_LARGE_TEXT,    L"Heading"                                                    },
    { GFI_USERNAME,          CPFT_EDIT_TEXT,     L"Username (room responsible)", CPFG_LOGON_USERNAME           },
    { GFI_PASSWORD,          CPFT_PASSWORD_TEXT, L"Password (room responsible)", CPFG_LOGON_PASSWORD           },
    { GFI_SUBMIT_BUTTON,     CPFT_SUBMIT_BUTTON, L"Submit"                                                     },
    { GFI_MOREINFO_LINK,     CPFT_COMMAND_LINK,  L"About GEWISUnlock"                                          },
    { GFI_MULTIVERS_TEXT,    CPFT_SMALL_TEXT,    L"Multivers status: "                                         },
    { GFI_MULTIVERS_CHECKBOX,CPFT_CHECKBOX,      L"Multivers checkbox: "                                       },
};

static const PWSTR s_rgComboBoxStrings[] =
{
    L"First",
    L"Second",
    L"Third",
};
