//
// GEWIS, 2020-2023
// 
// Previous work by: 
// - Microsoft Corporation, 2016
// This code is based on https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/Win7Samples/security/credentialproviders/samplecredentialprovider
// 

#pragma once

// global dll hinstance
extern HINSTANCE g_hinst;
#define HINST_THISDLL g_hinst

void DllAddRef();
void DllRelease();
