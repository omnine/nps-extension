// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "radutil.h"
#include <fstream>
#include <shlwapi.h>

#include "loguru/loguru.hpp"

extern LPCWSTR pwszDllType;
static HMODULE hInstance;


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        hInstance = hModule;
        DisableThreadLibraryCalls(hInstance);

        CHAR szFilePath[MAX_PATH];
        DWORD dwLen = GetModuleFileNameA(hModule, szFilePath, MAX_PATH);
        szFilePath[dwLen] = NULL;

        CHAR* pName = strrchr(szFilePath, '\\');
        if (pName != NULL) {
            pName++;

            strcpy(pName, "log.txt");
            loguru::add_file(szFilePath, loguru::Append, 6 - 4);	//4 + x

        }
    }

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

STDAPI DllRegisterServer(VOID)
{
    return RadiusExtensionInstall(hInstance, pwszDllType, TRUE);
}

STDAPI DllUnregisterServer(VOID)
{
    return RadiusExtensionInstall(hInstance, pwszDllType, FALSE);
}