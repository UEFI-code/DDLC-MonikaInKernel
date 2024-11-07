#include "pch.h"

extern "C"
{
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <Windows.h>
#include <tlhelp32.h>

DWORD GetProcessIdByName(const char* processName);
UINT8 injectX64Gal(char *targetEXE, const char *bmp_path);
UINT8 injectX86Gal(char *targetEXE, const char *bmp_path);

__declspec(dllexport) UINT8 injectGal(char *targetEXE, const char *bmp_path)
{
    // get pid
    DWORD processId = GetProcessIdByName(targetEXE);
    if (!processId)
    {
        printf("Target process \"%s\" not found. Exiting.\n", targetEXE);
        return -1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess)
    {
        printf("Failed to open process with PID %lu\n", processId);
        return -1;
    }

    // check target is x64 or wow64
    BOOL isWow64 = FALSE;
    IsWow64Process(hProcess, &isWow64);
    
    // Close Handle
    CloseHandle(hProcess);

    if (isWow64)
    {
        printf("Target process is x86 (WOW64)\n");
        // Inject x86 payload
        return injectX86Gal(targetEXE, bmp_path);
    }
    else
    {
        printf("Target process is x64\n");
        // Inject x64 payload
        return injectX64Gal(targetEXE, bmp_path);
    }
}
}