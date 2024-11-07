#include "pch.h"

extern "C"
{
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <Windows.h>
#include <tlhelp32.h>

// x86 (Win32 on Win64) version of the Monika payload is not finished yet...

DWORD GetProcessIdByName(const char* processName);
DWORD GetMainThreadId(DWORD processId);
LPVOID InjectShellcode(HANDLE hProcess, UINT8 *buf, UINT64 bufsize);
HWND GetTargetWindowHandleByPID(DWORD processId);
void DrawImageOnWindow(HWND hwnd, const char* imageFile);

static HWND targetHwnd = NULL;
static void displayMsgBoxOnTarget()
{
    MessageBoxA(targetHwnd, "JUST Monika", "JUST Monika", MB_OK | MB_ICONWARNING);
}

__declspec(dllexport) UINT8 injectX86Gal(char *targetEXE, const char *bmp_path)
{
    // First Get the PID of the target process
    DWORD processId = GetProcessIdByName(targetEXE);
    if (!processId)
    {
        printf("Target process \"%s\" not found. Exiting.\n", targetEXE);
        return -1;
    }
    printf("Target process \"%s\" found with PID %lu\n", targetEXE, processId);

    // Get Hwnd of the target process
    targetHwnd = GetTargetWindowHandleByPID(processId);
    if (!targetHwnd)
    {
        printf("Failed to get target window handle\n");
        return -1;
    }

    // Draw the image on the target window
    DrawImageOnWindow(targetHwnd, bmp_path);

    // Display MessageBoxA in the target process
    //MessageBoxA(targetHwnd, "JUST Monika", "JUST Monika", MB_OK | MB_ICONWARNING);
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)displayMsgBoxOnTarget, NULL, 0, NULL);
    
    return 0;
}

}