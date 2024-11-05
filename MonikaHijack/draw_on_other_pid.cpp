#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>

// Function to get the PID of the target process by name
DWORD GetProcessIdByName(const char* processName)
{
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
            if (strcmp(pe32.szExeFile, processName) == 0)
            {
                processId = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hProcessSnap, &pe32));
    }

    CloseHandle(hProcessSnap);
    return processId;
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

// Function to draw an image on a window using GDI
void DrawImageOnWindow(HWND hwnd)
{
    // Get the device context (DC) of the target window
    HDC hdc = GetDC(hwnd);
    if (!hdc)
    {
        printf("Failed to get device context.\n");
        return;
    }

    // Create a memory DC to hold the bitmap
    HDC memDC = CreateCompatibleDC(hdc);
    if (!memDC)
    {
        printf("Failed to create memory DC.\n");
        ReleaseDC(hwnd, hdc);
        return;
    }

    // Load an image from file (use LoadImage for simplicity)
    HBITMAP hBitmap = (HBITMAP)LoadImageA(NULL, "monika.bmp", IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE);
    if (!hBitmap)
    {
        printf("Failed to load image.\n");
        ReleaseDC(hwnd, hdc);
        return;
    }

    // Get the bitmap dimensions
    BITMAP bmp_info;
    GetObject(hBitmap, sizeof(BITMAP), &bmp_info);
    
    // Select the bitmap into the memory DC, this will change memDC mapping area to the bmp file content
    SelectObject(memDC, hBitmap);

    // BitBlt (copy) the image from the memory DC to the window DC
    BitBlt(hdc, 0, 0, bmp_info.bmWidth, bmp_info.bmHeight, memDC, 0, 0, SRCCOPY);
    
    // Clean up
    DeleteDC(memDC);
    DeleteObject(hBitmap);
    ReleaseDC(hwnd, hdc);
}

int main()
{
    // Get the PID of the target process
    targetPID = GetProcessIdByName("target.exe");
    if (!targetPID)
    {
        printf("Target process not found.\n");
        return -1;
    }
    printf("Target process found with PID %lu\n", targetPID);

    // Get the window handle of the target process
    EnumWindows(EnumWindowsCallback, 0);
    if (!targetHwnd)
    {
        printf("Failed to find window of target process.\n");
        return -1;
    }
    printf("Window handle of target process: 0x%p\n", targetHwnd);

    // Draw an image on the target window
    DrawImageOnWindow(targetHwnd);
}
