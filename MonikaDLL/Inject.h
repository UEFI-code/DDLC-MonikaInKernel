#include <Windows.h>

DWORD GetProcessIdByName(const char* processName);
DWORD GetMainThreadId(DWORD processId);
LPVOID InjectShellcode(HANDLE hProcess, UINT8 *buf, UINT64 bufsize);
HWND GetTargetWindowHandleByPID(DWORD processId);
void DrawImageOnWindow(HWND hwnd, const char* imageFile);