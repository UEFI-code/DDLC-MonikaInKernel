// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Winnt.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBox(0, L"DLL Attached 233", L"MonikaDLL", 0);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

extern "C"
{

__declspec(dllexport) UINT32 MonikaMsg(char* msg, char* title, UINT8 type) {
    return MessageBoxA(0, msg, title, type);
}

__declspec(dllexport) UINT8 check_secure_boot()
{
    // Read from registry, HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled
    HKEY hKey;
    DWORD dwType = REG_DWORD;
    DWORD dwSize = sizeof(DWORD);
    DWORD dwValue;
    DWORD dwDisposition;
    LONG lResult = RegCreateKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_READ, NULL, &hKey, &dwDisposition);
    if (lResult != ERROR_SUCCESS) {
        return -1;
    }
    lResult = RegQueryValueEx(hKey, L"UEFISecureBootEnabled", NULL, &dwType, (LPBYTE)&dwValue, &dwSize);
    RegCloseKey(hKey);
    if (lResult != ERROR_SUCCESS) {
        return -1;
    }
    return dwValue;
}

__declspec(dllexport) UINT8 check_admin_privileges()
{
    // Check if the current process has admin privileges
    BOOL bIsAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) {
        CheckTokenMembership(NULL, AdministratorsGroup, &bIsAdmin);
        FreeSid(AdministratorsGroup);
    }
    return bIsAdmin;
}

// __declspec(dllexport) UINT8 acquire_admin_uac()
// {
//     // Using SeProfileSingleProcessPrivilege to elevate the process
//     HANDLE hToken;
//     LUID luid;
//     TOKEN_PRIVILEGES tp;
//     if (!LookupPrivilegeValue(NULL, SE_PROFILE_SINGLE_PROCESS_NAME, &luid)) {
//         return -1;
//     }
//     if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
//         return -1;
//     }
//     tp.PrivilegeCount = 1;
//     tp.Privileges[0].Luid = luid;
//     tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
//     if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
//         return -1;
//     }
//     return 0;
// }

__declspec(dllexport) UINT8 create_kernel_service()
{
    // Create a kernel service
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (hSCManager == NULL) {
        return -1;
    }
    SC_HANDLE hService = CreateService(hSCManager, L"MonikaService", L"Monika Service", SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, L"C:\\MonikaDriver.sys", NULL, NULL, NULL, NULL, NULL);
    if (hService == NULL) {
        CloseServiceHandle(hSCManager);
        return -1;
    }
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return 0;
}

__declspec(dllexport) UINT8 start_kernel_service()
{
    // Start the kernel service
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (hSCManager == NULL) {
        return -1;
    }
    SC_HANDLE hService = OpenService(hSCManager, L"MonikaService", SERVICE_ALL_ACCESS);
    if (hService == NULL) {
        CloseServiceHandle(hSCManager);
        return -1;
    }
    if (!StartService(hService, 0, NULL)) {
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return -1;
    }
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return 0;
}

}