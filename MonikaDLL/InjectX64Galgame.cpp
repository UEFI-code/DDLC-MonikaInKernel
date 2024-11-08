#include "pch.h"

extern "C"
{
#include <stdio.h>
#include <stdlib.h>
#include "Inject.h"
#include <Windows.h>
#include <tlhelp32.h>

static BYTE MonikaPayload_NO_CRASH[] = {
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
    0x48, 0x83, 0xEC, 0x28,        // sub rsp, 0x28 (MessageBoxA Strictly requires 32-byte aligned stack)
    0xE8, 0x00, 0x00, 0x00, 0x00,  // call $+5 (self-relative)
    0x5A,                          // pop rdx
    0x48, 0x83, 0xC2, 0x43,        // add rdx, 0x43 (adjust rdx to point to "JUST Monika!")
    0x48, 0xB9, 0,0,0,0,0,0,0,0,   // mov rcx, 0
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

static BYTE Gidget_Shellcode[] = {
    0x55,                          // push rbp
    0x48, 0x8B, 0xEC,              // mov rbp, rsp
    0x48, 0x83, 0xEC, 0x20,        // sub rsp, 32
    0xE8, 0x00, 0x00, 0x00, 0x00,  // call $+5 (self-relative)
    0x59,                          // pop rcx
    0x48, 0x83, 0xC1, 0x3F,        // add rcx, 0x3F
    0x48, 0xB8, 0xC0, 0x04, 0x10, 0x1B, 0xFC, 0x7F, 0x00, 0x00, // mov rax, 0x7FFC1B1004C0
    0xFF, 0xD0,                    // call rax
    0x48, 0x8B, 0xC8,              // mov rcx, rax
    0xE8, 0x00, 0x00, 0x00, 0x00,  // call $+5 (self-relative)
    0x5A,                          // pop rdx
    0x48, 0x83, 0xC2, 0x31,        // add rdx, 0x31
    0x48, 0xB8, 0x50, 0xAA, 0x0F, 0x1B, 0xFC, 0x7F, 0x00, 0x00, // mov rax, 0x7FFC1B0FAA50
    0xFF, 0xD0,                    // call rax
    0xE8, 0x00, 0x00, 0x00, 0x00,  // call $+5 (self-relative)
    0x5B,                          // pop rbx
    0x48, 0x83, 0xC3, 0x27,        // add rbx, 0x27
    0x48, 0x89, 0x03,              // mov [rbx], rax
    0x48, 0x83, 0xC4, 0x20,        // add rsp, 32
    0x5D,                          // pop rbp
    0xC3,                          // ret
    0x90, 0x90,                    // nop, nop (padding)
    0x75, 0x73, 0x65, 0x72, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C, 0x00, // "user32.dll"
    0x4D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x42, 0x6F, 0x78, 0x41, 0x00, // "MessageBoxA"
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // reserved for result
};

// Function to hijack the main thread and set its RIP to the injected MonikaPayload
static UINT8 HijackMainThread(HANDLE hProcess, HANDLE hThread, LPVOID remotePayloadMemory)
{
    if(!hProcess)
    {
        printf("Invalid process handle\n");
        return -1;
    }
    if(!hThread)
    {
        printf("Invalid thread handle\n");
        return -1;
    }
    if(!remotePayloadMemory)
    {
        printf("Invalid remote memory address\n");
        return -1;
    }

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

        // Set RIP to the MonikaPayload address
        ctx.Rip = (DWORD64)remotePayloadMemory;
        printf("Hijacking RIP to address: 0x%p\n", remotePayloadMemory);

        // Update the thread context
        SetThreadContext(hThread, &ctx);
        return 0;
    }
    else
    {
        printf("Failed to get thread context\n");
        return -1;
    }
}

static void GetTargetMsgBoxA_Routine(HANDLE hProcess)
{
    // Allocate RWX memory in the target process, size is gadget_shellcode size
    LPVOID remoteGadgetMemory = VirtualAllocEx(hProcess, NULL, sizeof(Gidget_Shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteGadgetMemory)
    {
        printf("Failed to allocate memory in the target process\n");
        return;
    }
    printf("Allocated RWX memory for Gidget_Shellcode at address: 0x%p\n", remoteGadgetMemory);
    // Write the Gidget_Shellcode to the allocated memory
    WriteProcessMemory(hProcess, remoteGadgetMemory, Gidget_Shellcode, sizeof(Gidget_Shellcode), NULL);
    printf("Gidget_Shellcode written to remote memory successfully\n");
    // Create Remote Thread to execute Gidget_Shellcode
    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteGadgetMemory, NULL, 0, NULL);
    if (!hRemoteThread)
    {
        printf("Failed to create remote thread\n");
        return;
    }
    WaitForSingleObject(hRemoteThread, INFINITE);
    CloseHandle(hRemoteThread);
    // Write Back last 8 bytes of Gidget_Shellcode to get MessageBoxA address
    ReadProcessMemory(hProcess, (LPVOID)((UINT64)remoteGadgetMemory + sizeof(Gidget_Shellcode) - 8), (LPVOID)((UINT64)Gidget_Shellcode + sizeof(Gidget_Shellcode) - 8), 8, NULL);
    printf("MessageBoxA Address in Target: 0x%p\n", *(UINT64 *)((UINT64)Gidget_Shellcode + sizeof(Gidget_Shellcode) - 8));
}

__declspec(dllexport) UINT8 injectX64Gal(char *targetEXE, const char *bmp_path)
{
    // Update Gidget_Shellcode with function addresses
    *(UINT64 *)(Gidget_Shellcode + 20) = (UINT64)LoadLibraryA;
    *(UINT64 *)(Gidget_Shellcode + 45) = (UINT64)GetProcAddress;
    
    // Get the PID of the target process
    DWORD processId = GetProcessIdByName(targetEXE);
    if (!processId)
    {
        printf("Target process \"%s\" not found. Exiting.\n", targetEXE);
        return -1;
    }
    printf("Target process \"%s\" found with PID %lu\n", targetEXE, processId);

    // Get the main thread ID
    DWORD mainThreadId = GetMainThreadId(processId);
    if (!mainThreadId)
    {
        printf("Failed to find main thread.\n");
        return -1;
    }
    printf("Main thread found with TID %lu\n", mainThreadId);

    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess)
    {
        printf("Failed to open process with PID %lu\n", processId);
        return -1;
    }

    // Get Target MessageBoxA address
    GetTargetMsgBoxA_Routine(hProcess);

    // Update MonikaPayload with target MessageBoxA address
    *(UINT64 *)(MonikaPayload_NO_CRASH + 62) = *(UINT64 *)(Gidget_Shellcode + sizeof(Gidget_Shellcode) - 8);
    
    // Get Target Window Handle
    HWND targetHwnd = GetTargetWindowHandleByPID(processId);
    if (!targetHwnd)
    {
        printf("Failed to get target window handle\n");
        return -1;
    }
    printf("Target window handle: 0x%p\n", targetHwnd);

    // Update MonikaPayload with target window handle
    *(UINT64 *)(MonikaPayload_NO_CRASH + 42) = (UINT64)targetHwnd;

    // Replace Target Window content with image
    DrawImageOnWindow(targetHwnd, bmp_path);

    // Inject MonikaPayload into the target process and get the address of the remote memory
    LPVOID remoteMemory = InjectShellcode(hProcess, MonikaPayload_NO_CRASH, sizeof(MonikaPayload_NO_CRASH));
    if (!remoteMemory)
    {
        printf("Failed to inject MonikaPayload.\n");
        return -1;
    }
    printf("MonikaPayload injected successfully.\n");

    // open main thread
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, mainThreadId);
    if (!hThread)
    {
        printf("Failed to open main thread with TID %lu\n", mainThreadId);
        return -1;
    }
    SuspendThread(hThread);
    printf("Main thread suspended.\n");
    
    // Hijack the main thread
    if (HijackMainThread(hProcess, hThread, remoteMemory) == 0)
        printf("Main thread hijacked successfully.\n");
    else
        printf("Failed to hijack main thread.\n");

    // Resume the main thread
    ResumeThread(hThread);
    printf("Main thread resumed.\n");
    
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}
}