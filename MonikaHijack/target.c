#include<stdio.h>
#include<windows.h>

int main()
{
    MessageBoxA(NULL, "Target", "Target", MB_OK);
    while(1)
    {
        printf("Waiting for Hijack...\n");
        Sleep(1000);
    }
}