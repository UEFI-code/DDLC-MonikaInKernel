#include<stdio.h>
#include<windows.h>

#define RING3TO0_OBJ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x910, METHOD_BUFFERED, FILE_WRITE_DATA)
#define RING0TO3_OBJ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x911, METHOD_BUFFERED, FILE_READ_DATA)
#define RING3_REQUIRE_BSOD 0x444

#define ProgramEnd() \
system("pause"); \
return -1

typedef struct
{
	UINT8 type;
	char msg[128];
} MonikaObj;

int main()
{
	MonikaObj a = { 0 };
	DWORD ret_code;

	HANDLE device = CreateFile(L"\\\\.\\Monika_Link", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
	if (device == INVALID_HANDLE_VALUE) {
		printf("CreateFile failed!\n");
		ProgramEnd();
	}

	UINT8* p = (UINT8*)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memset(p, 0x90, 0x1000);
	printf("Allocated Executable Memory at %p\n", p);

	while (1)
	{
		printf("Type Func type: ");
		scanf_s("%d", &a.type);
		DeviceIoControl(device, RING3TO0_OBJ, &a, sizeof(MonikaObj), NULL, 0, &ret_code, 0);
		printf_s("DeviceIoControl returned %d\n", ret_code);
	}

	CloseHandle(device);
}