#include<stdio.h>
#include<windows.h>

#define RING3TO0_OBJ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x910, METHOD_BUFFERED, FILE_WRITE_DATA)
#define RING0TO3_OBJ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x911, METHOD_BUFFERED, FILE_READ_DATA)
#define RING3_REQUIRE_BSOD 0x444

typedef struct
{
	UINT8 type;
	char msg[128];
} MonikaObj;

int main()
{
	MonikaObj a = { 0 };
	a.type = 0;
	strcpy(a.msg, "Hello Driver!");
	ULONG ret_code = 0;
	HANDLE device = CreateFile(L"\\\\.\\Monika_Link", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
	DeviceIoControl(device, RING0TO3_OBJ, NULL, 0, &a, sizeof(MonikaObj), &ret_code, 0);
	CloseHandle(device);
	printf("%s\n", a.msg);
	printf("%u\n", ret_code);
	system("pause");
}