#include<stdio.h>
#include<windows.h>

#define RING3TO0 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x911, METHOD_BUFFERED, FILE_WRITE_DATA)
#define RING0TO3 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x912, METHOD_BUFFERED, FILE_READ_DATA)

int main()
{
	ULONG ret_code = 0;
	char *msg = (char *)malloc(16);
	HANDLE device = CreateFile("\\\\.\\Monika_Link", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
	DeviceIoControl(device, RING0TO3, msg, strlen(msg) + 1, msg, 16, &ret_code, 0);
	printf("%s\n", msg);
	printf("%u\n", ret_code);
	system("pause");
}
