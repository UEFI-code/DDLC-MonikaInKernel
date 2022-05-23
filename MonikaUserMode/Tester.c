#include<stdio.h>
#include<windows.h>
#define SEND_STR CTL_CODE(FILE_DEVICE_UNKNOWN, 0x911, METHOD_BUFFERED, FILE_WRITE_DATA)
#define RECIEVE_STR CTL_CODE(FILE_DEVICE_UNKNOWN, 0x912, METHOD_BUFFERED, FILE_READ_DATA)
int main()
{
	ULONG ret_code = 0;
	char msg[] = "Hello driver!\n";
	HANDLE device = CreateFile("\\\\.\\Monika_Link", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
	DeviceIoControl(device, SEND_STR, msg, strlen(msg) + 1, NULL, 0, &ret_code, 0);
	printf("%s",msg);
	printf("%ld", ret_code);
	system("pause");
}
