#include<stdio.h>
#include<windows.h>

#define RING3TO0_OBJ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x910, METHOD_BUFFERED, FILE_WRITE_DATA)
#define RING0TO3_OBJ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x911, METHOD_BUFFERED, FILE_READ_DATA)

#define RING3_REQUIRE_TESTSTR 0
#define RING3_REQUIRE_BSOD 0x44
#define RING3_REQUIRE_TESTFILE_CREATE 0x10
#define RING3_REQUIRE_TESTFILE_DELETE 0x11


typedef struct
{
	UINT8 type;
	char msg[128];
} MonikaObj;

int main()
{
	FILE *fp = fopen("a.txt", "rwb");
	fseek(fp, -4, SEEK_END);
	
	MonikaObj a = {0};
	a.type = 0x10;
	strcpy(a.msg, "Monika Here!");
	ULONG ret_code = 0;
	HANDLE device = CreateFile("\\\\.\\Monika_Link", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
	DeviceIoControl(device, RING3TO0_OBJ, &a, sizeof(MonikaObj), 0, 0, &ret_code, 0);
	CloseHandle(device);
	printf("%u\n", ret_code);
	system("pause");
}
