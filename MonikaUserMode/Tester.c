#include<stdio.h>
#include<windows.h>

#define RING3TO0_OBJ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x910, METHOD_IN_DIRECT, FILE_WRITE_DATA)
#define RING0TO3_OBJ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x911, METHOD_BUFFERED, FILE_READ_DATA)

#define RING3_REQUIRE_TESTSTR 0
#define RING3_REQUIRE_BSOD 0x44
#define RING3_REQUIRE_TESTFILE_CREATE 0x10
#define RING3_REQUIRE_TESTFILE_DELETE 0x11
#define RING3_REQUIRE_TESTPHYMEM_RW 0x20
#define RING3_REQUIRE_TESTBEEP 0x99

typedef struct
{
	UINT8 type;
	char msg[128];
} MonikaObj;

int main()
{
	MonikaObj a = {0};
	a.type = RING3_REQUIRE_TESTBEEP;
	strcpy(a.msg, "Monika Here!");
	ULONG ret_code = 0;
	HANDLE device = CreateFile("\\\\.\\Monika_Link", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
	DeviceIoControl(device, RING3TO0_OBJ, &a, sizeof(MonikaObj), NULL, 0, &ret_code, 0);
	CloseHandle(device);
	//printf("%s\n", a.msg);
	printf("%u\n", ret_code);
	system("pause");
}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      
