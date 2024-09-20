#include "pch.h"

extern "C"
{

#include <stdio.h>
#include <stdint.h>
#include <Windows.h>
#include <winioctl.h>

HANDLE device = NULL;

typedef struct
{
	UINT8 type;
	char msg[128];
} MonikaObj;

#define RING3TO0_OBJ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x910, METHOD_IN_DIRECT, FILE_WRITE_DATA)
#define RING0TO3_OBJ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x911, METHOD_BUFFERED, FILE_READ_DATA)
#define RING3_REQUIRE_TESTSTR 0
#define RING3_REQUIRE_BSOD 0x44
#define RING3_REQUIRE_TESTFILE_CREATE 0x10
#define RING3_REQUIRE_TESTFILE_DELETE 0x11
#define RING3_REQUIRE_TESTPHYMEM_RW 0x20
#define RING3_REQUIRE_TESTBEEP 0x99
#define RING3_REQUIRE_START_BEEP 0x90
#define RING3_REQUIRE_STOP_BEEP 0x91

__declspec(dllexport) void get_my_driver_handle()
{
    device = CreateFile(L"\\\\.\\Monika_Link", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
    if (device == INVALID_HANDLE_VALUE) {
        printf("CreateFile failed!\n");
        device = NULL;
    }
}

__declspec(dllexport) uint32_t MonikaBeepStart(uint16_t freq)
{
    if (device == NULL) {
        printf("Device not opened!\n");
        return -1;
    }

    MonikaObj ctlData = { RING3_REQUIRE_START_BEEP };
    *(uint16_t*)ctlData.msg = freq;
    DWORD ret_code;
    DeviceIoControl(device, RING3TO0_OBJ, &ctlData, sizeof(MonikaObj), NULL, 0, &ret_code, 0);
    return ret_code;
}

__declspec(dllexport) uint32_t MonikaBeepStop()
{
    if (device == NULL) {
        printf("Device not opened!\n");
        return -1;
    }

    MonikaObj ctlData = { RING3_REQUIRE_STOP_BEEP };
    DWORD ret_code;
    DeviceIoControl(device, RING3TO0_OBJ, &ctlData, sizeof(MonikaObj), NULL, 0, &ret_code, 0);
    return ret_code;
}

}