#include <ntddk.h>
#include <wdm.h>
#include <wdmsec.h>
#include <stdio.h>
#include <stdint.h>

UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\Monika_Core");
UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;WD)");
UNICODE_STRING DeviceGUID = RTL_CONSTANT_STRING(L"23333333-2333-2333-2333-233333333333");
PDEVICE_OBJECT g_DeviceObj = 0;
UNICODE_STRING DeviceSymbolicLinkName = RTL_CONSTANT_STRING(L"\\??\\Monika_Link");

char* BSOD_MSG = 0;
PKBUGCHECK_CALLBACK_RECORD g_BSOD = 0;

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

typedef struct
{
	UINT8 type;
	char msg[128];
} MonikaObj;

UNICODE_STRING testFilePath = RTL_CONSTANT_STRING(L"\\??\\C:\\Monika_TestCreate.txt");

PHYSICAL_ADDRESS PhyRAMAddr = { 0 };
// UINT8* myRAM = 0;

VOID InbvAcquireDisplayOwnership(VOID);

void MonikaBeepInit(uint16_t freq);
void MonikaBeepStart();
void MonikaBeepStop();
void MonikaDelayNanoNative(UINT64 t);
void NopToy();
