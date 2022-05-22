#include <ntddk.h>

VOID DriverUnload(PDRIVER_OBJECT DrvObj)
{
	if (DrvObj != 0)
	{
		DbgPrint("On Exit DrvObj Valid 233!\n");
	}

	return;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DrvObj, PUNICODE_STRING RegPath)
{
	if (DrvObj != 0)
	{
		DbgPrint("On Entry DrvObj Valid 233!\n");
		DrvObj->DriverUnload = DriverUnload;
	}
	
	if (RegPath != 0)
	{
		DbgPrint("The RegPath is %wZ\n", RegPath);
	}

	return STATUS_SUCCESS;
}