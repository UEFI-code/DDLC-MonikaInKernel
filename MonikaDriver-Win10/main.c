#include <ntddk.h>
#include <wdmsec.h>
#include <stdio.h>


UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\Monika_Core");
UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;WD)");
UNICODE_STRING DeviceGUID = RTL_CONSTANT_STRING(L"23333333-2333-2333-2333-233333333333");
PDEVICE_OBJECT g_DeviceObj = 0;
UNICODE_STRING DeviceSymbolicLinkName = RTL_CONSTANT_STRING(L"\\??\\Monika_Link");

VOID DriverUnload(PDRIVER_OBJECT DrvObj)
{
	if (DrvObj != 0)
	{
		DbgPrint("On Exit DrvObj Valid 233!\n");
		if (g_DeviceObj != 0)
		{
			IoDeleteSymbolicLink(&DeviceSymbolicLinkName);
			IoDeleteDevice(g_DeviceObj);
		}
	}

	return;
}

NTSTATUS DeviceCTL(PDEVICE_OBJECT DeviceObj, PIRP myIRP)
{
	if (DeviceObj != 0 && myIRP != 0)
	{
		DbgPrint("On DeviceCTL DeviceObj and myIRP Valid 233!\n");
		if (DeviceObj != g_DeviceObj)
		{
			DbgPrint("Go wrong dispatch place!\n");
			return STATUS_BAD_DEVICE_TYPE;
		}
		PIO_STACK_LOCATION myIRPsp = IoGetCurrentIrpStackLocation(myIRP);
		ULONG inlen = myIRPsp->Parameters.DeviceIoControl.InputBufferLength;
		ULONG outlen = myIRPsp->Parameters.DeviceIoControl.OutputBufferLength;
		if (inlen > 512 || outlen > 512)
		{
			DbgPrint("Buffer too big!\n");
			return STATUS_NO_MEMORY;
		}
		UINT8* buffer = myIRP->AssociatedIrp.SystemBuffer;
		buffer[inlen - 1] = 0;
		DbgPrint("Recieved: %s", (char *)buffer);
		sprintf((char*)buffer, "Processed 233\n");
		myIRP->IoStatus.Information = 2333;
		myIRP->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(myIRP, IO_NO_INCREMENT); //No this will cause bug in usermode!
		return STATUS_SUCCESS;
	}

	return STATUS_SUCCESS;
}

NTSTATUS MuShi(PDEVICE_OBJECT DeviceObj, PIRP myIRP)
{
	//DbgPrint("DeviceObj: 0x%x, myIRP: 0x%x\n", DeviceObj, myIRP);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DrvObj, PUNICODE_STRING RegPath)
{
	NTSTATUS status = 0;
	if (DrvObj != 0)
	{
		DbgPrint("On Entry DrvObj Valid 233!\n");
		DrvObj->DriverUnload = DriverUnload;
		status = IoCreateDeviceSecure(DrvObj, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, TRUE, &sddl, (LPCGUID)&DeviceGUID, &g_DeviceObj);
		if (NT_SUCCESS(status))
		{
			DbgPrint("Create Device Success!\n");
			DrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceCTL;
			DrvObj->MajorFunction[IRP_MJ_CREATE] = MuShi;
			DrvObj->MajorFunction[IRP_MJ_CLOSE] = MuShi;
			IoCreateSymbolicLink(&DeviceSymbolicLinkName, &DeviceName);
		}
			
	}
	
	if (RegPath != 0)
	{
		DbgPrint("The RegPath is %wZ\n", RegPath);
	}

	return STATUS_SUCCESS;
}