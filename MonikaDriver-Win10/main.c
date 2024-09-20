#include "MonikaDrv.h"
#include "MonikaDelay.c"
#include "MonikaFileSystem.c"
#include "MonikaMemory.c"
#include "MonikaBSOD.c"

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
			myIRP->IoStatus.Information = 4444;
			myIRP->IoStatus.Status = STATUS_NO_MEMORY;
			IoCompleteRequest(myIRP, IO_NO_INCREMENT); //No this will cause bug in usermode!
			return STATUS_NO_MEMORY;
		}
		MonikaObj* buffer = myIRP->AssociatedIrp.SystemBuffer;
		DbgPrint("IOCTL code is 0x%X\n", myIRPsp->Parameters.DeviceIoControl.IoControlCode);
		switch (myIRPsp->Parameters.DeviceIoControl.IoControlCode)
		{
		case RING3TO0_OBJ:
			DbgPrint("Task Type: 0x%X\n", buffer->type);
			switch (buffer->type)
			{
			case RING3_REQUIRE_TESTSTR:
				DbgPrint("Recieved: %s\n", buffer->msg);
				break;
			case RING3_REQUIRE_TESTFILE_CREATE:
				MonikaCreateFile(&testFilePath);
				break;
			case RING3_REQUIRE_TESTFILE_DELETE:
				MonikaDeleteFile(&testFilePath);
				break;
			case RING3_REQUIRE_BSOD:
				DbgPrint("Wow you like BSOD!?\n");
				BSOD_MSG = buffer->msg;
				if (g_BSOD == 0)
				{
					g_BSOD = (PKBUGCHECK_CALLBACK_RECORD)ExAllocatePoolWithTag(NonPagedPool, 512, 0);
					KeInitializeCallbackRecord(g_BSOD);
					KeRegisterBugCheckCallback(g_BSOD, MonikaBSODCallback, NULL, 0, 0);
					//KeBugCheck(0x23333333);
				}
				InbvAcquireDisplayOwnership();
				UINT8* vram = myRAM + 0xa0000;
				for (int i = 0; i < 0xffff; i++)
					vram[i] = i ^ 0xff;
				break;
			case RING3_REQUIRE_TESTPHYMEM_RW:
				DbgPrint("Will Try ReadWrite PhyMem\n");
				UINT8* mem = MonikaMapPhysicalMemToVirtual(0xa0000, 2333);
				if (mem)
				{
					int value = 0;
					for (int i = 0; i < 233; i++)
					{
						value = mem[i];
						DbgPrint("%d ", value);
						mem[i] ^= 0x233;
					}
					DbgPrint("\n");
				}
				break;
			case RING3_REQUIRE_TESTBEEP:
				DbgPrint("Will Try Beep\n");
				MonikaBeepInit(3000);
				MonikaBeepStart();
				MonikaDelayMs(1000);
				MonikaBeepStop();
				break;
			}
			myIRP->IoStatus.Information = 2333;
			break;
		case RING0TO3_OBJ:
			DbgPrint("Sending Data\n");
			buffer->type = 0;
			strcpy((char*)buffer->msg, "Processed 233\n");
			myIRP->IoStatus.Information = 6666;
			break;
		}
		myIRP->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(myIRP, IO_NO_INCREMENT); //No this will cause bug in usermode!
		return STATUS_SUCCESS;
	}

	return STATUS_ILLEGAL_INSTRUCTION;
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
		myRAM = MmMapIoSpace(PhyRAMAddr, 32 * 1024 * 1024, MmWriteCombined);
		status = IoCreateDeviceSecure(DrvObj, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &sddl, (LPCGUID)&DeviceGUID, &g_DeviceObj);
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