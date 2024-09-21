/*
NTSYSAPI VOID NTAPI HalDisplayString(PCHAR String);
VOID InbvAcquireDisplayOwnership(VOID);
VOID InbvResetDisplay(VOID);
INT InbvSetTextColor(INT color); //IRBG
VOID InbvDisplayString(PSZ text);
VOID InbvSolidColorFill(ULONG left, ULONG top, ULONG width, ULONG height, ULONG color);
VOID InbvSetScrollRegion(ULONG left, ULONG top, ULONG width, ULONG height);
VOID InbvInstallDisplayStringFilter(ULONG b);
VOID InbvEnableDisplayString(ULONG b);
*/

UNICODE_STRING OnBSODFile = RTL_CONSTANT_STRING(L"\\??\\C:\\Monika_OnBSOD");

VOID MonikaBSODCallback(PVOID  Buffer, ULONG  Length)
{
	/* Not Work on Windows Server 2019
	InbvAcquireDisplayOwnership(); //Takes control of screen
	InbvResetDisplay(); //Clears screen
	InbvSolidColorFill(0, 0, 639, 479, 4); //Colors the screen blue
	InbvSetTextColor(15); //Sets text color to white
	InbvInstallDisplayStringFilter(0); //Not sure but nessecary
	InbvEnableDisplayString(1); //Enables printing text to screen
	InbvSetScrollRegion(0, 0, 639, 475); //Not sure, would recommend keeping
	HalDisplayString(BSOD_MSG);
	*/
	// MonikaCreateFile(&OnBSODFile);
	MonikaBeepInit(1000);
	MonikaBeepStart();
	MonikaDelayMs(1000);
	MonikaBeepStop();
	NopToy();
	// UINT8* vram = MonikaMapPhysicalMemToVirtual(0xa0000, 23333);
	// for (int i = 0; i < 23333; i++)
	// {
	// 	vram[i] ^= 0x233;
	// }
	return;
}