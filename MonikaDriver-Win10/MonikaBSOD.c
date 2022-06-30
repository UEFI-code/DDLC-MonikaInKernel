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

void BeepInit(int freq);
void BeepStart();
void BeepStop();

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
	UNICODE_STRING OnBSODFile = RTL_CONSTANT_STRING(L"\\DosDevices\\C:\\Monika_OnBSOD");
	MonikaCreateFile(&OnBSODFile);
	BeepInit(1000);
	UINT8* vram = (UINT8*)0xa0000;
	for (int i = 0; i < 0xffff; i++)
	{
		vram[i] = 256 ^ (i % 256);
	}
	BeepStart();
	DelayMs(3000);
	BeepStop();
	return;
}