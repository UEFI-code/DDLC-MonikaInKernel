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
	MonikaBeepInit(50);
	MonikaBeepStart();
	for (int i = 50; i < 1000; i+=200)
	{
		MonikaBeepInit(i);
		MonikaDelayRouglyCMOS(1);
	}
	MonikaBeepStop();
	NopToy();
	return;
}