UINT8* MonikaMapPhysicalMemToVirtual(UINT8 * phyAddr, __int64 size)
{
	PHYSICAL_ADDRESS PhyRAMAddr = { 0 };
	PhyRAMAddr.QuadPart = phyAddr;
	return MmMapIoSpace(PhyRAMAddr, size, MmNonCached);
}

UINT8* MonikaGetPhysicalMemAddrFromVirtual(UINT8* virtAddr)
{
	PHYSICAL_ADDRESS PhyRAMAddr = { 0 };
	PhyRAMAddr = MmGetPhysicalAddress(virtAddr);
	return PhyRAMAddr.QuadPart;
}