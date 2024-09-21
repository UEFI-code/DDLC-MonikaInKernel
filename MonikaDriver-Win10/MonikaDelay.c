LARGE_INTEGER delayTime;
void MonikaDelayMs(int t)
{
	delayTime.QuadPart = t * -1000 * 10;
	KeDelayExecutionThread(KernelMode, TRUE, &delayTime);
	return;
}
