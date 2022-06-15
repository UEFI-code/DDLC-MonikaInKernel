LARGE_INTEGER delayTime;
void DelayMs(int t)
{
	delayTime.QuadPart = -3000 * 1000 * 10;
	KeDelayExecutionThread(KernelMode, TRUE, &delayTime);
	return;
}