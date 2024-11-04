#include<windows.h>

const char msg[] = "JUST Monika!";
const char title[] = "ALERT";

void display_message_box()
{
    MessageBoxA(0, msg, title, MB_OK);
}

int main()
{
    HANDLE hThread;
	while(1)
	{
		// create thread to display message box
        hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)display_message_box, 0, 0, 0);
    	// wait for the thread
        WaitForSingleObject(hThread, INFINITE);
	}
    
}
