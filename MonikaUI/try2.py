from ctypes import *
import os
import time

MonikaDLL = cdll.LoadLibrary(os.getcwd() +  '\\MonikaDLL.dll')

status = MonikaDLL.get_my_driver_handle()

def BeepSong(song = [100,200,300,400,500,600,700,800], duration = 0.3):
    for freq in song:
        MonikaDLL.MonikaBeepStart(freq)
        time.sleep(duration)
    MonikaDLL.MonikaBeepStop()

if __name__ == "__main__":
    BeepSong()
    print("Beeped")