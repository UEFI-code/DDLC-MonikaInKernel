from ctypes import *
import os
import time

MonikaDLL = cdll.LoadLibrary(os.getcwd() +  '\\MonikaDLL.dll')

MonikaDLL.get_my_driver_handle.restype = c_uint8
status = MonikaDLL.get_my_driver_handle()
if status != 0:
    print("Error in loading driver")
    exit()

def BeepSong(song = [100,200,300,400,500,600,700,800], duration = 0.3):
    for freq in song:
        MonikaDLL.MonikaBeepStart(freq)
        time.sleep(duration)
    MonikaDLL.MonikaBeepStop()

def BeepUp():
    for freq in range(100, 5000, 50):
        MonikaDLL.MonikaBeepStart(freq)
        time.sleep(0.1)
    MonikaDLL.MonikaBeepStop()

if __name__ == "__main__":
    BeepUp()
    print("Beeped")