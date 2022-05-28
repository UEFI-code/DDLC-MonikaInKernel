import os
from ctypes import *
MonikaDLL = cdll.LoadLibrary(os.getcwd() +  '\\MonikaDLL.dll')
p = create_string_buffer(16)
MonikaDLL.MonikaMsg(p)
print(p.value)