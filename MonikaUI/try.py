import os
from ctypes import *
MonikaDLL = cdll.LoadLibrary(os.getcwd() +  '\\MonikaDLL.dll')
msg = input("Enter your message: ").encode('utf-8')
title = input("Enter your title: ").encode('utf-8')
typ = int(input("Enter your type: "))

p_msg = create_string_buffer(msg)
p_title = create_string_buffer(title)

print(MonikaDLL.MonikaMsg(p_msg, p_title, typ))