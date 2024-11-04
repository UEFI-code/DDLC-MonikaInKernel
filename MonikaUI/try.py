import os
from ctypes import *
MonikaDLL = cdll.LoadLibrary(os.getcwd() +  '\\MonikaDLL.dll')

print(f'Check SecureBoot: {MonikaDLL.check_secure_boot()}')
print(f'Check Admin: {MonikaDLL.check_admin_privileges()}')

msg = input("Enter your message: ").encode('utf-8')
title = input("Enter your title: ").encode('utf-8')
typ = int(input("Enter your type: "))

p_msg = create_string_buffer(msg)
p_title = create_string_buffer(title)

print(MonikaDLL.MonikaMsg(p_msg, p_title, typ))

print('Now lets check hijack other x64 process')

target_process = input("Enter target process name: ").encode('utf-8')
p_target_process = create_string_buffer(target_process)
MonikaDLL.injectX64Gal(p_target_process)