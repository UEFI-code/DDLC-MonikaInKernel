KI_USER_SHARED_DATA equ 0FFFFF78000000000h
SharedSystemTime equ KI_USER_SHARED_DATA + 14h

.data

.code _text

NopToy PROC PUBLIC
dq 9090909090909090h
dq 9090909090909090h
ret
NopToy ENDP

MonikaDelayNanoNative PROC PUBLIC
mov rdx, SharedSystemTime ; Prepare Pointer to SharedSystemTime
mov rbx, [rdx] ; Remember the initial time

WaitLoop:
hlt;
mov rax, [rdx] ; Get the current time
sub rax, rbx ; Calculate the elapsed time
cmp rax, rcx ; Compare with the requested delay
jb WaitLoop;

ret
MonikaDelayNanoNative ENDP

MonikaDelayRouglyCMOS PROC PUBLIC
mov al, 0
out 70h, al
in al, 71h
mov bl, al ; Remember the initial time

WaitLoop:
;hlt;
in al, 71h
cmp al, bl
jae Normal
; current second is less than the initial second
add al, 60
Normal:
sub al, bl
cmp al, cl
jb WaitLoop

ret
MonikaDelayRouglyCMOS ENDP

END