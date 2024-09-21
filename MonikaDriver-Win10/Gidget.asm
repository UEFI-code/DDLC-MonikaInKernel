KI_USER_SHARED_DATA equ 0FFFFF78000000000h
SharedSystemTime equ KI_USER_SHARED_DATA + 14h

.data

AccuTimeBuf:
    buffer db 8 dup(0);

.code _text

NopToy PROC PUBLIC

dq 9090909090909090h
dq 9090909090909090h
ret

NopToy ENDP

MonikaDelayMsNative PROC PUBLIC

push rcx; // backup goal parameter

;before we call stupid NT API, we should prepare a safer stack buffer
push rbp;
mov rbp, rsp;
sub rsp, 128; // fly away 128 bytes
;Query Current Time
mov rcx, AccuTimeBuf
call KeQuerySystemTime;
;Now we can partly restore the stack
mov rsp, rbp;
mov rax, [AccuTimeBuf];
push rax; // push the current time to stack
mov rbp, rsp;

WaitLoop:
hlt;
;Before we call stupid NT API, we should prepare a safer stack buffer
sub rsp, 128; // fly away 128 bytes
;Query Current Time
mov rcx, AccuTimeBuf
call KeQuerySystemTime;
;Now we can partly restore the stack
mov rsp, rbp;
mov rax, [AccuTimeBuf]; Current Time
pop rbx; The Initial Time
add rsp, 8; skip the orignal rbp bakup
pop rcx; The Goal delay
; Now we should put rsp to a right place
sub rsp, 8 + 8 + 8
sub rax, rbx; The Time Difference
cmp rax, rcx;
jb WaitLoop;

add rsp, 8
pop rbp;
add rsp, 8
ret

MonikaDelayMsNative ENDP

END