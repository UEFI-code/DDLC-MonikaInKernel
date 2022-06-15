.code _text

BeepInit PROC PUBLIC

push rax;
push rbx;
push rdx;
mov rax, 1193180000;
mov rbx, rcx;
idiv rbx;
mov rbx, rax; //save the result
mov al, 182;
out 67, al;
mov al, bl;
out 66, al;
mov al, bh;
out 66, al;
pop rdx;
pop rbx;
pop rax;
ret;

BeepInit ENDP

BeepStart PROC PUBLIC

push rax;
in al, 97;
or al, 3;
and al, 15;
out 97, al;
pop rax;
ret;

BeepStart ENDP

BeepStop PROC PUBLIC

push rax;
in al, 97;
and al, 13;
out 97, al;
pop rax;

BeepStop ENDP

END