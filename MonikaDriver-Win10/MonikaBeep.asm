.code _text

MonikaBeepInit PROC PUBLIC

cmp cx, 0;
ja process;
mov rax, -1;
ret;
process:
mov al, 182;
out 67, al;
mov rdx, 0;
mov rax, 1193180;
div cx;
out 66, al;
mov al, ah;
out 66, al;
mov rax, 0;
ret;

MonikaBeepInit ENDP

MonikaBeepStart PROC PUBLIC

in al, 97;
or al, 3;
and al, 15;
out 97, al;
ret;

MonikaBeepStart ENDP

MonikaBeepStop PROC PUBLIC

in al, 97;
and al, 13;
out 97, al;

MonikaBeepStop ENDP

END