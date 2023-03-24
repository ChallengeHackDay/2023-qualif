; this assembly program is used to check if the password is right
; it is called as a shellcode and has 4 parameters : the password, its length, an encoded version of the real password, and finally its length too
; they are put on purpose in rdi, rsi, rdx, and rcx respectively to conform to the x64 Linux calling convention for stack frames

section .text
    push rbp
    mov rbp, rsp

    ; the password must be the same length as the encoded password
    cmp rsi, rcx
    jne .failure

.loop_check:
    ; load the nth character of the password and the nth DWORD of the encoded password
    movzx rax, BYTE [rdi]
    xor rbx, rbx
    mov ebx, DWORD [rdx]

    ; check that the supplied password is the encoded password left shifted by 3 bits and XORed with this random number
    shl rax, 3
    xor rax, 1014125475
    cmp rax, rbx
    jne .failure

    dec rsi
    jz .success

    inc rdi
    add rdx, 4
    jmp .loop_check

.failure:
    ; the result is returned using rax : 0 if the password is wrong, 1 if it is right
    mov rax, 0
    jmp .epilogue

.success:
    mov rax, 1

.epilogue:
    leave
    ret