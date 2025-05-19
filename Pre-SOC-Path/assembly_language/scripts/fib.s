global _start
extern printf, scanf

section .data
    message db "Donnez-lui moi Fib Num:", 0x0a           ; avec une nouvelle line
    length equ $-message
    outFormat db "%d", 0x0a, 0x00                      ; avec null terminator de dire cest la fin du string
    inFormat db "%d", 0x00

section .bss
    userInput resb 1                               ; to tell nasm to reserve 1 byte of buffer space

section .text

_start:
    call printMessage
    call getInput
    call initFib
    call loopFib
    call Exit

printMessage:
    mov rax, 1
    mov rdi, 1
    mov rsi, message
    mov rdx, length
    syscall
    ret

getInput:
    sub rsp, 8
    mov rdi, inFormat
    mov rsi, userInput
    call scanf
    add rsp, 8
    ret

initFib:
    xor rax, rax
    xor rbx, rbx
    inc rbx
    ret

printFib:
    push rax
    push rbx
    mov rdi, outFormat
    mov rsi, rbx              ; rbx a Fib numero
    call printf
    pop rbx
    pop rax
    ret

loopFib:
    call printFib
    add rax, rbx            ; get the next num
    xchg rax, rbx           ; swap values
    cmp rbx, [userInput]    ; no change to operands, just update status flags: RFLAGS
    js loopFib              ; jump while $rbx < 10
    ret

Exit:
    mov rax, 60
    mov rdi, 0
    syscall



