# random

```python
#!/usr/bin/python3

from pwn import *
import random
import time
from ctypes import *

context.binary = exe = ELF('./random',checksec=False)
elf = cdll.LoadLibrary("libc.so.6")

#p = process(exe.path)
p = remote('challs.tfcctf.com', 31766)

giay = int(time.time())
elf.srand(giay)

a = []

for i in range(0,10):
    x = elf.rand()
    a.append(x)

log.info(str(a))

for i in range(0,10):
    sleep(1)
    p.sendline(str(a[i]))

p.interactive()
#TFCCTF{W0W!_Y0U_GU3SS3D_TH3M_4LL!@!}
```
