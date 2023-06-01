# **RET2WIN**

*một task khá lạ đòi hỏi khả năng đọc hiểu asm*

**source C:**

```
#include "stdio.h"
#include <stdlib.h>

void laugh()
{
	printf("ROP detected and denied...\n");
	exit(2);
}

void win()
{
	FILE *fptr;
	char buf[28];
	// Open a file in read mode
	fptr = fopen("flag.txt", "r");
	fgets(buf, 28, fptr);
	puts(buf);
}

void pwnable()
{
	char buffer[10];
	printf(" > ");
	fflush(stdout);

	read(0, (char *)buffer, 56);

	/* Check ret */
	__asm__ __volatile__("add $0x18, %rsp;"
						 "pop %rax;"
						 "cmp $0x0401262, %rax;"
						 "jle EXIT;"
						 "cmp $0x040128a, %rax;"
						 "jg EXIT;"
						 "jmp DONE;"
						 "EXIT:"
						 "call laugh;"
						 "DONE: push %rax;"w);
	return;
}

int main()
{
	setbuf(stdout, NULL);

	pwnable();

	return 0;
}

```

nhìn qua thì nghĩ ret2win cơ bản nhưng debug thử thì khá khó

**chú ý:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/4327c084-5500-4ca7-b25c-0928ad139ce5)


đến đây ta cần dùng si để đi vào hàm pwnable nếu không thì nó sẽ bắt mình nhập vào out chương trình liền mà không kiểm tra được gì

```
__asm__ __volatile__("add $0x18, %rsp;"
			"pop %rax;"
			"cmp $0x0401262, %rax;"
			"jle EXIT;"
			"cmp $0x040128a, %rax;"
			"jg EXIT;"
			"jmp DONE;"
			"EXIT:"
			"call laugh;"
			"DONE: push %rax;"w);
	return;
```

**trước khi đi vào pwnable thì ta cần hiểu code này**

**add $0x18, %rsp:** hiểu là thêm 0x18 vào địa chỉ stack rsp đang trỏ đến

**pop %rax:** rax được nhận vào giá trị của rsp đang chứa

**cmp $0x0401262, %rax:** so sánh rax với 0x0401262

**cmp $0x040128a, %rax:** so sánh rax với 0x040128a

**nếu rax bằng 1 trong 2 cái trên thì chương trình sẽ nhảy qua hàm laugh**

**DONE: push %rax:** trả về giá trị của rax

oke h ta nhập vào thử **8byte a , 8byte b, 8 byte c** xem chương trình chạy sao

![image](https://github.com/gookoosss/CTF.-/assets/128712571/7796228e-5953-4ce8-8b4b-13883a754bf3)


sau khi ta nhập xong thì thấy **offset đến rip là 18byte**

hiện tại **rsp** là **0x007fffffffe0d0**

sau đó **rsp** sẽ cộng thêm **0x18** thành **0x007fffffffe0e8** và trỏ đến giá trị 6byte c

ni lần nữa thì **6byte c** sẽ được gán vào **rax**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/afc8e93d-5ea7-4684-9ded-903d603531fb)


oke vậy ta hiểu sơ được vấn đề r, bây h  viết script thôi

**script:**

!![image](https://github.com/gookoosss/CTF.-/assets/128712571/3ae36967-f41f-4521-b5e9-efcf319cbad4)


mình có giải thích chi tiết trên script rồi đó

**chạy thử xem sao**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/1f33f0c3-45eb-4c20-92f4-5511d44a149b)


lấy được flag gòi nè (flag dỏm hehe)

***flag:***

**tjctf{this_i#-my-questsss}**
