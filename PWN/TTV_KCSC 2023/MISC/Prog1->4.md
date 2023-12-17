- cả 4 chall đều có 1 điểm chung là nhập đáp án đúng vào nhiều lần liền sẽ có flag, vậy thì việc của ta đơn giản là viết script với 1 hàm thỏa điều kiện của chall rồi cho nó lặp 100 lần là được
# Prog1 
```python 
#!/usr/bin/env python3

from pwn import *

p = remote("103.162.14.116", 14002)

for i in range(50):
    p.recvuntil(b'arr = ')
    string_numbers = p.recvuntil(b']').decode() # lấy full mảng
    print(string_numbers)
    numbers = [int(num) for num in string_numbers.replace('[', '').replace(']', '').split(',')] 
    max_number = max(numbers) # tìm số lớn nhất 
    p.sendline(str(max_number))


p.interactive()
```
![image](https://github.com/gookoosss/CTF/assets/128712571/c08bdbaa-652d-4ef8-9b5c-37d7cce547f1)

# Prog2 
```python
#!/usr/bin/env python3

from pwn import *

p = remote("103.162.14.116", 14005)

def calculate_a(n):
    a = [0] * (n + 1)  # Khởi tạo danh sách a với kích thước n+1 và tất cả các phần tử ban đầu đều là 0
    a[0] = 1  # Gán a[0] = 1

    for i in range(1, n + 1):
        if i % 2 == 0:
            a[i] = i * a[i - 1]
        else:
            a[i] = i + a[i - 1]

    return a[n]

p.recvuntil(b'n = ')
n = p.recvuntil(b'>>')[:-3].decode()
print(n)
result = calculate_a(int(n))
p.sendline(str(result))

for i in range(100):
    p.recvuntil(b'n = ')
    n = p.recvuntil(b'>>')[:-3].decode()
    print(n)
    result = calculate_a(int(n))
    p.sendline(str(result))

p.interactive()
```

![image](https://github.com/gookoosss/CTF/assets/128712571/c8594cbc-0b96-4896-9663-0945c683c664)

# Prog3 
```python
#!/usr/bin/env python3

from pwn import *

p = remote("103.162.14.116", 14003)

def is_valid_parentheses(s):
    stack = []
    opening_brackets = ['(', '[', '{']
    closing_brackets = [')', ']', '}']

    for char in s:
        if char in opening_brackets:
            stack.append(char)
        elif char in closing_brackets:
            if not stack or opening_brackets.index(stack.pop()) != closing_brackets.index(char):
                return False
    
    return len(stack) == 0


for i in range(100):
    p.recvuntil(b'ROUND')
    p.recv(4)
    s = p.recvuntil(b'yes')[:-4].decode()
    print(s)
    result = is_valid_parentheses(s)
    if result:
        p.sendline(b'yes')
    else:
        p.sendline(b'no')


p.interactive()
```
![image](https://github.com/gookoosss/CTF/assets/128712571/613ebff6-6656-4579-b372-593e6afff839)

# Prog4
```python
#!/usr/bin/env python3

from pwn import *

p = remote("103.162.14.116", 14004)

def find_nth_digit(n):
    digit_count = 1
    number_count = 9
    start_number = 1

    while n > digit_count * number_count:
        n -= digit_count * number_count
        digit_count += 1
        number_count *= 10
        start_number *= 10

    start_number += (n - 1) // digit_count
    digit_index = (n - 1) % digit_count

    return int(str(start_number)[digit_index])

n = 1
result = find_nth_digit(n)
p.recvuntil(b'Output: 3\n')
for i in range(100):
    p.recvuntil(b'n = ')
    n = p.recvuntil(b'>>')[:-3].decode()
    print(n)
    result = find_nth_digit(int(n))
    p.sendline(str(result))

p.interactive()
```
![image](https://github.com/gookoosss/CTF/assets/128712571/5ae796a8-1cc5-4008-99a6-811f2758c17b)
