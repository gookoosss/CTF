# downunderflow

## source C

```c 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define USERNAME_LEN 6
#define NUM_USERS 8
char logins[NUM_USERS][USERNAME_LEN] = { "user0", "user1", "user2", "user3", "user4", "user5", "user6", "admin" };

void init() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
}

int read_int_lower_than(int bound) {
    int x;
    scanf("%d", &x);
    if(x >= bound) {
        puts("Invalid input!");
        exit(1);
    }
    return x;
}

int main() {
    init();

    printf("Select user to log in as: ");
    unsigned short idx = read_int_lower_than(NUM_USERS - 1);
    printf("Logging in as %s\n", logins[idx]);
    if(strncmp(logins[idx], "admin", 5) == 0) {
        puts("Welcome admin.");
        system("/bin/sh");
    } else {
        system("/bin/date");
    }
}

```

hmm nhiệm vụ đơn giản là nhập idx sao cho trả về "admin" là có shell 

admin nằm ở logins[7] nhưng mà chương trình chỉ giới hạn idx đến 6 thôi nên ta ko nhập 7 được

để ý thì có lỗi OOB nên ta có thể nhập được số âm, vậy thử idx bằng -1 xem sao

![image](https://github.com/gookoosss/CTF/assets/128712571/2460bbc4-cd4b-492b-853a-df5554eab350)


ta nhập -1 thì địa chỉ ta đang trỏ đến là 0x005555555b801a, ta cần trỏ đến địa chỉ chứa admin nên ta sẽ tính offset nó là 0x5ffd0

tiếp theo ta thử nhập -2 xem sao

![image](https://github.com/gookoosss/CTF/assets/128712571/772b6a11-0f6d-4660-9e11-4571dd50c607)


ồ vậy offset giữa -1 và -2 là 6 byte, vậy ta sẽ lấy offset đến admin là 0x5ffd0 chia cho 0x6 rồi trừ thêm -1 (vì ta tính offset từ -1) là ra được idx ta cần là -65529

![image](https://github.com/gookoosss/CTF/assets/128712571/7c4e7a9b-e5b4-47af-8782-b8849a1664b3)


deeee và ta đã được shell

![image](https://github.com/gookoosss/CTF/assets/128712571/b1940e55-8077-4b53-a704-cf74b1687843)


## Flag

DUCTF{-65529_==_7_(mod_65536)}


