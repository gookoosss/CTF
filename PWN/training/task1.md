# **RET2SHELLCODE**

**check ida:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/f1481f76-f007-4b6e-a756-22f50518f15a)


**vmmap và checksec**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/f3ea6c14-0d9b-465f-9594-f19b64cdad0c)


*NX mở và file tĩnh nên ta có thực thi task*

nhập thử 8byte xem sao:

![image](https://github.com/gookoosss/CTF.-/assets/128712571/c2692126-f7a5-407a-beaf-ec671136b8be)


8byte được trỏ đến **địa chỉ rax**

đề bài có cho ta 1 địa chỉ stack nào đó


![image](https://github.com/gookoosss/CTF.-/assets/128712571/7390891c-5fff-41c0-a385-52cf0c6d61c3)


**như ảnh thì ta thấy địa chỉ đề cho là địa chỉ stack đầu tiên chứa giá trị nhập vào**

như bài **bof6** trước, thì bình thường ta cần leak địa chỉ **rbp**, sau đó tìm offset để trả về địa chỉ của **shellcode**. Nhưng ở đây thì đề đã cho ta sẵn đỉa chỉ **shellcode** r nên ta dùng luôn 

***bây giờ việc đầu tiên ta cần leak địa chỉ để cho ra*** 

![image](https://github.com/gookoosss/CTF.-/assets/128712571/7420de7c-61b5-4d32-9159-a66fc499fb6b)


chạy thử xem địa chỉ đề cho vs địa chỉ shellcode giống nhau ko

**địa chỉ leak:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/15027813-f37b-4ad3-8de4-c0b3ac926420)


**địa chỉ shellcode:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/01435a2c-8450-4727-90a9-057ee8c67797)


vậy là ta leak đúng r đó, h chỉ cần tính offset đến rip rồi chèn shellcode, offset, địa chỉ leak được là lấy đươc shell
**script:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/adf6af63-1ff8-460c-a0c9-2f7d6b4f7e73)


**flag:**

***tjctf{s4llys3llss34sh3lls50973fce}***


