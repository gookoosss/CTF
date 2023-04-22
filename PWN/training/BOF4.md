# BOF4 -- ROPchain

**1 kĩ thuật và lý thuyết mới rất quan trọng trong pwn là ROPchain**

**giải thích :** hiểu đơn giản là ROP là những đoạn code nhỏ trong chương trình, hay còn gọi là gadget, ROPchain là ta sẽ xây dựng các gadget thành 1 chuỗi để dễ dàng tạo shell cho chương trình

**dấu hiệu :** khi chương trình là file tĩnh, không có lệnh system và /bin/sh

giờ mở ida lên xem sao:

![](https://i.imgur.com/ICNnyPc.png)

Lỗi BOF và tìm hoài không thấy lệnh system đâu
Mở terminal lên xem sao:

![](https://i.imgur.com/bTgSfXM.png)

**Như trong hình ta thấy file bof4 không liên kết với bất kì file nào khác như những bài cơ bản ta từng làm**

**Lớp bảo  vệ PIE không hề có và các địa chỉ trong bof4 là địa chỉ tĩnh**

**Địa chỉ tĩnh**: là địa chỉ có 6byte và cố định không thay đổi suốt chương trình

![](https://i.imgur.com/OWz43JI.png)

**==> Bài này có dạng ROPchain**

Bây giờ chúng ta cần tìm các **pop rdi, rsi, rdx, rax, syscall**

**Lệnh : ROPgadget --binary name_file | grep “pop”**

![](https://i.imgur.com/LLM1Nid.png)


**kinh nghiệm:** chọn gadget có pop đứng đầu, ngắn nhất , gần hàm ret nhất


![](https://i.imgur.com/0RTb0yb.png)

gòi h ta lưu các gadget vừa tìm vào script : 

![](https://i.imgur.com/E0uCul9.png)

**bây giờ ta cần tạo ra /bin/sh thông qua lệnh execve("/bin/sh", arg, env)**

**trong đó "/bin/sh", ta sẽ trỏ đến địa chỉ của pop rdi, sau đó gắn cho nó 1 địa chỉ có rw**

**để tìm được địa chỉ rw_section ta cần làm:**

- dùng vmmap xem địa chỉ tĩnh nào có rw , như trong ảnh là địa chỉ 0x00000000406000

![](https://i.imgur.com/mquApB2.png)

- dùng x/xg50 gòi tìm địa chỉ nào trống chưa có giá trị nhập vào, mình chọn 0x406e00
 
![](https://i.imgur.com/1Iq2Pk3.png)

- sau khi tìm được địa chỉ rw_section thì ta cần trỏ đến hàm gets để nhập giá trị /bin/sh vào rw_section

![](https://i.imgur.com/gEN4p87.png)

**bây giờ ta cần thực thi lệnh execve("/bin/sh", 0, 0):**

- **rdi** thì ta cho gắn giá trị /bin/sh thông qua rw_section
- **rsi và rdx** thì ta không cần quan tâm nên cho nó giá trị null
- ta thêm **0x28byte** để chương trình nhảy trực tiếp vào **rax**
- **rax** thì thực hiện **execve (*)** 
- cuối cùng **syscall** để kiểm tra và thực thi chương trình


**(*) chú ý : để làm được điều này cần vào linK:**

https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md

chọn x86_64 (64-bit) rồi tìm execve và rax:


![](https://i.imgur.com/0ht5Iky.png)


copy 0x3b rồi gán vào rax trong script

**script:**

![](https://i.imgur.com/Bkerf26.png)

chạy thử xem sao:

![](https://i.imgur.com/bUVCwsG.png)

**như trong hình thì các thanh rdi, rsi, rdx, rax đầu giống với yêu cầu rồi**

![](https://i.imgur.com/OI7713i.png)

 **/usr/bin/dash là ta đã lấy dc shell rồi đó**
