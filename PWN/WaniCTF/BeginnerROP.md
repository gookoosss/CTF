# Beginner ROP

**đây là 1 bài khá hay và thú vị cần kết hợp giữ ret2win vs ROPchain**

**source C:**

![image](https://user-images.githubusercontent.com/128712571/236634373-368f93a2-9996-4273-a6df-93d2d232d14a.png)


checksec xem sao:

![image](https://user-images.githubusercontent.com/128712571/236634388-b41843ec-538a-4c09-b05d-7440974f602b.png)



**đây là file tĩnh với PIE mở nên ta đoán sẽ dùng ROPchain**

**tìm gadget xem sao:**

![image](https://user-images.githubusercontent.com/128712571/236634393-d7af1ae0-e7f0-4213-b528-7cfbcc785b43.png)



hmm ko có pop mình cần rồi 


**xem source C thì nó cho các hàm void có liên quan đến rdi,rsi,rdx,rax rồi nên ta có thể thử sử dụng luôn các hàm này bằng cách ret2win** 

check ra offset bằng 40byte

![image](https://user-images.githubusercontent.com/128712571/236634403-1fe7c153-4e26-4ebc-85f1-a59f941f6605.png)


**riêng thằng rdi thì nó sẽ đưa vị trí $rsp vào $rdi khi return (tức là ngay $rbp ở lần nhập của mình)**

**vậy thì mình sẽ để ‘/bin/sh\0’ ngay trước $rip**

**giải thích thêm :** 


![image](https://user-images.githubusercontent.com/128712571/236634410-dc39e493-1b3e-43ee-a00a-83e56b78e1e3.png)


script thử:

![image](https://user-images.githubusercontent.com/128712571/236634417-4ffc4adf-ddc0-4f46-9b92-9dd3653d00df.png)


script chạy thử xem sao:

![image](https://user-images.githubusercontent.com/128712571/236634434-1459f2df-2221-4054-8c82-17150af7e317.png)


hmm lỗi rồi

ở đây ta thấy rdi đã có /bin/sh\0 rồi

rsi lại trỏ đến địa chỉ hàm bad kết thúc chương trình

**đến đây ta đổi hướng khác tìm gadget giống với hàm void source cho sẵn:**

![image](https://user-images.githubusercontent.com/128712571/236634442-5a5180ee-9798-4695-a466-dbb071764d92.png)


**2 cái cuối cùng giống đề cho nè nên ta lưu lại luôn**

sau đó tự lấy thêm địa chỉ **call rax** vs **syscall** nữa là xong nè

**script:**

![image](https://user-images.githubusercontent.com/128712571/236634448-0cea1d6a-0492-4daa-9336-2c00bb050baf.png)


chạy thử thì láy được shell r nè 

![image](https://user-images.githubusercontent.com/128712571/236634460-7f52c815-cacc-4c12-b461-0f700e207530.png)

**FLAG{h0p_p0p_r0p_po909090p93r!!!}
**
