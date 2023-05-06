# Beginner ROP

**đây là 1 bài khá hay và thú vị cần kết hợp giữ ret2win vs ROPchain**

**source C:**

![](https://hackmd.io/_uploads/rkAn2yEN2.png)

checksec xem sao:

![](https://hackmd.io/_uploads/ByIBayV42.png)


**đây là file tĩnh với PIE mở nên ta đoán sẽ dùng ROPchain**

**tìm gadget xem sao:**

![](https://hackmd.io/_uploads/BJ_h6k4Vh.png)


hmm ko có pop mình cần rồi 


**xem source C thì nó cho các hàm void có liên quan đến rdi,rsi,rdx,rax rồi nên ta có thể thử sử dụng luôn các hàm này bằng cách ret2win** 

check ra offset bằng 40byte

![](https://hackmd.io/_uploads/rJ_9glEE3.png)

**riêng thằng rdi thì nó sẽ đưa vị trí $rsp vào $rdi khi return (tức là ngay $rbp ở lần nhập của mình)**

**vậy thì mình sẽ để ‘/bin/sh\0’ ngay trước $rip**

**giải thích thêm :** 


![](https://hackmd.io/_uploads/rk0VUl44n.png)

script thử:

![](https://hackmd.io/_uploads/Bycx4eVEh.png)

script chạy thử xem sao:

![](https://hackmd.io/_uploads/Hy6E4e4V2.png)

hmm lỗi rồi

ở đây ta thấy rdi đã có /bin/sh\0 rồi

rsi lại trỏ đến địa chỉ hàm bad kết thúc chương trình

**đến đây ta đổi hướng khác tìm gadget giống với hàm void source cho sẵn:**

![](https://hackmd.io/_uploads/rkfgHe4Eh.png)

**2 cái cuối cùng giống đề cho nè nên ta lưu lại luôn**

sau đó tự lấy thêm địa chỉ **call rax** vs **syscall** nữa là xong nè

**script:**


![](https://hackmd.io/_uploads/HJcj8e4V3.png)

chạy thử thì láy được shell r nè 

![](https://hackmd.io/_uploads/HJYkvlN4h.png)

**FLAG{h0p_p0p_r0p_po909090p93r!!!}
**
