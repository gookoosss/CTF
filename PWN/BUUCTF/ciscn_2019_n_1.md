# ciscn_2019_n_1 -- BUUCTF

**đây là 1 bài khá lạ và thú vị mình đã mất hơn 1 ngày mới giải được**

vào ida xem thử sao:

![](https://i.imgur.com/1ijnzu5.png)

nhìn có vẻ đơn giản nhỉ, chỉ cần v2 = 11.28125 là ta sẽ lấy được flag

**ở đây có 2 vần đề cần giải quyết:**
- đầu tiên làm sao để tìm được địa chỉ của v2 là rbp-4h
- chèn cho v2 giá trị 11.28125 , để chèn được ta cần dịch 11.28125 ra Hexadecimal Representation bằng web:

https://www.h-schmidt.net/FloatConverter/IEEE754.html

![](https://i.imgur.com/sam8ZJ2.png)

**11.28125 == 0x41348000**

h ta mở terminal ra debug xem sao, chèn thử 8 byte nữa:

![](https://i.imgur.com/59jY9Vd.png)

**hmm ta phân tích xem sao:**
- v2 có địa chỉ là [rbp-4h] thì ta cần để ý thanh ghi rbp rồi trừ xuống 4byte là đến v2
- đây là dạng tràn biến bình thường  nên ta thử nhập vào 44byte cho v1 r chèn thêm p32(0x41348000) cho v2 

script đây:

![](https://i.imgur.com/oyGJ3yF.png)

lấy được flag gòi nè : 

![](https://i.imgur.com/0z4Qjcs.png)

flag{7f6dbdaa-9493-4742-9a76-915c5cf28557}
