# jarvisoj_level0 - BUUCTF

một bài tập quen thuộc vào khá thú vị, cùng phân tích nào:

**hàm main** 

![](https://i.imgur.com/wnhL63k.png)


![](https://i.imgur.com/yx2eong.png)

**flag đây rồi:**

![](https://i.imgur.com/HW6H1GQ.png)

đọc qua ida thì ta có thể thấy được đây là 1 dạng bài ret2win khá quen thuộc : 

**nhập thử 128byte xem sao:**

![](https://i.imgur.com/z2bw6dm.png)

ta thấy giá trị nhập vào chưa chạy tới dc thanh rbp
**hmm thử tăng thêm 8byte xem sao:**

![](https://i.imgur.com/J8m9SGW.png)

**ta thấy là nếu ta nhập 136byte vào thì thanh ghi rbp đã được làm đầy bằng 8byte, bây giờ ta chỉ cần chèn thêm 8byte vào thanh ghi rip rồi trỏ đếm hàm callsystem là được:**

**script đây:**

![](https://i.imgur.com/OCEeTH0.png)

**lấy shell nào :** 

![](https://i.imgur.com/RlrohE8.png)

flag{6dae6f9b-4873-4cff-b595-163cb72c1735}
