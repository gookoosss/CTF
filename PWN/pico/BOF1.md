# **PicoGYM - Buffer overflow 1**
***Đầu tiên t vào ida32 kiểm tra code xem sao:***

![image](https://user-images.githubusercontent.com/128712571/230591874-484ee9e5-a782-44c0-915a-70f6dcb939c3.png)


***hàm vlun:***

![](https://i.imgur.com/zXHgiWp.png)

***chà có hàm win nè:***

![](https://i.imgur.com/uBxgZqA.png)

***vào terminal kiểm tra xem sao
chạy vào hàm main+102 là hàm vuln để nhập dữ liệu vào*

![](https://i.imgur.com/vGAlY0O.png)

***chạy đến vuln+29 là hàm gets rồi nhập thử 8byte kiểm tra xem sao***

![](https://i.imgur.com/MrXOAKa.png)

***ở đây ta dùng tel kiểm tra thì thấy địa chỉ 0xffffd1e0 là mảng buf vì nó chứa giá trị t nhập vào***

![](https://i.imgur.com/FCnWhvU.png)

***cùng phân tích xíu nha:***
- ở đây ta có thể đoán được rằng bài này là dạng ret2win, nếu vậy ta cần quan tâm đến thanh ghi eip( rip) nằm ở dưới thanh ghi ebp ( rbp), ta thử làm đầy eip xem sao nào
- h ta đếm từ dòng 0xffffd1e0 đến ebp thì thấy có 11 dòng, mỗi dòng 4byte , vậy ta nhập cần chèn 11*4 byte , tiếp theo ta chèn thử them 4byte bbbb vào eip xem sao nào

![](https://i.imgur.com/2GEDWxX.png)

***thì sau khi chèn xong thì ta eip đã được làm đầy r , thử chạy chương trình xem sao***

![](https://i.imgur.com/qeOcvdZ.png)

***hmm lỗi rồi nè, bây h ta cùng phân tích lại nè:***
- vào ida kiểm tra hàm win lại thì để lấy dc flag ta cần thông qua hàm win
- đây là dạng bài ret2win nên ta cần chèn 4byte của thằng eip vào thằng win thì ta mới lấy được flag được
- h chúng ta cần dùng python 3 để làm nào 
**à trước tiên ta cần vào picoGYM để lấy netcat cái **

![](https://i.imgur.com/oR1ElLI.png)
***netcat đây:  nc saturn.picoctf.net 63414
code python đ**ây:*

![](https://i.imgur.com/VryNTUf.png)

dịch code: như đã phân tích thì đầu tiên ta cần chèn 44byte từ hàm buf đến ebp, sau đó ta chèn tiếp 4byte vào địa chỉ của thằng win để chạy chương trình 

h vào terminal chạy xem sao:

![](https://i.imgur.com/f4nTn2t.png)

tenten có flag gòi nè hehe

flag : picoCTF{addr3ss3s_ar3_3asy_0195a40f}
