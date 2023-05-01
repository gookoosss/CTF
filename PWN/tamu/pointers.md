# POINTERS -- TAMU

**đây là 1 bài khó và lạ nên mình cần học nhiều thủ thuật lạ**

ida:

![](https://i.imgur.com/QhtpTJ8.png)


![](https://i.imgur.com/WO6QBNL.png)


**bài này lỗi BOF và dùng ret2win là ra**

mở terminal lên:

![](https://i.imgur.com/j3y2Yad.png)

**đề bài cho ta sẵn địa chỉ của một hàm nào đó ta ko rõ được**

vì đây là địa chỉ động nên là để xác định địa chỉ đó nằm ở đâu ta cần thực hiện thủ thuật leak address để leak ra cái địa chỉ đề bài cho

![](https://i.imgur.com/xumdH2u.png)

**kiểm tra xem địa chỉ ta được leak ra chưa và nó nằm ở đâu**

![](https://i.imgur.com/onS1f4C.png)

![](https://i.imgur.com/RY2NxkD.png)

**như ta đã thấy thì địa chỉ stack đề cho luôn trỏ đến địa chỉ của hàm loser ko có flag dù ta nhập bao nhiêu giá trị**

h ta chạy lại thử 10 byte xem sao:

![](https://i.imgur.com/h9gwDmJ.png)

**ta cùng phân tích nè:**

- như ida thì lệnh read cho ta nhập tối đa 10byte
- giá trị ta nhập vào thì 8byte vào rsi còn 2byte tràn xuống rbp
- lợi dụng 2byte này ta thay đổi cái đuôi của địa chỉ rbp để ta có trỏ đến địa chỉ hàm ta mún 
- địa chỉ mà ta leak được ở trên là địa chỉ của hàm loser, ta cần trỏ đến hàm win, mà như trong hình thì địa chỉ của hàm win hơn hàm loser 8, nên ta cần cộng thêm 8 cho leak_add để trỏ đến hàm win ta cần 

![](https://i.imgur.com/CrLjJQT.png)

**chạy thử xem sao:**

![](https://i.imgur.com/heV0wYG.png)

![](https://i.imgur.com/NP7eAqv.png)

**sai rồi nè**

chạy lại vài lần thì mình đã nhận ra là, ở ảnh trên khi chạy vào main+74 thì thì rbp-0x20; nên lúc này ta đã trỏ sai địa chỉ rồi, vì vậy ta cần cho leak_address + 40, lúc này địa chỉ leak_addres là 0x0048, sau khi đi qua hàm main+74 nó sẽ trừ đi 20 là thành 0x0028 và trỏ trực tiếp đến hàm win ta cần : 

**script:**

![](https://i.imgur.com/lt6vjCa.png)

**chạy lại xem sao**

![](https://i.imgur.com/etOqmKO.png)

**lúc này rdx đã trỏ đúng đến hàm win r nè**

![](https://i.imgur.com/zLwMspE.png)

**lấy được flag luôn**
