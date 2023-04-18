# warmup_csaw_2016 

đây là bài khá độc lạ làm mình mất 1 tuần mới hiểu và giải được 

**mở ida xem sao nào:**

![](https://i.imgur.com/HsZaq9J.png)

hàm chứa flag đây : 

![](https://i.imgur.com/MxhMbFv.png)

mở terminal lên sao : 

![](https://i.imgur.com/VVOqDb8.png)

**thề là lần đầu đọc bài này mình lú thật sự không biết bắt đầu từ đâu luôn , không biết nên đặt breakpoint ở đâu hay nhập ở đâu, nó lạ quá :))**

thôi thì mình ni từ từ dậy :))

**sau một hồi ni thì mình phát hiển ra ở địa chỉ main+102 cho phép nhập dữ liệu để chạy chương trình nên b*main+102 luôn :**

![](https://i.imgur.com/Jwzwamr.png)

**nhập thử 100 byte xem sao:**

![](https://i.imgur.com/QuP5i8e.png)

![](https://i.imgur.com/tVf0YhO.png)

**cùng phân tích nha:**

- như ta đã thấy ở ảnh 2 thì thanh ghi rbp đã được làm đầy 
- sau đó ở hình 1 từ thanh rsp ta thấy nó tràn ra 28 byte 
**=> ta tạm suy đoán là để làm đầy đến thanh rbp thì cần 100-28 = 72byte**

**để kiểm tra suy đoán của mình đúng ko thì nhập thử 64byte xem sao **

![](https://i.imgur.com/WAe3OsQ.png)

chương trình ko chạy được nè

n**hập thêm 8byte nữa thanh 72byte xem sao:**

![](https://i.imgur.com/dcOq2SI.png)

**lúc này thanh rbp đã đầy, còn rsp thì ko thấy tràn ra, chứng tỏ mình suy đoán đúng rồi**

**bây giờ ta chỉ cần chèn 72byte với 8byte cho địa chỉ 0x40060d là được rồi :** 

![](https://i.imgur.com/Tn5jQ5R.png)

bị lỗi này do địa chỉ ko chia hết cho 16 thôi, thêm +4 vào 0x40060d là được:

![](https://i.imgur.com/9dRkLOk.png)

**có flag giả gòi nè hehe :))**

**giờ nc rồi lấy flag thật thôi** 

![](https://i.imgur.com/OHkMddS.png)

**flag{010b24a3-ecfa-4070-820a-349aa4d809b1}**
