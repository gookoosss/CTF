# WINNER2 - CHALLFUN

**đây là 1 bài tập khá độc đáo kết hợp giữ ret2win và ROPchain, sau 1 ngày nghiên cứu thì mình cũng giải dc hehe**

mở ida lên xem sao nào:

![](https://i.imgur.com/1f3ydAJ.png)

![](https://i.imgur.com/5WkIqkF.png)

**đọc qua ida ta phân tích sơ nè :** 

- ở hàm main thì có BOF khá dễ thấy
- hàm win khá lạ, để đọc được flag thì các bạn phải đi vào được lệnh if, mà lệnh if là a2 == 0xF672AE02
- lục tung nguyên cái ida ko thấy a2 đâu cả :)) nma có điều đặc biệt nếu bạn để chuột vào a2 thì thấy a2 chính là giá trị của thanh rsi (arg2) và a1 là rdi (arg1)

**thì if ko yêu cầu gì về a1 cả nên ta ko quan tâm , ta chỉ chèn giá trị cho rsi là được**

**tìm gadget của rsi nào:**


![](https://i.imgur.com/49VqjWP.png)


kiểm tra hàm win thì ta cần nhảy vào win+5 để ko bị lỗi:


![](https://i.imgur.com/fG8eX3i.png)


nhập thử 8byte tìm offset cho rip:


![](https://i.imgur.com/LMPF7xh.png)


**vậy là ta có đủ những thứ mình cần rồi nên viết script thôi:**


![](https://i.imgur.com/tXsfHbd.png)


chạy thử xem sao nào


![](https://i.imgur.com/g5gNZmX.png)


hmm có gì đó ko đúng nhỉ


**rõ ràng rsi đã đúng điều kiện của if mà sao chương trình không chạy vào hàm win vậy**


**à kiểm tra lại mới thấy thì mình đã quên mất r15 :)) lúc này địa chỉ của thằng r15 còn chống nên nó trỏ vào hàm win + 5 , nên ret ko nhận được địa chỉ của win nên đã tự kết thúc chương trình**


h ta thử thêm ta byte cho r15 nào:


![](https://i.imgur.com/DeJs3mr.png)

chương trình đã in flag và ta làm đúng r nè:

![](https://i.imgur.com/YBbrqSa.png)
