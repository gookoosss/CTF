# Buffer overflow - WIN

**đầu tiên mở ida32 lên xem sao:**

![](https://i.imgur.com/Y0RsrQx.png)

![](https://i.imgur.com/p3M8hF0.png)

 **có hàm win nên ta dự đoán đây là bài dạng ret2win nha :))
 mở terminal chạy thử xem sao
 chạy chương trình đến hàm gets rồi nhập thử 8byte kiểm tra xem:**

![](https://i.imgur.com/cUk8fSl.png)

**cùng phân tích nha : **
- ta thấy 8byte được nhập vào thanh ghi đầu tiên nên đó là vị trí của mảng buf
- đây là dạng ret2win ta cần quan tâm đến rip ở dưới rbp và làm tràn nó
- từ buf đến rip ta cần 18 dòng thì ta cần nhập 18*8 = 144byte

**h nhập thử 136byte a và 8byte b xem sao:**

![](https://i.imgur.com/8pNxeA9.png)

**ta đã làm tràn đến rip rồi đó, thử chạy hết chương trình xem sao**

![](https://i.imgur.com/mCxZrbp.png)

**lỗi rồi nè, h chúng ta cần dùng python3 để chèn dữ liệu từ rip qua hàm win nha:
à mà khoan trước khi làm bước này ta phải tạo 1 file flag có nội dung là KCSC{FLAG} trước nha
**

![](https://i.imgur.com/kfpxYuj.png)

**code đây chạy thử xem sao nè**

![](https://i.imgur.com/NNjJfX9.png)

**có flag r nè vậy là ta làm đúng r đó
**
