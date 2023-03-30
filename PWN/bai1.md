 Buffer Overflow - Tràn biến 1

Đầu tiên ta mở vào Terminal để truy cấp đến file bof1 bằng lệnh cd và ls;
Sau đó ta vào ida64 để kiểm tra code c;
https://i.imgur.com/U5vNHxR.png

Ý tưởng : 
Bây giờ chúng ta hãy đọc từ trên xuống thì sẽ dễ dàng giải bài này!
https://i.imgur.com/20tlnYM.png


Cách giải:
Oke giờ chúng ta sẽ bắt đầu làm bài :
B1: gdb bof1 và start (hình mẫu)
https://i.imgur.com/0jsOmI5.png 

B2: ta dùng lệnh ni tìm <read@plt>
https://i.imgur.com/t3KzHkX.png

B3: ta pattern create 48 để tạo 48 bit roi copy nó
https://i.imgur.com/81LOJMa.png

B4: dùng lệnh ni rồi paste (aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaa) vào , sau đó dùng lệnh tel để kiểm tra sự thay đổi:
Ban đầu khi chưa nhập dữ liệu:
https://i.imgur.com/TaOfvNl.png

Sau khi nhập 48 byte vào:
https://i.imgur.com/h6byg1g.png

B5: như vậy là ta đã xong  điều kiện đề bài , giờ dùng lệnh c để chạy chương trình và lấy shell thôi :
https://i.imgur.com/qW2KXdo.png

Như vậy là chúng ta đã xong bài 1 rồi đó

