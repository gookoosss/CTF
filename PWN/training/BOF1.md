 Buffer Overflow - Tràn biến 1

Đầu tiên ta mở vào Terminal để truy cấp đến file bof1 bằng lệnh cd và ls;
Sau đó ta vào ida64 để kiểm tra code c;
![image](https://user-images.githubusercontent.com/128712571/230343894-a547e63e-bb37-4a36-9f3d-1622faee70bc.png)


Ý tưởng : 
Bây giờ chúng ta hãy đọc từ trên xuống thì sẽ dễ dàng giải bài này!
![image](https://user-images.githubusercontent.com/128712571/230343956-8654f191-264a-4fff-a4b4-f0d2be581b7c.png)



Cách giải:
Oke giờ chúng ta sẽ bắt đầu làm bài :
B1: gdb bof1 và start (hình mẫu)
![image](https://user-images.githubusercontent.com/128712571/230344013-226c4a20-4f24-4b75-9a6e-68fccf7def03.png)


B2: ta dùng lệnh ni tìm <read@plt>
![image](https://user-images.githubusercontent.com/128712571/230344049-07e12424-a1fe-4c2e-8daf-f00969a68372.png)


B3: ta pattern create 48 để tạo 48 byte roi copy nó
![image](https://user-images.githubusercontent.com/128712571/230344113-aa8e3fcf-4cf0-4ce9-84fd-46fd2475d32e.png)


B4: dùng lệnh ni rồi paste (aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaa) vào , sau đó dùng lệnh tel để kiểm tra sự thay đổi:
Ban đầu khi chưa nhập dữ liệu:
![image](https://user-images.githubusercontent.com/128712571/230344149-b979da3c-f08a-41fd-bb24-d11471c736d4.png)


Sau khi nhập 48 byte vào:
![image](https://user-images.githubusercontent.com/128712571/230344194-b80cdcec-5092-4b63-bddb-6de1e133adbb.png)


B5: như vậy là ta đã xong  điều kiện đề bài , giờ dùng lệnh c để chạy chương trình và lấy shell thôi :
![image](https://user-images.githubusercontent.com/128712571/230344241-7c6a21ae-0dfb-45e1-8266-c23a4bdeb344.png)

Như vậy là chúng ta đã xong bài 1 rồi đó

