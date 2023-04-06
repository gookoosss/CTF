Đầu tiên ta vào ida64 kiểm tra file bof3 xem nó chạy ntn

![image](https://user-images.githubusercontent.com/128712571/230345518-807d3cbb-1c4e-405e-99a9-f7e4717294b6.png)
![image](https://user-images.githubusercontent.com/128712571/230345596-c59dcb3f-d560-4c37-a2a4-f88651651bf3.png)


ở đây ta tìm thấy hàm win , hmm ta có thể đoán đây là dạng ret2win
vào terminal debug thử nào :
![image](https://user-images.githubusercontent.com/128712571/230345660-7a71a610-530d-4f02-88d9-0e0cc823f05e.png)


Ta chạy chèn thử 48byte r chạy ct xem sao
![image](https://user-images.githubusercontent.com/128712571/230345818-0a28a2b4-4e90-4fb5-9131-dd3308725375.png)


Đến cuối main+107 là lỗi r ☹
Đọc ida64 thì ta thấy chúng ta cần hàm WIN để lấy shell mà đến ret là chương trình đã dừng r
H ta thử ktra xem
![image](https://user-images.githubusercontent.com/128712571/230345855-2fc6a862-36a2-4cdf-b9a0-d568a4c56ccf.png)


Dùng lệnh pattern search <địa chỉ>

![image](https://user-images.githubusercontent.com/128712571/230345880-c3592720-d1fa-4167-8999-82c0d23c18fe.png)

Bây giờ ta cùng phân tích nè : chương trình yêu cầu ta cần 48 byte , mà 40byte đã được chèn vào thanh ghi 0x007fffffffe0e8 ta đã kiểm tra ở trên rồi, giờ ta còn 8 byte cần chèn vào hàm win để chạy chương trình, vì vậy ta cần dùng tool thông qua python3

![image](https://user-images.githubusercontent.com/128712571/230345907-aa4c9411-eeab-4d45-8ab6-cac589a41543.png)

H ta thử chạy chương trình xem sao
![image](https://user-images.githubusercontent.com/128712571/230345938-7e9ef8df-6c7f-4ac7-a96d-85817eb46c48.png)


ở đây ta thấy xnml là lỗi của địa chỉ thanh ghi không chia hết cho 16
h ta cùng kiểm tra thử xem sao:
![image](https://user-images.githubusercontent.com/128712571/230345984-9eef6c8b-4d04-4cc6-84d8-7d1017b7a9e3.png)


ở win+0 ta kiểm tra qua python3 thấy địa chỉ các thanh ghi ko chia hết cho 16, win+4 cũng tương tự vậy
Đến win+5 thì 0x007ffe7639d720 rbp chia hết cho 16
![image](https://user-images.githubusercontent.com/128712571/230346043-9685c155-0090-40ae-a798-c6a7067ae61f.png)


Vậy ta cần trực tiếp đi vào win+5 và bỏ qua luôn win+0 và win+4;
![image](https://user-images.githubusercontent.com/128712571/230346076-033cd6f1-61ff-419a-90f2-5febcf7d708a.png)


Giờ ta chạy ct thử lại xem sao :
![image](https://user-images.githubusercontent.com/128712571/230346223-35d20ad9-e55b-4b2e-86d4-e966247f3478.png)


Hết bị lỗi gòi hehe, lấy shell thôi
![image](https://user-images.githubusercontent.com/128712571/230346237-4097a207-5f00-429d-88ad-2b102ef26757.png)
