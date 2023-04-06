Đầu tiên , các bạn tại file bof2 về máy dùng lệnh cd với ls để truy cập vào ổ đĩa d nha
Sau đó dùng ida64 để đọc code c của bof2 :

![image](https://user-images.githubusercontent.com/128712571/230344970-767cf43f-b5ae-49a8-8845-3216f7e76f9b.png)


Ý tưởng:
Oke đầu tiên chúng ta cùng phân tích bài này nào :

![image](https://user-images.githubusercontent.com/128712571/230345009-63a87c66-006a-48fc-867f-076131a370f4.png)


Vấn đề ta gặp phải là các điều kiện v7 == 0x13371337 && v6 == 0xDEADBEEFLL && v5 == 0xCAFEBABELL chúng ta không thể nào nhập bằng tay được nên ta phải dùng tool thông qua python.
Các bạn hãy nhập giống như mình:

![image](https://user-images.githubusercontent.com/128712571/230345052-ef67db72-b8fd-4fc4-88f9-e4ad7511f2c9.png)


Đây mình sẽ giải thích:

![image](https://user-images.githubusercontent.com/128712571/230345074-6bc0490c-cf4a-4162-820a-69a0abcebb86.png)


Sau khi các bạn đã làm xong giống mình rồi vào Terminal chạy lệnh:
Python3 pp.py
Trước khi nhập đây:

![image](https://user-images.githubusercontent.com/128712571/230345100-a5380bea-1832-480a-ac98-3c868dbc9034.png)


Sau khi nhập:

![image](https://user-images.githubusercontent.com/128712571/230345136-ec2039da-ab9f-4c87-b1a6-84abc9f2fade.png)


Các bạn đã thấy sự khác nhau và thỏa điều kiện chưa nè
Bây giờ mình chỉ cần dùng c chạy hết chương trình là lấy được shell rồi đó

![image](https://user-images.githubusercontent.com/128712571/230345163-c17f4b9e-8e12-46a1-86e0-4ac0a5c19909.png)
