# ret2libc - BOF7

**Đây là một kỹ thuật phổ biến vì việc leak được địa chỉ là thực sự cần thiết**

**mở ida lên xem nào:**

![](https://i.imgur.com/odO3eus.png)

đọc cả ngày cũng chỉ thấy có lỗi BOF, hàm win ,system hay /bin/sh đều ko thấy đâu 

**checksec:**

![](https://i.imgur.com/4aCriLr.png)

**NX đã mở rồi thì ta ko để dùng kĩ thuật ret2shellcode được nên ta chỉ còn cách duy nhất là dùng ret2libc sẽ giải:**

**note(ret2libc):**

- libc là 1 file chứa đầy đủ các hàm mình cần như là puts , system
- chúng ta cần leak địa chỉ libc ra để có thể thực thi các hàm trong libc
- vì hàm system('/bin/sh') đã có sẵn trong libc nên ta sẽ dùng nó để tạo shell

**mở terminal tính offset nào:**

![](https://i.imgur.com/A8TZd9E.png)


**oke offset là 88byte bây giờ ta cần có pop rdi:**

![](https://i.imgur.com/MZHxl92.png)

**và cần học thêm 2 khái niệm mới rất quan trong là GOT và PLT:**

- **GOT(global offset table):** Nơi chứa địa chỉ các hàm của libc
- **PLT(procedure linkage table):** thực thi hàm được chứa ở GOT 

vì vậy nên **lý do ta tìm địa chỉ của rdi là để trỏ đến địa chỉ của puts@got để đùng puts@plt thực thi hàm puts, từ đó ta có thể leak được địa chỉ libc**

![](https://i.imgur.com/R5ACi6A.png)

đến đây ta đã lấy được địa chỉ libc trên server ,nma nếu ta thi ctf **thì địa chỉ libc của local và server thì khác nhau nên bây giờ ta sẽ tìm file libc khác mà hợp với server:**

link: **libc.rip**

![](https://i.imgur.com/EapCyja.png)

**nhập hàm mình cần và địa chỉ libc trong local vào rồi chọn 1 file đúng để tải về**

**lúc này ta cần cho file libc vs bof7 vào 1 folder để pwninit:**

![](https://i.imgur.com/6RMujHq.png)

ra đến đây là ta đúng r , lúc này nó tạo cho ta 1 file **bof7_patched** mới để liên kết libc mới 

oke bây giờ ta cần tìm **địa chỉ base của libc mới(là địa chỉ nhỏ nhất trong file libc ta mới tải về)**

![](https://i.imgur.com/2bmCZiC.png)

**ở đây thì ta lấy địa chỉ của libc trừ đi cái offset trỏ đến địa chỉ của hàm puts là ta ra được địa chỉ của libc base** 


![](https://i.imgur.com/2J075OD.png)

chạy thử xem sao:

![](https://i.imgur.com/kvncMTO.png)

**oke vậy là ta đã leak dc 2 địa chỉ ta cần r nè** 

sau khi leak xong thì ta cần **chạy lại hàm main** 

**sau đó ta cần lấy rdi trỏ đến địa chỉ của hàm system(/bin/sh)  để tạo shell**

**trong hình mình có giải thích kĩ các bước làm r đó:**

![](https://i.imgur.com/RWehHz3.png)

**full script:**

![](https://i.imgur.com/gphKHff.png)

**oke giờ ta chạy thử xem sao:**

![](https://i.imgur.com/qsaALs5.png)

h ta đã lấy được shell gòi nè 
