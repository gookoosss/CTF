# **FORMAT STRING_Leak dữ liệu bằng %p**

**đây là 1 dạng mới trong pwn nên mình sẽ giới thiệu chung những thứ cơ bản và cần biết và Format String:**

- **%p** in ra địa chỉ của biến , cũng như in ra dữ liệu chứa trong stack
- **%c** in ra 1 byte duy nhất(theo mã ascii) 
- **%s** chuyển vào 1 địa chỉ, sau đó in ra dữ liệu đang trỏ đến
- **%n** cộng thêm số byte được in ra trước đó
- **%n$p** = %p%p%p%p.....%p có n lần
- **%c%c%nc%n** =>%n gán 2 + n byte vào biến

**ida:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/799be53b-2376-48b5-a993-c7788df5ede2)


ở hàm **printf(format)** ta thấy có lỗi ******format string****** vì **biến format ta có quyền quyết định kiểu dữ liệu của nó**


**checksec vs vm:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/2d060755-b24e-4a6a-9d70-2c8cf33f7f78)


**ta thấy địa chỉ stack là 6byte nên ta chắc chắn đây là địa chỉ động**

tại hàm **read** đầu tiên thì nó đọc giá trị của flag gán vào trong stack

![image](https://github.com/gookoosss/CTF.-/assets/128712571/84461086-9a1b-4a8c-94fb-328107b32cc6)


**oke lúc này ta cần phải leak được giá trị của flag trong stack ra để lấy được flag**

**vì ở đây địa chỉ stack là địa chỉ động**, nó sẽ thay đổi trong mỗi lần chạy, **nên việc dùng %s lên địa chỉ stack để leak ra flag là đieu bất khả thi**

**vì flag nằm strong stack**, **%p** thì leak giá trị nằm stack nên dùng **%p** là dễ nhất 

ở đây thì cần **5 %p cho 5 arg** và cộng thêm **7 %p để đến được stack chứa flag**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/53b3f3bc-3ea6-4b02-8087-1e2644ff198c)


hmm vì giá trị của flag dài chứa trong nhiều stack nên ta cứ **%12+n$p** đến khi nào có in ra hết flag thì thôi

![image](https://github.com/gookoosss/CTF.-/assets/128712571/dfe81204-e291-4cd0-ae47-5f54544d5ef6)

![image](https://github.com/gookoosss/CTF.-/assets/128712571/53e0b12d-8051-48ca-9251-789cabfbcf60)

**với cách này thì mình thấy khá lâu và bất tiện** 

bây giờ ta sẽ dùng cách viết script sẽ tiện lợi và nhanh hơn rất nhiều

**script:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/ea132467-6cdc-4b95-b4e8-13d8b1481833)


trong ảnh mình đã giải thích rất chi tiết rồi đó

**chạy thử và in ra đầy đủ flag**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/becadd47-dbfa-4855-bebe-2c3aab9ba853)














