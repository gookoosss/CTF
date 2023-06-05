# **FMTSTR2_Leak dữ liệu bằng %s**

**tiếp tục chuỗi seri format string với %s**

**ida:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/f98ad327-e49c-4811-8f26-8125bb7d9830)


ở đây có **lỗi format string** tại **printf(format)** 

chạy gdb xem sao:

![image](https://github.com/gookoosss/CTF.-/assets/128712571/91aac341-d792-4c68-8f5f-db1d078b73b0)


ta thấy ở đây buf là 1 con trỏ chứa địa chỉ trỏ đến giá trị của flag , hàm read đầu gán địa chỉ của con trỏ buf vào stack

trong trường hợp này **nếu ta dùng %p** thì nó leak trong giá trị trong stack là **0x005555555592a0** , thứ ta cần là flag nên ko thể dùng %p trong bài này

![image](https://github.com/gookoosss/CTF.-/assets/128712571/14e858d3-f117-4f6c-b953-fd84b82a3c85)


còn **nếu ta dùng %s** thì nó sẽ trả về giá trị mà địa chỉ trong stack trỏ đến từ đó ta có thể lấy dc flag 

![image](https://github.com/gookoosss/CTF.-/assets/128712571/fa3f79dd-e819-4a92-88df-1a62bacb81ac)


**khá đơn giản nhỉ**
