# Retrivever -- ida

bài này khá lạ và ảo nên là cần mất khá nhiều thời gian nha:

![](https://i.imgur.com/bSlLlqG.png)

đọc lú thật sự, kéo xuống xem sao nào:

![](https://i.imgur.com/JkO8SX5.png)

**thề đọc lú vãi, nma ta cùng phân tích nha:**
- ở đây ta thấy mảng src show ra một chuỗi các số dài nằm  trong khoản 95 -> 114 (đa số),mà mảng src có kiểu dữ liệu char nên ta có thể đoán đây là kí tự trong bảng mã ascii

**h ta đổi các số ra char xem sao:**

![](https://i.imgur.com/bPrOkxG.png)

**ra gòi nè , nma có hàng trăm số mà đổi từng cái xong copy đến mùa quýt à, nên giờ ta phải debug rồi:**

dùng lệnh disas tìm strcpy để có in ra flag

![](https://i.imgur.com/WNsriwZ.png)


![](https://i.imgur.com/rMy1JmY.png)

**dùng x/s đọc dữ liệu toàn bộ thanh ghi :** 

![](https://i.imgur.com/kp81JVe.png)

có flag r nè

FLAG: **flag-most_Muggles_aren't_exactly_accustomed_to_seeing_a_flying_car**
