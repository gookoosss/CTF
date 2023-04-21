# ADMIN1 -- FUN

một bài khá thú vị và lạ làm mình rất đau đầu :)) nma ko sao cả, sau 2 ngày suy nghĩ thì mình cũng ra được và nó dễ bất ngờ á tr

**mở ida lên xem sao :** 

![](https://i.imgur.com/LlCZz9R.png)

**chỗ này mình cần nhập đúng mật khẩu và tài khoản nè:**

![](https://i.imgur.com/a01VQgV.png)


**chỗ này có nhiều vần đề cần giải quyết nè**

**oke h mình sẽ phân tích sơ khi xem qua ida nha :**

 - **bước 1**: ta cần phải nhập đúng mật khẩu và tài khoản mà giấu trong file này , để lấy được mật khẩu thì ta nhấp 2 lần vào true_name và true_password


![](https://i.imgur.com/GhdjYL9.png)

**name: Oleg
password: Super_Oleg_admin**

- **bước 2**: ta có 3 lựa chọn 1 2 3, nếu v7 => 3 thì chương trình sẽ dừng nên ta ko nhập 3, nếu v7 == 1 chương trình sẽ trỏ đến địa chỉ của v6 mà ta ko cần địa chỉ này, vì vậy ta phải nhập 2 là tối ưu nhất

- **bước 3**: một vấn đề lớn ở đây mà ta cần để ý là trong hàm system không hề có lệnh tạo shell để in flag mà chỉ chứa biến v6 vì thế ta cần chèn cho v6 có giá trị là "/bin/sh" để tạo shell cho chương trình

oke phân tích xong rồi h vào terminal debug thôi

nhập name:

![](https://i.imgur.com/hgwk3Qi.png)

nhập pass:

![](https://i.imgur.com/bnLFoC7.png)

chọn 2:

![](https://i.imgur.com/TkLtldm.png)

sai gòi tr :)) lên kiểm tra lại thui

**chạy thử script** 

![](https://i.imgur.com/E9upNqr.png)

![](https://i.imgur.com/Kvd1tiJ.png)

**như ta thấy thì pass nhập sau nma nằm ở trên name, mà nhiệm vụ ta cần làm biến v6 có giá trị là /bin/sh nên là ta cần làm tràn biến từ name xuống v6 để chèn già trị**

**có 2 điều cần biết là :** 

![](https://i.imgur.com/z2APlvc.png)

**- v6 nằm ở vi trí rbp-30h có nghĩ là nằm ở địa chỉ 0x007ffc67f6c120**

![](https://i.imgur.com/GbKKBkv.png)

**- s1 và true name chỉ cần so sánh đúng 4 giá trị đầu là đúng, nên ta có thể tràn biến thoải mái mà ko lo sai điều kiện**

oke h làm lại thôi

![](https://i.imgur.com/JG0Cmwa.png)

**lấy được shell gòi nè**

![](https://i.imgur.com/FCrNjUU.png)
