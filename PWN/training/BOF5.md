# **ret2shellcode không leak - BOF5**

một bài giống BOF6 nma dễ hơn nhiều :))

**vào ida xem sao:**

![](https://i.imgur.com/hZ5ziLs.png)

![](https://i.imgur.com/LvbnVLZ.png)

xem qua thì thấy lần nhập đầu không có lỗi gì cả, lần 2 thì lỗi BOF

**lên terminal debug thử:**

**lần nhập đầu ko có lỗi nên ta nhập thử abcd, lần 2 thì ta nhập 544 byte ở overthewrite thanh rip xem sao:**

![](https://i.imgur.com/MmafhQx.png)

**ta thấy ở lần nhập đầu tiên nó đã chèn ngay thanh ghi rax rồi, nên ta có thể chèn shellcode ở đây luon**

**ở lần nhập 2 thì ta sẽ lợi dụng thanh rip để trỏ đến 1 gadget nào đó chạy rax (call rax và jmp rax) để thực thi shellcode**

![](https://i.imgur.com/5RayKzj.png)

**ở đây thì call hay jmp gì cũng được nên mình chọn call nha**

**script đây:**

![](https://i.imgur.com/Ccbl88c.png)

lấy được shell rồi nè hehe





![](https://i.imgur.com/tmxnarq.png)
