# Return Address Overwrite - R2W

đây là một bài tập khá quen thuộc trên dreamhack.
trước tiên cứ nc trước nha:

**nc host3.dreamhack.games 10901**

vào source c kiểm tra xem sao : 

![](https://i.imgur.com/aIiL7PV.png)

khá là đơn giản nhỉ, nhiệm vụ của ta là phải lấy dc shell thông qua hàm get_shell bằng lỗi buffer overlow, nhưng trong hàm main lại ko có lệnh nào chạy đến hàm get_shell nên chúng ta có thể đoán được đây là dạng bài tập ret2win

mở terminal lên debug xem sao

chạy đến scanf nhập thử 8 byte : 

![](https://i.imgur.com/WqtOkfP.png)

bài này đơn giản mình đã hướng dẫn rất chi tiết ở các bài tập trước đó trong training gòi nên mình chỉ đưa script thôi:

![](https://i.imgur.com/903dO5X.png)



chạy lại chương trình xem sao:

![](https://i.imgur.com/GBXvu6Y.png)


lấy được shell rồi nè, h ta ls xong lấy flag thôi:

![](https://i.imgur.com/WqdfKnb.png)


flag: DH{5f47cd0e441bdc6ce8bf6b8a3a0608dc}
