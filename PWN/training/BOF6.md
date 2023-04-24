# ret2shellcode cần leak - BOF6

**một dạng bài tập thú vị trong pwn và rất quan trọng**

trước tiên mở ida lên xem sao

**hàm main:**

![](https://i.imgur.com/6KsloIl.png)

**get_name:**

![](https://i.imgur.com/V2KpcEo.png)

**get_wish:**

![](https://i.imgur.com/3eZW9ar.png)

**ở đây có 2 vấn đề quan trọng:**

- lệnh read trong get_name có 1 lỗ hỏng là khi nhập giá trị vào nó sẽ không kết thúc bằng byte null, mà sẽ nối liền với giá trị của thanh ghi tiếp theo. ta có thể lợi dụng việc này để leak địa chỉ stack 
- trong get_wish có lỗi BOF mà ta có thể khai thác

**kinh nghiêm:**
- nên leak stack của thanh rbp
- hàm nào có lỗi BOF thì đặt shellcode tại đó

oke mở terminal lên xem sao : 


![](https://i.imgur.com/RsjFiAD.png)


**NX đã đóng , đây là file tĩnh, ta có quyền thực thi đươc shellcode vào stack**

**kinh nghiệm : NX mà đóng thì auto thực thi shellcode** 

bài này có dạng là ret2shellcode vì ta có thể leak stack  và thực thi shellcode dễ dàng

**các bước làm ret2shellcode:**

- đầu tiên ta cần leak ra địa chỉ stack của thanh ghi rbp
- vì địa chỉ stack của rbp là địa chỉ động mà ta đã leak ra và xác định được, còn địa chỉ của shellcode là địa chỉ tĩnh, mà muốn thực thi shellcode thì ta phải dùng địa chỉ stack ta leak được để trỏ đến địa chỉ shellcode

**giờ ta leak stack thôi:**

![](https://i.imgur.com/NwInHGe.png)

ở get_name thì ta cần nhập 80byte để leak đỉa chỉ rbp 

bây giờ ta viết script để in là địa chi leak ra:

![](https://i.imgur.com/ghA10TZ.png)

chạy thử xem sao:

![](https://i.imgur.com/sAKvole.png)

**ra tới đây là ta đúng bước 1 rồi**

**giờ sang bước 2 thì ta thực thi shellcode**

ở đây thì mình có viết sẵn shellcode cho file 64bit rồi nên chỉ cần copy vào thôi:

![](https://i.imgur.com/Ma6zzzJ.png)

giờ ta chạy script này xem sao:

![](https://i.imgur.com/HpmyZq2.png)

**ở đây ta không biết shell code chứa bao nhiêu byte cả, nên ta sẽ dùng lênh ljust để tự làm đầy nó đến số lượng ta muốn, ở get_wish cho giới hạn 544byte nên ta thử trừ đi 8byte mà chèn vào 536byte**

chạy thử xem sao:

![](https://i.imgur.com/DGKqRHT.png)

kiểm tra xem chỗ này có phải shellcode ko:

![](https://i.imgur.com/RPXhfFn.png)

chuẩn rồi nè

**h tìm offset từ stack ta leak ra đến shellcode thôi:**

![](https://i.imgur.com/IvxmC2l.png)

**vậy ta cần trừ đi 0x220 byte để trỏ đến địa chỉ shellcode**

kiểm tra xem thanh rip ta đã chèn đúng chưa 

![](https://i.imgur.com/0u8EeVg.png)

hình như ta lố rồi

![](https://i.imgur.com/Xc8yyrz.png)

**ở đây ta thấy rsp không trỏ đúng vào địa chỉ ta cần vì ta đã lố 16byte nên ta cần trừ bớt đi**

![](https://i.imgur.com/JmjnECH.png)

oke chạy lại script xem sao : 

![](https://i.imgur.com/Tt4mboS.png)

lấy được shell rồi nè

huhu mệt xỉu
